"""BLACK ICE ingest (Phase 3 slice): turns collector output into evidence, assets and
relationships. Deterministic rules; every derived relationship records its rule id.

Discovered names become assets only if they are inside the operation's scope. Names
outside scope or excluded are kept in the raw evidence and counted, never registered as
targets. Re-running the same operation never duplicates rows (unique keys + upserts).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from nightfall.core.db.models import (
    Asset,
    AssetKind,
    AssetRelationship,
    Confidence,
    Evidence,
    EvidenceKind,
    Operation,
    RelationshipType,
)
from nightfall.recon.collectors import CollectorResult
from nightfall.scope.engine import ScopeSnapshot, evaluate

RULESET_VERSION = "2026.11-p3"
RULE_SUBDOMAIN = "dns-name-hierarchy/v1"
RULE_RESOLVES = "dns-a-aaaa-answer/v1"
RULE_CNAME = "dns-cname-answer/v1"


@dataclass
class IngestSummary:
    evidence_id: uuid.UUID
    target_asset_id: uuid.UUID
    assets_new: int
    assets_seen: int
    out_of_scope: int
    rejected: int
    relationships: int
    technologies: list[dict[str, str | None]]

    def as_dict(self) -> dict[str, object]:
        return {
            "evidence_id": str(self.evidence_id),
            "assets_new": self.assets_new,
            "assets_seen": self.assets_seen,
            "out_of_scope": self.out_of_scope,
            "rejected": self.rejected,
            "relationships": self.relationships,
            "technologies": self.technologies,
            "ruleset": RULESET_VERSION,
        }


def _upsert_asset(
    db: Session,
    op: Operation,
    org_id: uuid.UUID,
    kind: AssetKind,
    value: str,
    source: str,
    now: datetime,
) -> tuple[uuid.UUID, bool]:
    stmt: Any = (
        insert(Asset)
        .values(
            workspace_id=op.workspace_id,
            organization_id=org_id,
            kind=kind,
            value=value,
            source=source,
            first_seen_at=now,
            last_seen_at=now,
        )
        .on_conflict_do_update(
            index_elements=["workspace_id", "organization_id", "kind", "value"],
            set_={"last_seen_at": func.greatest(Asset.last_seen_at, now)},
        )
        .returning(Asset.id, literal_column("xmax = 0"))  # true when inserted
    )
    row = db.execute(stmt).one()
    return row[0], bool(row[1])


def _existing_host_asset(db: Session, org_id: uuid.UUID, value: str) -> uuid.UUID | None:
    return db.scalar(
        select(Asset.id).where(
            Asset.organization_id == org_id,
            Asset.value == value,
            Asset.kind.in_([AssetKind.DOMAIN, AssetKind.HOSTNAME]),
        )
    )


def _relate(
    db: Session,
    op: Operation,
    a: uuid.UUID,
    b: uuid.UUID,
    rel: RelationshipType,
    evidence_id: uuid.UUID,
    rule: str,
    now: datetime,
) -> None:
    if a == b:
        return
    db.execute(
        insert(AssetRelationship)
        .values(
            workspace_id=op.workspace_id,
            from_asset_id=a,
            to_asset_id=b,
            rel_type=rel,
            confidence=Confidence.HIGH,
            evidence_id=evidence_id,
            rule_id=rule,
            first_seen_at=now,
            last_seen_at=now,
        )
        .on_conflict_do_update(
            index_elements=["from_asset_id", "to_asset_id", "rel_type"],
            set_={"last_seen_at": now},
        )
    )


def ingest(
    db: Session,
    op: Operation,
    org_id: uuid.UUID,
    scope: ScopeSnapshot,
    result: CollectorResult,
    digest: bytes,
    now: datetime,
) -> IngestSummary:
    new = seen = out = rels = 0

    def track(created: bool) -> None:
        nonlocal new, seen
        if created:
            new += 1
        else:
            seen += 1

    target_id = _existing_host_asset(db, org_id, op.target_value)
    if target_id is None:
        target_id, created = _upsert_asset(
            db, op, org_id, AssetKind.HOSTNAME, op.target_value, result.source, now
        )
        track(created)

    db.execute(
        insert(Evidence)
        .values(
            workspace_id=op.workspace_id,
            project_id=op.project_id,
            asset_id=target_id,
            operation_id=op.id,
            kind=EvidenceKind.TOOL_OUTPUT,
            source=result.source,
            collection_method=op.params.get("method", op.tool),
            collected_at=now,
            confidence=result.confidence,
            tool_name=result.tool_name,
            tool_version=result.tool_version,
            input_params={"target": op.target_value},
            content_sha256=digest,
            content_type=result.content_type,
            size_bytes=len(result.raw),
            summary={
                "names": len(result.names),
                "addresses": result.addresses,
                "cnames": result.cnames,
                "records": result.records,
                "technologies": result.technologies,
                "http": result.http,
                "checks": result.matches,
            },
            is_simulation=False,
        )
        .on_conflict_do_nothing(index_elements=["operation_id", "content_sha256"])
    )
    evidence_id = db.scalar(
        select(Evidence.id).where(Evidence.operation_id == op.id, Evidence.content_sha256 == digest)
    )
    if evidence_id is None:
        raise RuntimeError("evidence row missing after insert")

    # Discovered hostnames (CT) and CNAME targets (DNS): only in-scope names become assets.
    for name in result.names:
        if name == op.target_value:
            continue
        if not evaluate(scope, name, now).allowed:
            out += 1
            continue
        aid = _existing_host_asset(db, org_id, name)
        if aid is None:
            aid, created = _upsert_asset(
                db, op, org_id, AssetKind.HOSTNAME, name, result.source, now
            )
            track(created)
        else:
            track(False)
        if name.endswith("." + op.target_value):
            _relate(
                db,
                op,
                aid,
                target_id,
                RelationshipType.SUBDOMAIN_OF,
                evidence_id,
                RULE_SUBDOMAIN,
                now,
            )
            rels += 1
    for cname in result.cnames:
        if not evaluate(scope, cname, now).allowed:
            out += 1
            continue
        aid = _existing_host_asset(db, org_id, cname)
        if aid is None:
            aid, created = _upsert_asset(
                db, op, org_id, AssetKind.HOSTNAME, cname, result.source, now
            )
            track(created)
        _relate(db, op, target_id, aid, RelationshipType.CNAME_TO, evidence_id, RULE_CNAME, now)
        rels += 1
    # Resolved addresses are recorded facts about an in-scope name. They are stored as
    # assets with unknown ownership; whether an IP may be *tested* is decided by the scope's
    # IP entries, never by the fact that an in-scope name resolves to it.
    for addr in result.addresses:
        aid, created = _upsert_asset(db, op, org_id, AssetKind.IP_ADDRESS, addr, result.source, now)
        track(created)
        _relate(
            db, op, target_id, aid, RelationshipType.RESOLVES_TO, evidence_id, RULE_RESOLVES, now
        )
        rels += 1

    return IngestSummary(
        evidence_id=evidence_id,
        target_asset_id=target_id,
        assets_new=new,
        assets_seen=seen,
        out_of_scope=out,
        rejected=result.rejected,
        relationships=rels,
        technologies=result.technologies,
    )


def apply_finding_rules(
    db: Session,
    op: Operation,
    target_asset_id: uuid.UUID,
    evidence_id: uuid.UUID,
    result: CollectorResult,
    now: datetime,
) -> list[dict[str, object]]:
    """Creates or refreshes rule-based findings for this evidence. Re-observation updates the
    existing finding (last seen + evidence link); a finding marked remediated is reopened as
    unverified. A finding marked false positive keeps that status."""
    from nightfall.blackice.finding_rules import RULESET, from_http, from_nuclei
    from nightfall.core.db.models import (
        Finding,
        FindingEvidence,
        FindingOrigin,
        ValidationStatus,
    )

    changes: list[dict[str, object]] = []
    drafts = from_http(result.http, result.technologies, now) + from_nuclei(result.matches)
    for d in drafts:
        existing = db.scalar(
            select(Finding)
            .where(
                Finding.project_id == op.project_id,
                Finding.asset_id == target_asset_id,
                Finding.check_id == d.check_id,
            )
            .with_for_update()
        )
        if existing is None:
            f = Finding(
                workspace_id=op.workspace_id,
                project_id=op.project_id,
                asset_id=target_asset_id,
                title=d.title,
                description=d.description,
                severity=d.severity,
                confidence=d.confidence,
                validation_status=ValidationStatus.UNVERIFIED,
                origin=FindingOrigin.DETERMINISTIC_CHECK,
                check_id=d.check_id,
                rule_id=f"{d.rule_id}@{RULESET}",
                discovery_source=f"{result.tool_name} via operation {op.id}",
                impact=d.impact,
                remediation=d.remediation,
                first_observed_at=now,
                last_observed_at=now,
            )
            db.add(f)
            db.flush()
            changes.append({"finding_id": str(f.id), "check_id": d.check_id, "change": "new"})
        else:
            f = existing
            f.last_observed_at = now
            change = "seen_again"
            if f.validation_status is ValidationStatus.REMEDIATED:
                f.validation_status = ValidationStatus.UNVERIFIED
                f.validated_by_user_id = None
                f.validated_at = None
                f.status_note = (
                    f"Observed again on {now.date().isoformat()} after being marked remediated."
                )
                change = "reopened"
            changes.append({"finding_id": str(f.id), "check_id": d.check_id, "change": change})
        db.execute(
            insert(FindingEvidence)
            .values(
                workspace_id=op.workspace_id,
                finding_id=f.id,
                evidence_id=evidence_id,
                linked_by=f"rule:{d.rule_id}",
            )
            .on_conflict_do_nothing(index_elements=["finding_id", "evidence_id"])
        )
    return changes
