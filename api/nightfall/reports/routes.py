"""Assessment reports.

Generating a report freezes the project's current state into an immutable snapshot
(insert-only table) with a SHA-256 of its canonical JSON. The report page renders from the
snapshot, never from live data, so a report always shows exactly what was true when it was
made. The executive summary is assembled from counts by fixed templates (no LLM).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import RULESET as FINDING_RULESET
from nightfall.blackice.ingest import RULESET_VERSION as INGEST_RULESET
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    OPEN_STATUSES,
    Approval,
    AssessmentSnapshot,
    Asset,
    AttackPath,
    Evidence,
    Finding,
    FindingEvidence,
    Operation,
    Organization,
    Project,
    Scope,
    ScopeExclusion,
    ScopeStatus,
    ScopeTarget,
    Severity,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.findings.paths import _path_out
from nightfall.findings.routes import SEVERITY_RANK, ref
from nightfall.recon.collectors import TOOLS
from nightfall.recon.fingerprint import RULESET as FINGERPRINT_RULESET

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["reports"])
SCHEMA = "nightfall-report/1"


class ReportSummary(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    taken_at: datetime
    taken_by: str
    sha256: str
    findings_open: int


class ReportOut(ReportSummary):
    integrity_ok: bool
    content: dict[str, Any]


def canonical(content: dict[str, Any]) -> bytes:
    return json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def build_content(db: Session, project: Project, now: datetime) -> dict[str, Any]:
    org = db.get(Organization, project.organization_id)
    cache: dict[uuid.UUID, str] = {}

    def name(user_id: uuid.UUID | None) -> str | None:
        """Display name for one referenced user (never loads other users)."""
        if user_id is None:
            return None
        if user_id not in cache:
            cache[user_id] = db.scalar(select(User.display_name).where(User.id == user_id)) or "?"
        return cache[user_id]

    scope = db.scalar(
        select(Scope).where(Scope.project_id == project.id, Scope.status == ScopeStatus.ACTIVE)
    )
    scope_block = None
    if scope:
        scope_block = {
            "version": scope.version,
            "reference": scope.authorization_reference,
            "is_lab": scope.is_lab,
            "authorized_by": name(scope.authorized_by_user_id),
            "authorized_at": _iso(scope.authorized_at),
            "valid_from": _iso(scope.valid_from),
            "valid_until": _iso(scope.valid_until),
            "targets": [
                {"kind": t.kind.value, "value": t.value}
                for t in db.scalars(
                    select(ScopeTarget)
                    .where(ScopeTarget.scope_id == scope.id)
                    .order_by(ScopeTarget.value)
                )
            ],
            "exclusions": [
                {"kind": e.kind.value, "value": e.value, "reason": e.reason}
                for e in db.scalars(
                    select(ScopeExclusion)
                    .where(ScopeExclusion.scope_id == scope.id)
                    .order_by(ScopeExclusion.value)
                )
            ],
        }

    ops = db.scalars(select(Operation).where(Operation.project_id == project.id)).all()
    method: dict[str, dict[str, Any]] = {}
    for o in ops:
        m = method.setdefault(
            o.tool,
            {
                "tool": o.tool,
                "label": TOOLS.get(o.tool, (o.tool,))[0],
                "risk_class": o.risk_class.value,
                "runs": 0,
                "succeeded": 0,
                "denied_or_rejected": 0,
            },
        )
        m["runs"] += 1
        m["succeeded"] += o.status.value == "succeeded"
        m["denied_or_rejected"] += o.status.value in ("denied", "rejected")
    approvals = db.scalar(
        select(Approval.id)
        .join(Operation, Operation.id == Approval.operation_id)
        .where(Operation.project_id == project.id)
        .limit(1)
    )

    assets = db.scalars(
        select(Asset)
        .where(Asset.organization_id == project.organization_id)
        .order_by(Asset.kind, Asset.value)
    ).all()
    asset_values = {a.id: a.value for a in assets}
    findings = db.scalars(select(Finding).where(Finding.project_id == project.id)).all()
    findings = sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.number))
    ev_rows = db.execute(
        select(FindingEvidence.finding_id, Evidence)
        .join(Evidence, Evidence.id == FindingEvidence.evidence_id)
        .where(Evidence.project_id == project.id)
    ).all()
    ev_by_finding: dict[uuid.UUID, list[dict[str, Any]]] = {}
    fixture = False
    for fid, e in ev_rows:
        fixture = fixture or e.tool_name.startswith("fixture")
        ev_by_finding.setdefault(fid, []).append(
            {
                "id": str(e.id),
                "sha256": e.content_sha256.hex(),
                "tool": e.tool_name,
                "source": e.source,
                "collected_at": _iso(e.collected_at),
            }
        )
    fixture = fixture or bool(
        db.scalar(
            select(Evidence.id)
            .where(Evidence.project_id == project.id, Evidence.tool_name.like("fixture%"))
            .limit(1)
        )
    )

    finding_rows = [
        {
            "ref": ref(f.number),
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "status": f.validation_status.value,
            "origin": f.origin.value,
            "asset": asset_values.get(f.asset_id) if f.asset_id else None,
            "description": f.description,
            "impact": f.impact,
            "remediation": f.remediation,
            "first_observed_at": _iso(f.first_observed_at),
            "last_observed_at": _iso(f.last_observed_at),
            "decided_by": name(f.validated_by_user_id),
            "decision_note": f.status_note,
            "rule_id": f.rule_id,
            "check_id": f.check_id,
            "evidence": sorted(ev_by_finding.get(f.id, []), key=lambda e: e["collected_at"] or ""),
        }
        for f in findings
    ]

    open_f = [f for f in findings if f.validation_status in OPEN_STATUSES]
    by_sev = Counter(f.severity.value for f in open_f)
    by_status = Counter(f.validation_status.value for f in findings)
    breakdown = {s.value: by_sev.get(s.value, 0) for s in Severity}
    paths = [
        _path_out(db, p).model_dump(mode="json")
        for p in db.scalars(
            select(AttackPath)
            .where(AttackPath.project_id == project.id)
            .order_by(AttackPath.created_at)
        )
    ]

    sev_text = ", ".join(f"{n} {s}" for s, n in breakdown.items() if n) or "none"
    summary = [
        f"This report covers {org.name if org else 'the organization'} — {project.name}, "
        f"generated {now.date().isoformat()}.",
        (
            f"Testing was limited to scope v{scope_block['version']} "
            f"(authorization: {scope_block['reference']})."
            if scope_block
            else "No scope was authorized, so no collection could run."
        ),
        f"{len(assets)} assets are recorded and {len(findings)} findings exist; "
        f"{len(open_f)} are open ({sev_text}).",
        f"{by_status.get('validated', 0)} findings were validated by a person; "
        f"{by_status.get('unverified', 0)} are unverified and "
        f"{by_status.get('hypothesis', 0)} are hypotheses (see Limitations).",
    ]
    limitations = []
    if by_status.get("hypothesis"):
        limitations.append(
            f"{by_status['hypothesis']} findings are hypotheses: plausible but "
            "not shown by evidence. They are not confirmed vulnerabilities."
        )
    if by_status.get("unverified"):
        limitations.append(
            f"{by_status['unverified']} findings are unverified: the evidence "
            "shows the condition, but nobody has reviewed and confirmed them."
        )
    hyp_paths = sum(1 for p in paths if p["status"] == "hypothesis")
    if hyp_paths:
        limitations.append(
            f"{hyp_paths} attack paths are hypotheses, not demonstrated compromises."
        )
    limitations.append(
        "Collection was limited to passive sources and approved low-risk HTTP "
        "requests within scope; no exploitation or active scanning was performed."
    )
    if fixture:
        limitations.append(
            "This report includes TEST-FIXTURE evidence (canned data used for "
            "testing). Those observations are not real."
        )

    return {
        "schema": SCHEMA,
        "generated_at": now.isoformat(),
        "rulesets": {
            "ingest": INGEST_RULESET,
            "findings": FINDING_RULESET,
            "fingerprint": FINGERPRINT_RULESET,
        },
        "organization": {"name": org.name if org else None},
        "project": {
            "name": project.name,
            "assessment_type": project.assessment_type.value,
            "status": project.status.value,
            "started_at": _iso(project.started_at),
        },
        "executive_summary": summary,
        "scope": scope_block,
        "methodology": {
            "collectors": sorted(method.values(), key=lambda m: m["tool"]),
            "human_approvals_recorded": approvals is not None,
        },
        "assets": [
            {
                "kind": a.kind.value,
                "value": a.value,
                "ownership": a.ownership.value,
                "source": a.source,
                "first_seen_at": _iso(a.first_seen_at),
                "last_seen_at": _iso(a.last_seen_at),
            }
            for a in assets
        ],
        "severity_breakdown": {"open": breakdown, "by_status": dict(sorted(by_status.items()))},
        "findings": finding_rows,
        "attack_paths": paths,
        "limitations": limitations,
    }


def _summary(s: AssessmentSnapshot, taken_by: str) -> ReportSummary:
    open_counts = s.content.get("severity_breakdown", {}).get("open", {})
    return ReportSummary(
        id=s.id,
        project_id=s.project_id,
        taken_at=s.taken_at,
        taken_by=taken_by,
        sha256=s.content_sha256.hex(),
        findings_open=sum(open_counts.values()),
    )


@router.post("/projects/{project_id}/reports", response_model=ReportSummary, status_code=201)
def create_report(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT)
) -> ReportSummary:
    project = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if project is None:
        raise not_found("Project not found.")
    content = build_content(db, project, utcnow())
    snap = AssessmentSnapshot(
        workspace_id=ctx.workspace_id,
        project_id=project.id,
        taken_by_user_id=ctx.user_id,
        ruleset_version=f"{INGEST_RULESET}+{FINDING_RULESET}",
        content=content,
        content_sha256=hashlib.sha256(canonical(content)).digest(),
    )
    db.add(snap)
    db.flush()
    db.refresh(snap)
    record(
        db,
        "report.generated",
        entity_type="report",
        entity_id=snap.id,
        data={"project_id": str(project.id), "sha256": snap.content_sha256.hex()},
        **ctx.audit_kwargs(),
    )
    return _summary(snap, ctx.auth.user.display_name)


@router.get("/projects/{project_id}/reports", response_model=list[ReportSummary])
def list_reports(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[ReportSummary]:
    rows = db.execute(
        select(AssessmentSnapshot, User.display_name)
        .join(User, User.id == AssessmentSnapshot.taken_by_user_id)
        .where(
            AssessmentSnapshot.project_id == project_id,
            AssessmentSnapshot.workspace_id == ctx.workspace_id,
        )
        .order_by(AssessmentSnapshot.taken_at.desc())
    ).all()
    return [_summary(s, n) for s, n in rows]


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> ReportOut:
    row = db.execute(
        select(AssessmentSnapshot, User.display_name)
        .join(User, User.id == AssessmentSnapshot.taken_by_user_id)
        .where(
            AssessmentSnapshot.id == report_id, AssessmentSnapshot.workspace_id == ctx.workspace_id
        )
    ).first()
    if row is None:
        raise not_found("Report not found.")
    s, name = row
    ok = hashlib.sha256(canonical(s.content)).digest() == s.content_sha256
    return ReportOut(**_summary(s, name).model_dump(), integrity_ok=ok, content=s.content)
