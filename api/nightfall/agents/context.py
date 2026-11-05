"""What each agent is shown. Everything collected from targets goes into delimited,
size-capped <data> blocks in the user turn, never into the system prompt (review §6).
Only the current task's project is read, under that workspace's row-level security.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    AgentTask,
    Asset,
    Evidence,
    Finding,
    FindingEvidence,
    Operation,
    Project,
    ScopeEntryKind,
    ScopeExclusion,
    ScopeTarget,
)
from nightfall.core.evidence_store import BlobStore, IntegrityError
from nightfall.scope.repository import active_scope

MAX_ASSETS = 200
MAX_OPERATIONS = 50
MAX_EVIDENCE = 30
MAX_SUMMARY_CHARS = 2_000
MAX_RAW_CHARS = 8_000


def _neutralize(text: str) -> str:
    # A block can't be closed early by content: '</data' inside data is broken up.
    return text.replace("</data", "<\\/data").replace("<data", "<\\data")


def data_block(source: str, payload: Any, limit: int, **attrs: str) -> str:
    raw = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, default=str)
    truncated = len(raw) > limit
    raw = raw[:limit]
    extra = "".join(f' {k}="{_neutralize(str(v))[:100]}"' for k, v in attrs.items())
    note = ' truncated="true"' if truncated else ""
    return f'<data source="{source}"{extra}{note}>\n{_neutralize(raw)}\n</data>'


@dataclass
class Prepared:
    user: str
    shown_evidence: set[uuid.UUID] = field(default_factory=set)


def _project_header(db: Session, task: AgentTask) -> list[str]:
    project = db.get(Project, task.project_id)
    name = project.name if project else "?"
    return [
        f"Task: {task.objective}",
        f"Project: {name}",
    ]


def _scope_blocks(db: Session, task: AgentTask) -> list[str]:
    scope = active_scope(db, task.project_id)
    if scope is None:
        return [data_block("scope", {"status": "no active scope"}, 500)]
    targets = db.execute(
        select(ScopeTarget.kind, ScopeTarget.value).where(ScopeTarget.scope_id == scope.id)
    ).all()
    exclusions = db.execute(
        select(ScopeExclusion.kind, ScopeExclusion.value).where(ScopeExclusion.scope_id == scope.id)
    ).all()

    def fmt(kind: ScopeEntryKind, value: str) -> str:
        return f"{kind.value}: {value}"

    return [
        data_block(
            "scope",
            {
                "version": scope.version,
                "in_scope": [fmt(k, v) for k, v in targets],
                "excluded": [fmt(k, v) for k, v in exclusions],
            },
            6_000,
        )
    ]


def _org_id(db: Session, task: AgentTask) -> uuid.UUID | None:
    return db.scalar(select(Project.organization_id).where(Project.id == task.project_id))


def _asset_block(db: Session, task: AgentTask) -> str:
    rows = db.execute(
        select(Asset.kind, Asset.value, Asset.source, Asset.last_seen_at)
        .where(Asset.organization_id == _org_id(db, task))
        .order_by(Asset.last_seen_at.desc())
        .limit(MAX_ASSETS)
    ).all()
    return data_block(
        "assets",
        [{"kind": k.value, "value": v, "source": s, "last_seen": str(t)} for k, v, s, t in rows],
        20_000,
    )


def scout(db: Session, task: AgentTask) -> Prepared:
    since = utcnow() - timedelta(days=30)
    ops = db.execute(
        select(Operation.tool, Operation.target_value, Operation.status, Operation.created_at)
        .where(Operation.project_id == task.project_id, Operation.created_at >= since)
        .order_by(Operation.created_at.desc())
        .limit(MAX_OPERATIONS)
    ).all()
    blocks = [
        *_scope_blocks(db, task),
        _asset_block(db, task),
        data_block(
            "recent_collections",
            [{"tool": t, "target": v, "status": s.value, "at": str(c)} for t, v, s, c in ops],
            8_000,
        ),
    ]
    return Prepared(user="\n\n".join([*_project_header(db, task), *blocks]))


def hunter(db: Session, task: AgentTask) -> Prepared:
    evidence = (
        db.execute(
            select(Evidence)
            .where(Evidence.project_id == task.project_id)
            .order_by(Evidence.collected_at.desc())
            .limit(MAX_EVIDENCE)
        )
        .scalars()
        .all()
    )
    existing = db.execute(
        select(Finding.title, Finding.validation_status)
        .where(Finding.project_id == task.project_id)
        .limit(200)
    ).all()
    blocks = [_asset_block(db, task)]
    shown: set[uuid.UUID] = set()
    for e in evidence:
        shown.add(e.id)
        blocks.append(
            data_block(
                "evidence",
                {"summary": e.summary, "simulation": e.is_simulation},
                MAX_SUMMARY_CHARS,
                id=str(e.id),
                tool=f"{e.tool_name} {e.tool_version}",
                collected_at=str(e.collected_at),
            )
        )
    blocks.append(
        data_block(
            "recorded_findings",
            [{"title": t, "status": s.value} for t, s in existing],
            8_000,
        )
    )
    return Prepared(user="\n\n".join([*_project_header(db, task), *blocks]), shown_evidence=shown)


def guardian(db: Session, task: AgentTask, store: BlobStore) -> Prepared:
    finding = db.get(Finding, task.subject_finding_id) if task.subject_finding_id else None
    if finding is None:
        raise LookupError("The finding to review no longer exists.")
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    claim = {
        "title": finding.title,
        "severity": finding.severity.value,
        "asset": asset.value if asset else None,
        "description": finding.description,
        "impact": finding.impact,
    }
    blocks = [data_block("claim", claim, 6_000)]
    cited = (
        db.execute(
            select(Evidence)
            .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
            .where(FindingEvidence.finding_id == finding.id)
        )
        .scalars()
        .all()
    )
    for e in cited:
        try:
            raw = store.get(e.content_sha256).decode("utf-8", "replace")
        except IntegrityError:
            raw = "(content unavailable: failed its integrity check)"
        blocks.append(
            data_block(
                "evidence",
                raw,
                MAX_RAW_CHARS,
                id=str(e.id),
                tool=f"{e.tool_name} {e.tool_version}",
                collected_at=str(e.collected_at),
            )
        )
    return Prepared(user="\n\n".join(["Review this claimed finding.", *blocks]))
