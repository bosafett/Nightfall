"""BLACK ICE endpoints: source freshness and report replay (review §14)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import select

from nightfall.blackice.freshness import STALE_AFTER, source_states
from nightfall.blackice.replay import Item, replay
from nightfall.config import get_settings
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AssessmentSnapshot, RiskClass
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.recon.collectors import TOOLS

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["black-ice"])


class SourceOut(Model):
    key: str
    label: str
    risk_class: RiskClass
    state: Literal["fresh", "stale", "failing", "never_run", "unavailable"]
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error: str | None


class SourcesOut(Model):
    stale_after_days: int
    sources: list[SourceOut]


@router.get("/sources", response_model=SourcesOut)
def sources(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> SourcesOut:
    s = get_settings()
    # Serverless hosting can't run the tool sandbox, so tool-based sources can't run there.
    unavailable = {"nuclei"} if s.on_demand_worker and not s.nuclei_bin else set()
    states = source_states(db, ctx.workspace_id, list(TOOLS), unavailable, utcnow())
    return SourcesOut(
        stale_after_days=STALE_AFTER.days,
        sources=[
            SourceOut(
                key=st.key,
                label=TOOLS[st.key][0],
                risk_class=TOOLS[st.key][1],
                state=st.state,  # type: ignore[arg-type]
                last_success_at=st.last_success_at,
                last_failure_at=st.last_failure_at,
                last_error=(st.last_error or "")[:300] or None,
            )
            for st in states
        ],
    )


class ReplayItem(Model):
    asset: str | None
    check_id: str | None
    rule_id: str
    title: str
    severity: str


class ReplayChange(Model):
    then: ReplayItem
    now: ReplayItem


class ReplayOut(Model):
    report_id: uuid.UUID
    as_of: datetime
    snapshot_ruleset: str
    current_ruleset: str
    evidence_considered: int
    unchanged: list[ReplayItem]
    changed: list[ReplayChange]
    new: list[ReplayItem]
    gone: list[ReplayItem]


def _item(i: Item) -> ReplayItem:
    return ReplayItem(
        asset=i.asset, check_id=i.check_id, rule_id=i.rule_id, title=i.title, severity=i.severity
    )


@router.get("/reports/{report_id}/replay", response_model=ReplayOut)
def replay_report(
    report_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> ReplayOut:
    """Read-only: re-runs the current finding rules over the evidence as of this report."""
    snap = db.scalar(
        select(AssessmentSnapshot).where(
            AssessmentSnapshot.id == report_id,
            AssessmentSnapshot.workspace_id == ctx.workspace_id,
        )
    )
    if snap is None:
        raise not_found("Report not found.")
    d = replay(db, snap)
    return ReplayOut(
        report_id=snap.id,
        as_of=d.as_of,
        snapshot_ruleset=d.snapshot_ruleset,
        current_ruleset=d.current_ruleset,
        evidence_considered=d.evidence_considered,
        unchanged=[_item(i) for i in d.unchanged],
        changed=[ReplayChange(then=_item(a), now=_item(b)) for a, b in d.changed],
        new=[_item(i) for i in d.new],
        gone=[_item(i) for i in d.gone],
    )
