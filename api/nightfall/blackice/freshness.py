"""BLACK ICE source freshness (review §14, A5): when each data source last worked, derived
from the operations table (no extra state).

States, per source, for this workspace's real-world (non-lab) collections:
  * fresh        last success within STALE_AFTER, and nothing has failed since
  * stale        last success is older than STALE_AFTER
  * failing      the most recent finished run failed (the source may be down right now)
  * never_run    no finished run yet
  * unavailable  can't run on this deployment (e.g. the tool sandbox isn't present)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nightfall.core.db.models import Operation, OperationStatus

STALE_AFTER = timedelta(days=7)


@dataclass(frozen=True)
class SourceState:
    key: str
    state: str
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error: str | None


def source_states(
    db: Session, workspace_id: object, keys: list[str], unavailable: set[str], now: datetime
) -> list[SourceState]:
    base = (
        Operation.workspace_id == workspace_id,
        Operation.is_lab.is_(False),
        Operation.finished_at.is_not(None),
    )
    ok = dict(
        db.execute(
            select(Operation.tool, func.max(Operation.finished_at))
            .where(*base, Operation.status == OperationStatus.SUCCEEDED)
            .group_by(Operation.tool)
        ).all()
    )
    bad = dict(
        db.execute(
            select(Operation.tool, func.max(Operation.finished_at))
            .where(*base, Operation.status == OperationStatus.FAILED)
            .group_by(Operation.tool)
        ).all()
    )
    out: list[SourceState] = []
    for key in keys:
        s, f = ok.get(key), bad.get(key)
        error = None
        if f is not None:
            error = db.scalar(
                select(Operation.error)
                .where(*base, Operation.tool == key, Operation.status == OperationStatus.FAILED)
                .order_by(Operation.finished_at.desc())
                .limit(1)
            )
        if key in unavailable:
            state = "unavailable"
        elif s is None and f is None:
            state = "never_run"
        elif f is not None and (s is None or f > s):
            state = "failing"
        elif s is not None and now - s > STALE_AFTER:
            state = "stale"
        else:
            state = "fresh"
        out.append(SourceState(key, state, s, f, error))
    return out
