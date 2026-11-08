"""The daily SHIELD run (called by the platform's cron, before the queue is drained).

For every live standing authorization, in its own transaction with that workspace's
context: end it if it expired or its scope version is no longer the active one (raising an
alert either way); warn 7 days before expiry; and, at most once per 20 hours, queue one
ordinary operation per covered target and check. Each queued operation is still checked by
the worker when it runs (scope, authorization, risk). At most DAILY_CAP scheduled checks per
workspace per day (owner decision 2): anything over the cap waits for the next day.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.db.models import (
    ActorType,
    MonitorAuthorization,
    Operation,
    OperationStatus,
    Severity,
)
from nightfall.shield.alerts import raise_alert
from nightfall.shield.rules import AlertDraft

log = logging.getLogger("nightfall.shield")
DAILY_CAP = 30
RUN_EVERY = timedelta(hours=20)
WARN_BEFORE = timedelta(days=7)
PENDING = (OperationStatus.QUEUED, OperationStatus.RUNNING, OperationStatus.AWAITING_APPROVAL)


def _end(db: Session, a: MonitorAuthorization, reason: str, note: str, now: datetime) -> None:
    a.ended_at, a.ended_reason, a.end_note = now, reason, note
    db.flush()
    record(
        db, "monitor.ended", actor_type=ActorType.SYSTEM, workspace_id=a.workspace_id,
        entity_type="monitor_authorization", entity_id=a.id,
        data={"project_id": str(a.project_id), "reason": reason, "note": note},
    )  # fmt: skip
    raise_alert(
        db, a.workspace_id, a.project_id, a.id,
        AlertDraft("monitor.ended", Severity.MEDIUM, "Monitoring stopped", note,
                   f"monitor.ended:{a.id}"),
        ", ".join(a.targets)[:300], now,
    )  # fmt: skip


def schedule_one(db: Session, a: MonitorAuthorization, now: datetime) -> int:
    """Returns how many operations it queued."""
    from nightfall.recon.collectors import TOOLS
    from nightfall.scope.engine import evaluate
    from nightfall.scope.repository import active_scope, snapshot

    if a.expires_at <= now:
        _end(db, a, "expired", "The 30-day authorization expired. Renew it to continue.", now)
        return 0
    current = active_scope(db, a.project_id)
    if current is None or current.id != a.scope_id or current.is_lab:
        _end(db, a, "scope_changed", "The project's authorized scope changed.", now)
        return 0
    if a.expires_at - now <= WARN_BEFORE:
        raise_alert(
            db, a.workspace_id, a.project_id, a.id,
            AlertDraft("monitor.expiring", Severity.LOW, "Monitoring authorization expires soon",
                       f"It expires on {a.expires_at:%Y-%m-%d %H:%M} UTC.",
                       f"monitor.expiring:{a.id}"),
            ", ".join(a.targets)[:300], now,
        )  # fmt: skip
    if a.last_run_at is not None and now - a.last_run_at < RUN_EVERY:
        return 0
    used = (
        db.scalar(
            select(func.count())
            .select_from(Operation)
            .where(
                Operation.workspace_id == a.workspace_id,
                Operation.monitor_authorization_id.is_not(None),
                Operation.created_at >= now - timedelta(hours=24),
            )
        )
        or 0
    )
    snap = snapshot(db, current)
    queued, skipped = 0, []
    for target in a.targets:
        for tool in a.checks:
            if used + queued >= DAILY_CAP:
                skipped.append(f"{tool} {target}: daily cap of {DAILY_CAP} reached")
                continue
            decision = evaluate(snap, target, now)
            if not decision.allowed:
                skipped.append(f"{tool} {target}: {decision.reason}")
                continue
            busy = db.scalar(
                select(Operation.id).where(
                    Operation.project_id == a.project_id,
                    Operation.tool == tool,
                    Operation.target_value == decision.target,
                    Operation.status.in_(PENDING),
                )
            )
            if busy is not None:
                skipped.append(f"{tool} {target}: already pending")
                continue
            label, risk = TOOLS[tool]
            db.add(
                Operation(
                    workspace_id=a.workspace_id,
                    project_id=a.project_id,
                    scope_id=a.scope_id,
                    tool=tool,
                    risk_class=risk,
                    target_value=decision.target,
                    params={"method": label, "scheduled": True},
                    requested_by_user_id=a.authorized_by_user_id,
                    monitor_authorization_id=a.id,
                    status=OperationStatus.QUEUED,
                )
            )
            queued += 1
    a.last_run_at = now
    db.flush()
    record(
        db, "monitor.run_queued", actor_type=ActorType.SYSTEM, workspace_id=a.workspace_id,
        entity_type="monitor_authorization", entity_id=a.id,
        data={"project_id": str(a.project_id), "queued": queued, "skipped": skipped[:50]},
    )  # fmt: skip
    return queued


def schedule(sessions: Callable[[], Session], now: datetime) -> int:
    """Worker role. Each authorization in its own transaction, with its workspace context."""
    from nightfall.core.db.session import set_workspace_context

    with sessions() as db:
        rows = db.execute(
            select(MonitorAuthorization.id, MonitorAuthorization.workspace_id).where(
                MonitorAuthorization.ended_at.is_(None)
            )
        ).all()
    total = 0
    for auth_id, ws in rows:
        try:
            with sessions() as db:
                set_workspace_context(db, ws)
                a = db.get(MonitorAuthorization, auth_id)
                if a is None or a.ended_at is not None:
                    continue
                total += schedule_one(db, a, now)
                db.commit()
        except Exception:  # one bad authorization must not stop the others
            log.exception("SHIELD scheduling failed for authorization %s", auth_id)
    return total
