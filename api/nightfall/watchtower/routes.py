"""Platform integrity for the owner and admins.

`/api/health` is public, so it never mentions the lab. This route is behind sign-in and
reports what the database actually shows: worker and lab worker heartbeats, whether this
deployment can still write audit events, and failed work in the last day.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import func, select, text

from nightfall.config import get_settings
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AuditEvent, Operation, OperationStatus, WorkerHeartbeat
from nightfall.core.db.session import DB
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.recon.worker import LAB_HEARTBEAT_PREFIX, PROFILE_B_HEARTBEAT_PREFIX

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["watchtower"])

FRESH = timedelta(seconds=30)  # same window as /api/health


class Heartbeat(Model):
    status: Literal["online", "offline", "never", "on_demand"]
    last_seen_at: datetime | None


class AuditPipeline(Model):
    status: Literal["ok", "down"]
    last_event_at: datetime | None


class WatchtowerOut(Model):
    checked_at: datetime
    worker: Heartbeat
    lab: Heartbeat
    profile_b: Heartbeat
    audit: AuditPipeline
    failed_operations_24h: int


def _beat(last: datetime | None, now: datetime) -> Heartbeat:
    if last is None:
        return Heartbeat(status="never", last_seen_at=None)
    return Heartbeat(status="online" if last > now - FRESH else "offline", last_seen_at=last)


@router.get("/watchtower", response_model=WatchtowerOut)
def watchtower(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ)
) -> WatchtowerOut:
    now = utcnow()
    is_lab = WorkerHeartbeat.worker_id.startswith(LAB_HEARTBEAT_PREFIX)
    lab_last = db.scalar(select(func.max(WorkerHeartbeat.last_seen_at)).where(is_lab))
    is_pb = WorkerHeartbeat.worker_id.startswith(PROFILE_B_HEARTBEAT_PREFIX)
    pb_last = db.scalar(select(func.max(WorkerHeartbeat.last_seen_at)).where(is_pb))
    worker_last = db.scalar(select(func.max(WorkerHeartbeat.last_seen_at)).where(~is_lab, ~is_pb))
    worker = (
        Heartbeat(status="on_demand", last_seen_at=worker_last)
        if get_settings().on_demand_worker
        else _beat(worker_last, now)
    )
    can_write = bool(
        db.scalar(text("SELECT has_table_privilege(current_user, 'audit_events', 'INSERT')"))
    )
    last_event = db.scalar(
        select(func.max(AuditEvent.occurred_at)).where(AuditEvent.workspace_id == ctx.workspace_id)
    )
    failed = db.scalar(
        select(func.count()).where(
            Operation.workspace_id == ctx.workspace_id,
            Operation.status == OperationStatus.FAILED,
            Operation.finished_at > now - timedelta(hours=24),
        )
    )
    return WatchtowerOut(
        checked_at=now,
        worker=worker,
        lab=_beat(lab_last, now),
        profile_b=_beat(pb_last, now),
        audit=AuditPipeline(status="ok" if can_write else "down", last_event_at=last_event),
        failed_operations_24h=failed or 0,
    )
