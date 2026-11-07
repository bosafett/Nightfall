"""Audit export with a hash chain (review F7).

The Neon owner credential can change or delete audit rows. Append-only storage outside the
database (e.g. object lock) would prevent that, but it's an external service and an owner
decision. This gives detection without one:

  * Export: every audit event of the workspace, oldest first, as canonical JSON records.
    Each carries `hash = sha256(prev_hash + "\\n" + canonical record)`, starting from a
    per-workspace genesis value, so changing, removing or inserting any earlier event
    changes every hash after it. The owner keeps the file outside this system.
  * Check: given the last record of a kept export (its id, position and hash), the server
    recomputes the chain from the start and says whether it still matches.

Limits, stated in the UI too: secret-looking fields are redacted before hashing, so a change
to a redacted value isn't detected; events without a workspace (sign-ins) aren't included;
and events newer than SETTLE are left for the next export, so a transaction that commits
late can't insert into the middle of an exported range.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import Field
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from nightfall.core.audit.routes import redact
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AuditEvent
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

FORMAT = "janus-audit-export/v1"
SETTLE = timedelta(minutes=5)
EXPORT_PAGE = 1000


def genesis(workspace_id: uuid.UUID) -> str:
    return hashlib.sha256(f"{FORMAT}:{workspace_id}".encode()).hexdigest()


def record_of(e: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "occurred_at": e.occurred_at.isoformat(),
        "action": e.action,
        "actor_type": e.actor_type.value,
        "actor_id": str(e.actor_id) if e.actor_id else None,
        "entity_type": e.entity_type,
        "entity_id": str(e.entity_id) if e.entity_id else None,
        "data": redact(e.data),
        "ip": e.ip,
        "user_agent": e.user_agent,
    }


def canonical(rec: dict[str, Any]) -> str:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link(prev: str, rec: dict[str, Any]) -> str:
    return hashlib.sha256(f"{prev}\n{canonical(rec)}".encode()).hexdigest()


def events(
    db: Session,
    workspace_id: uuid.UUID,
    cutoff: datetime,
    after: AuditEvent | None = None,
    limit: int | None = None,
) -> Iterator[AuditEvent]:
    q = select(AuditEvent).where(
        AuditEvent.workspace_id == workspace_id, AuditEvent.occurred_at <= cutoff
    )
    if after is not None:
        q = q.where(tuple_(AuditEvent.occurred_at, AuditEvent.id) > (after.occurred_at, after.id))
    q = q.order_by(AuditEvent.occurred_at, AuditEvent.id)
    if limit is not None:
        q = q.limit(limit)
    yield from db.scalars(q.execution_options(yield_per=500))


# --- Routes ------------------------------------------------------------------------------

router = APIRouter(prefix="/api/workspaces/{workspace_id}/audit/export", tags=["audit"])


class AuditExportRecord(Model):
    position: int  # 1-based position in the workspace's chain
    hash: str
    record: dict[str, Any]


class AuditExportCursor(Model):
    after: uuid.UUID
    position: int
    prev: str = Field(pattern=r"^[0-9a-f]{64}$")
    cutoff: datetime


class AuditExportPage(Model):
    format: str
    workspace_id: uuid.UUID
    genesis: str
    cutoff: datetime
    records: list[AuditExportRecord]
    next: AuditExportCursor | None


def _anchor(db: Session, ws: uuid.UUID, event_id: uuid.UUID) -> AuditEvent | None:
    e = db.get(AuditEvent, event_id)
    return e if e is not None and e.workspace_id == ws else None


@router.post("", response_model=AuditExportPage)
def export_page(
    db: DB,
    cursor: AuditExportCursor | None = None,
    ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ),
) -> AuditExportPage:
    """One page of the chained export. Call again with `next` until it is null."""
    ws = ctx.workspace_id
    if cursor is None:
        cutoff, after, position, prev = utcnow() - SETTLE, None, 0, genesis(ws)
    else:
        after = _anchor(db, ws, cursor.after)
        if after is None:
            raise not_found("That audit event isn't in this workspace.")
        cutoff, position, prev = cursor.cutoff, cursor.position, cursor.prev
    rows = list(events(db, ws, cutoff, after, EXPORT_PAGE + 1))
    more = len(rows) > EXPORT_PAGE
    out: list[AuditExportRecord] = []
    for e in rows[:EXPORT_PAGE]:
        rec = record_of(e)
        prev = link(prev, rec)
        position += 1
        out.append(AuditExportRecord(position=position, hash=prev, record=rec))
    nxt = (
        AuditExportCursor(
            after=rows[EXPORT_PAGE - 1].id, position=position, prev=prev, cutoff=cutoff
        )
        if more
        else None
    )
    if nxt is None:
        record(
            db,
            "audit.exported",
            entity_type="workspace",
            entity_id=ws,
            data={
                "format": FORMAT,
                "events": position,
                "head_hash": prev,
                "cutoff": cutoff.isoformat(),
            },
            **ctx.audit_kwargs(),
        )
    return AuditExportPage(
        format=FORMAT, workspace_id=ws, genesis=genesis(ws), cutoff=cutoff, records=out, next=nxt
    )


class AuditCheckIn(Model):
    through_id: uuid.UUID
    position: int = Field(ge=1)
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuditCheckOut(Model):
    match: bool
    problem: Literal["missing", "position", "hash"] | None
    detail: str
    events_checked: int


@router.post("/check", response_model=AuditCheckOut)
def check_export(
    body: AuditCheckIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ)
) -> AuditCheckOut:
    """Recompute the chain up to the last record of a kept export and compare."""
    ws = ctx.workspace_id
    through = _anchor(db, ws, body.through_id)
    if through is None:
        res = AuditCheckOut(
            match=False,
            problem="missing",
            detail="The export's last event is no longer in the audit log.",
            events_checked=0,
        )
    else:
        prev, position = genesis(ws), 0
        for e in events(db, ws, through.occurred_at):
            prev, position = link(prev, record_of(e)), position + 1
            if e.id == through.id:
                break
        if position != body.position:
            res = AuditCheckOut(
                match=False,
                problem="position",
                detail=f"The export's last event is now number {position}, not "
                f"{body.position}: events before it were added or removed.",
                events_checked=position,
            )
        elif prev != body.hash:
            res = AuditCheckOut(
                match=False,
                problem="hash",
                detail="The chain no longer matches: an event up to the export's last one "
                "was changed.",
                events_checked=position,
            )
        else:
            res = AuditCheckOut(
                match=True,
                problem=None,
                detail=f"All {position} events up to the export's last one match.",
                events_checked=position,
            )
    record(
        db,
        "audit.export_checked",
        entity_type="workspace",
        entity_id=ws,
        data={"match": res.match, "problem": res.problem, "position": body.position},
        **ctx.audit_kwargs(),
    )
    return res
