"""Read-only audit log (Addendum 5: SYSTEM → Audit Log; the first CHRONICLE view).

The app role can only insert and select audit events (migration 0001), and row-level security
limits it to the current workspace, so sign-in events without a workspace never appear here.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select, tuple_

from nightfall.core.db.models import ActorType, AuditEvent, User
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["audit"])

PAGE = 50
# Defence in depth: nothing secret is meant to be written to audit data, but never echo a
# field that looks like one.
_SECRET_KEY = re.compile(r"secret|token|password|passwd|authorization|cookie|totp|otp|code", re.I)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "<redacted>" if _SECRET_KEY.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class AuditEventOut(Model):
    id: uuid.UUID
    action: str
    actor: str
    actor_type: str
    entity_type: str | None
    entity_id: uuid.UUID | None
    data: dict[str, Any]
    ip: str | None
    occurred_at: datetime


class AuditPage(Model):
    events: list[AuditEventOut]
    categories: list[str]
    next_before: uuid.UUID | None


@router.get("/audit", response_model=AuditPage)
def audit_log(
    db: DB,
    category: Annotated[str | None, Query(max_length=40, pattern=r"^[a-z_]+$")] = None,
    before: uuid.UUID | None = None,
    ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ),
) -> AuditPage:
    ws = ctx.workspace_id
    prefix = func.split_part(AuditEvent.action, ".", 1)
    q = select(AuditEvent).where(AuditEvent.workspace_id == ws)
    if category:
        q = q.where(prefix == category)
    if before is not None:
        anchor = db.get(AuditEvent, before)
        if anchor is None or anchor.workspace_id != ws:
            raise not_found("That audit event isn't in this workspace.")
        q = q.where(tuple_(AuditEvent.occurred_at, AuditEvent.id) < (anchor.occurred_at, anchor.id))
    rows = db.scalars(
        q.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(PAGE + 1)
    ).all()
    more = len(rows) > PAGE
    rows = rows[:PAGE]
    ids = {e.actor_id for e in rows if e.actor_type is ActorType.USER and e.actor_id}
    names = (
        dict(db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).all())
        if ids
        else {}
    )
    categories = sorted(
        db.scalars(select(prefix).where(AuditEvent.workspace_id == ws).distinct()).all()
    )
    return AuditPage(
        events=[
            AuditEventOut(
                id=e.id,
                action=e.action,
                actor=names.get(e.actor_id, "A former member")
                if e.actor_type is ActorType.USER and e.actor_id
                else e.actor_type.value.capitalize(),
                actor_type=e.actor_type.value,
                entity_type=e.entity_type,
                entity_id=e.entity_id,
                data=redact(e.data),
                ip=e.ip,
                occurred_at=e.occurred_at,
            )
            for e in rows
        ],
        categories=categories,
        next_before=rows[-1].id if more else None,
    )
