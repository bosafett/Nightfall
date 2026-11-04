"""Audit writer. audit_events is append-only for the API role (INSERT/SELECT grants only).

record()          writes inside the request's transaction (use for successful mutations).
record_detached() commits on its own connection, so denials and failed sign-ins are kept
                  even though the request itself fails and rolls back.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, TypedDict

from sqlalchemy import insert
from sqlalchemy.orm import Session

from nightfall.core.db.models import ActorType, AuditEvent
from nightfall.core.db.session import get_session_factory, set_workspace_context

log = logging.getLogger("nightfall.audit")


class AuditActor(TypedDict):
    actor_id: uuid.UUID
    workspace_id: uuid.UUID
    ip: str
    user_agent: str


def record(
    db: Session,
    action: str,
    *,
    actor_type: ActorType = ActorType.USER,
    actor_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
    data: dict[str, Any] | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    db.execute(
        insert(AuditEvent).values(
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            workspace_id=workspace_id,
            entity_type=entity_type,
            entity_id=entity_id,
            data=data or {},
            ip=ip,
            user_agent=user_agent,
        )
    )


def record_detached(action: str, **kwargs: Any) -> None:
    try:
        with get_session_factory()() as db:
            ws = kwargs.get("workspace_id")
            if ws is not None:
                set_workspace_context(db, ws)
            record(db, action, **kwargs)
            db.commit()
    except Exception:  # never let audit failure mask the original response
        log.exception("failed to write detached audit event %s", action)
