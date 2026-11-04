"""Loading scope snapshots from the database (shared by API and worker)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.core.db.models import Scope, ScopeExclusion, ScopeStatus, ScopeTarget
from nightfall.scope.engine import Entry, ScopeSnapshot


def snapshot(db: Session, scope: Scope) -> ScopeSnapshot:
    targets = db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id == scope.id)).all()
    exclusions = db.scalars(select(ScopeExclusion).where(ScopeExclusion.scope_id == scope.id)).all()
    return ScopeSnapshot(
        status=scope.status,
        valid_from=scope.valid_from,
        valid_until=scope.valid_until,
        targets=tuple(Entry(t.kind, t.value) for t in targets),
        exclusions=tuple(Entry(e.kind, e.value) for e in exclusions),
    )


def active_scope(db: Session, project_id: uuid.UUID) -> Scope | None:
    return db.scalar(
        select(Scope).where(Scope.project_id == project_id, Scope.status == ScopeStatus.ACTIVE)
    )
