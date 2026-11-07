"""Versioned project scopes: draft → authorize → active → superseded.

Analysts may edit drafts; only roles with scope.authorize (admin/owner, with MFA) can make
a draft the active scope. An authorized version never changes (enforced by DB triggers);
changing scope means a new version and a new authorization.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter
from pydantic import Field, StringConstraints, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Project,
    Scope,
    ScopeEntryKind,
    ScopeExclusion,
    ScopeStatus,
    ScopeTarget,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model, OkOut
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.scope.engine import evaluate, normalize_entry
from nightfall.scope.lab import entry_problem
from nightfall.scope.normalize import NormalizationError
from nightfall.scope.ownership import proof_for
from nightfall.scope.repository import active_scope, snapshot

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["scope"])
Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]
MAX_ENTRIES = 500


Port = Annotated[int, Field(ge=1, le=65535)]


class EntryIn(Model):
    kind: ScopeEntryKind
    value: Annotated[str, StringConstraints(max_length=300)]
    note: Short = ""
    # Probe bounds for this target (BLACKSITE probe deck). Ignored for exclusions.
    allowed_ports: Annotated[list[Port], Field(min_length=1, max_length=10)] = [80, 443]
    max_rps: Annotated[int, Field(ge=1, le=10)] = 1
    daily_budget: Annotated[int, Field(ge=1, le=5000)] = 200


class ControlOut(Model):
    proven: bool
    claim_id: uuid.UUID | None = None
    claim_name: str | None = None
    method: str | None = None
    checked_at: datetime | None = None


class EntryOut(Model):
    id: uuid.UUID
    kind: ScopeEntryKind
    value: str
    note: str
    allowed_ports: list[int] | None = None
    max_rps: int | None = None
    daily_budget: int | None = None
    # Proof of control (Profile B G1): set only on targets of the active scope.
    control: ControlOut | None = None


class ScopePatch(Model):
    authorization_reference: Short | None = None
    is_lab: bool | None = None  # isolated lab scope (Phase 6b): lab-network addresses only
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @model_validator(mode="after")
    def _window(self) -> ScopePatch:
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("The end of the authorization period must be after its start.")
        return self


class ScopeOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    version: int
    status: ScopeStatus
    authorization_reference: str
    valid_from: datetime | None
    valid_until: datetime | None
    created_by: str
    authorized_by: str | None
    authorized_at: datetime | None
    superseded_at: datetime | None
    created_at: datetime
    is_lab: bool
    targets: list[EntryOut]
    exclusions: list[EntryOut]


class CheckIn(Model):
    value: Annotated[str, StringConstraints(max_length=300)]


class CheckOut(Model):
    allowed: bool
    reason: str
    normalized: str
    scope_version: int | None


def _project(db: Session, ctx: WorkspaceContext, project_id: uuid.UUID) -> Project:
    p = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if p is None:
        raise not_found("Project not found.")
    return p


def _scope(db: Session, ctx: WorkspaceContext, scope_id: uuid.UUID) -> Scope:
    s = db.scalar(select(Scope).where(Scope.id == scope_id, Scope.workspace_id == ctx.workspace_id))
    if s is None:
        raise not_found("Scope not found.")
    return s


def _draft(db: Session, ctx: WorkspaceContext, scope_id: uuid.UUID) -> Scope:
    s = _scope(db, ctx, scope_id)
    if s.status is not ScopeStatus.DRAFT:
        raise api_error(
            409,
            "scope_locked",
            "This scope version is authorized and can't change. Start a new draft.",
        )
    return s


def _control(db: Session, s: Scope, t: ScopeTarget) -> ControlOut | None:
    if s.status is not ScopeStatus.ACTIVE or s.is_lab:
        return None
    p = proof_for(db, s, t.kind, t.value)
    if p is None:
        return ControlOut(proven=False)
    return ControlOut(
        proven=True,
        claim_id=p.claim.id,
        claim_name=p.claim.name,
        method=p.claim.method.value,
        checked_at=p.check.checked_at,
    )


def _out(db: Session, s: Scope) -> ScopeOut:
    names = dict(
        db.execute(
            select(User.id, User.display_name).where(
                User.id.in_([u for u in (s.created_by_user_id, s.authorized_by_user_id) if u])
            )
        )
        .tuples()
        .all()
    )
    targets = db.scalars(
        select(ScopeTarget)
        .where(ScopeTarget.scope_id == s.id)
        .order_by(ScopeTarget.kind, ScopeTarget.value)
    ).all()
    exclusions = db.scalars(
        select(ScopeExclusion)
        .where(ScopeExclusion.scope_id == s.id)
        .order_by(ScopeExclusion.kind, ScopeExclusion.value)
    ).all()
    return ScopeOut(
        id=s.id,
        project_id=s.project_id,
        version=s.version,
        status=s.status,
        authorization_reference=s.authorization_reference,
        valid_from=s.valid_from,
        valid_until=s.valid_until,
        created_by=names.get(s.created_by_user_id, "Unknown"),
        authorized_by=names.get(s.authorized_by_user_id) if s.authorized_by_user_id else None,
        authorized_at=s.authorized_at,
        superseded_at=s.superseded_at,
        created_at=s.created_at,
        is_lab=s.is_lab,
        targets=[
            EntryOut(
                id=t.id,
                kind=t.kind,
                value=t.value,
                note=t.note,
                allowed_ports=t.allowed_ports,
                max_rps=t.max_rps,
                daily_budget=t.daily_budget,
                control=_control(db, s, t),
            )
            for t in targets
        ],
        exclusions=[
            EntryOut(id=e.id, kind=e.kind, value=e.value, note=e.reason) for e in exclusions
        ],
    )


@router.get("/projects/{project_id}/scopes", response_model=list[ScopeOut])
def list_scopes(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[ScopeOut]:
    _project(db, ctx, project_id)
    scopes = db.scalars(
        select(Scope).where(Scope.project_id == project_id).order_by(Scope.version.desc())
    ).all()
    return [_out(db, s) for s in scopes]


@router.post("/projects/{project_id}/scopes", response_model=ScopeOut, status_code=201)
def start_draft(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE)
) -> ScopeOut:
    """New draft version, pre-filled from the active version if there is one."""
    _project(db, ctx, project_id)
    if db.scalar(
        select(Scope.id).where(Scope.project_id == project_id, Scope.status == ScopeStatus.DRAFT)
    ):
        raise api_error(409, "draft_exists", "This project already has a draft scope.")
    version = (
        db.scalar(select(func.max(Scope.version)).where(Scope.project_id == project_id)) or 0
    ) + 1
    current = active_scope(db, project_id)
    draft = Scope(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        version=version,
        created_by_user_id=ctx.user_id,
        authorization_reference=current.authorization_reference if current else "",
        valid_from=current.valid_from if current else None,
        valid_until=current.valid_until if current else None,
        is_lab=current.is_lab if current else False,
    )
    db.add(draft)
    db.flush()
    if current:
        for t in db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id == current.id)):
            db.add(
                ScopeTarget(
                    workspace_id=ctx.workspace_id,
                    scope_id=draft.id,
                    kind=t.kind,
                    value=t.value,
                    note=t.note,
                )
            )
        for e in db.scalars(select(ScopeExclusion).where(ScopeExclusion.scope_id == current.id)):
            db.add(
                ScopeExclusion(
                    workspace_id=ctx.workspace_id,
                    scope_id=draft.id,
                    kind=e.kind,
                    value=e.value,
                    reason=e.reason,
                )
            )
        db.flush()
    db.refresh(draft)
    record(
        db,
        "scope.draft_created",
        entity_type="scope",
        entity_id=draft.id,
        data={"project_id": str(project_id), "version": version},
        **ctx.audit_kwargs(),
    )
    return _out(db, draft)


@router.patch("/scopes/{scope_id}", response_model=ScopeOut)
def update_draft(
    scope_id: uuid.UUID,
    body: ScopePatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ScopeOut:
    s = _draft(db, ctx, scope_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("is_lab") is None:
        changes.pop("is_lab", None)
    elif changes["is_lab"] != s.is_lab and (problem := _lab_problem(db, s, changes["is_lab"])):
        raise api_error(422, "lab_mismatch", problem)
    for k, v in changes.items():
        setattr(s, k, v)
    if s.valid_from and s.valid_until and s.valid_until <= s.valid_from:
        raise api_error(
            422, "invalid_window", "The end of the authorization period must be after its start."
        )
    db.flush()
    db.refresh(s)
    record(
        db,
        "scope.draft_updated",
        entity_type="scope",
        entity_id=s.id,
        data={"fields": sorted(changes)},
        **ctx.audit_kwargs(),
    )
    return _out(db, s)


def _lab_problem(db: Session, s: Scope, is_lab: bool) -> str | None:
    """First target that doesn't fit the scope type (lab or not), if any."""
    networks = get_settings().lab_networks
    for kind, value in db.execute(
        select(ScopeTarget.kind, ScopeTarget.value).where(ScopeTarget.scope_id == s.id)
    ).all():
        if problem := entry_problem(kind, value, is_lab, networks):
            return problem
    return None


def _add_entry(
    db: Session, ctx: WorkspaceContext, scope_id: uuid.UUID, body: EntryIn, exclusion: bool
) -> ScopeOut:
    s = _draft(db, ctx, scope_id)
    model = ScopeExclusion if exclusion else ScopeTarget
    count = db.scalar(select(func.count()).select_from(model).where(model.scope_id == s.id)) or 0
    if count >= MAX_ENTRIES:
        raise api_error(409, "too_many_entries", f"A scope can hold {MAX_ENTRIES} entries.")
    try:
        value = normalize_entry(body.kind, body.value)
    except NormalizationError as exc:
        raise api_error(422, "invalid_value", str(exc)) from exc
    if not exclusion and (
        problem := entry_problem(body.kind, value, s.is_lab, get_settings().lab_networks)
    ):
        raise api_error(422, "lab_mismatch", problem)
    if exclusion:
        db.add(
            ScopeExclusion(
                workspace_id=ctx.workspace_id,
                scope_id=s.id,
                kind=body.kind,
                value=value,
                reason=body.note,
            )
        )
    else:
        db.add(
            ScopeTarget(
                workspace_id=ctx.workspace_id,
                scope_id=s.id,
                kind=body.kind,
                value=value,
                note=body.note,
                allowed_ports=sorted(set(body.allowed_ports)),
                max_rps=body.max_rps,
                daily_budget=body.daily_budget,
            )
        )
    try:
        db.flush()
    except IntegrityError as exc:
        raise api_error(409, "duplicate", "That entry is already in this scope.") from exc
    record(
        db,
        "scope.exclusion_added" if exclusion else "scope.target_added",
        entity_type="scope",
        entity_id=s.id,
        data={"kind": body.kind.value, "value": value},
        **ctx.audit_kwargs(),
    )
    return _out(db, s)


def _remove_entry(
    db: Session, ctx: WorkspaceContext, scope_id: uuid.UUID, entry_id: uuid.UUID, exclusion: bool
) -> ScopeOut:
    s = _draft(db, ctx, scope_id)
    entry: ScopeTarget | ScopeExclusion | None
    if exclusion:
        entry = db.scalar(
            select(ScopeExclusion).where(
                ScopeExclusion.id == entry_id, ScopeExclusion.scope_id == s.id
            )
        )
    else:
        entry = db.scalar(
            select(ScopeTarget).where(ScopeTarget.id == entry_id, ScopeTarget.scope_id == s.id)
        )
    if entry is None:
        raise not_found("Entry not found.")
    record(
        db,
        "scope.exclusion_removed" if exclusion else "scope.target_removed",
        entity_type="scope",
        entity_id=s.id,
        data={"kind": entry.kind.value, "value": entry.value},
        **ctx.audit_kwargs(),
    )
    db.delete(entry)
    db.flush()
    return _out(db, s)


@router.post("/scopes/{scope_id}/targets", response_model=ScopeOut, status_code=201)
def add_target(
    scope_id: uuid.UUID,
    body: EntryIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ScopeOut:
    return _add_entry(db, ctx, scope_id, body, exclusion=False)


@router.delete("/scopes/{scope_id}/targets/{entry_id}", response_model=ScopeOut)
def remove_target(
    scope_id: uuid.UUID,
    entry_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ScopeOut:
    return _remove_entry(db, ctx, scope_id, entry_id, exclusion=False)


@router.post("/scopes/{scope_id}/exclusions", response_model=ScopeOut, status_code=201)
def add_exclusion(
    scope_id: uuid.UUID,
    body: EntryIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ScopeOut:
    return _add_entry(db, ctx, scope_id, body, exclusion=True)


@router.delete("/scopes/{scope_id}/exclusions/{entry_id}", response_model=ScopeOut)
def remove_exclusion(
    scope_id: uuid.UUID,
    entry_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ScopeOut:
    return _remove_entry(db, ctx, scope_id, entry_id, exclusion=True)


@router.delete("/scopes/{scope_id}", response_model=OkOut)
def discard_draft(
    scope_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE)
) -> OkOut:
    s = _draft(db, ctx, scope_id)
    record(
        db,
        "scope.draft_discarded",
        entity_type="scope",
        entity_id=s.id,
        data={"version": s.version},
        **ctx.audit_kwargs(),
    )
    db.delete(s)
    return OkOut()


@router.post("/scopes/{scope_id}/authorize", response_model=ScopeOut)
def authorize(
    scope_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.SCOPE_AUTHORIZE, fresh_mfa=True),
) -> ScopeOut:
    s = _draft(db, ctx, scope_id)
    if not s.authorization_reference.strip():
        raise api_error(
            422,
            "reference_required",
            "Add the authorization reference (e.g. the signed engagement letter).",
        )
    if not db.scalar(
        select(func.count()).select_from(ScopeTarget).where(ScopeTarget.scope_id == s.id)
    ):
        raise api_error(422, "no_targets", "Add at least one target before authorizing.")
    if problem := _lab_problem(db, s, s.is_lab):  # re-checked with the current lab networks
        raise api_error(422, "lab_mismatch", problem)
    now = utcnow()
    if s.valid_until is not None and s.valid_until <= now:
        raise api_error(422, "window_ended", "The authorization period has already ended.")
    previous = active_scope(db, s.project_id)
    if previous is not None:
        previous.status = ScopeStatus.SUPERSEDED
        previous.superseded_at = now
        db.flush()
    s.status = ScopeStatus.ACTIVE
    s.authorized_by_user_id = ctx.user_id
    s.authorized_at = now
    db.flush()
    db.refresh(s)
    record(
        db,
        "scope.authorized",
        entity_type="scope",
        entity_id=s.id,
        data={
            "project_id": str(s.project_id),
            "version": s.version,
            "reference": s.authorization_reference,
            "superseded_version": previous.version if previous else None,
            "is_lab": s.is_lab,
        },
        **ctx.audit_kwargs(),
    )
    return _out(db, s)


@router.post("/projects/{project_id}/scope-check", response_model=CheckOut)
def check(
    project_id: uuid.UUID,
    body: CheckIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> CheckOut:
    """Preview whether a value is inside the project's active scope. Changes nothing."""
    _project(db, ctx, project_id)
    current = active_scope(db, project_id)
    d = evaluate(snapshot(db, current) if current else None, body.value, utcnow())
    return CheckOut(
        allowed=d.allowed,
        reason=d.reason,
        normalized=d.target,
        scope_version=current.version if current else None,
    )
