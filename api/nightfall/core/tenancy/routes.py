"""Workspace settings, members, invites and admin-issued password resets."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AuthToken, Role, TokenPurpose, User, Workspace, WorkspaceMember
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.identity.security import new_token
from nightfall.core.schemas import Email, Model, Name, OkOut
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission, can_assign, can_manage

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["workspace"])

INVITE_TTL = timedelta(days=7)
RESET_TTL = timedelta(minutes=30)


class WorkspaceOut(Model):
    id: uuid.UUID
    name: str
    slug: str
    role: Role


class WorkspacePatch(Model):
    name: Name


class MemberOut(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    role: Role
    mfa_enabled: bool
    joined_at: datetime


class MemberPatch(Model):
    role: Role


class InviteIn(Model):
    email: Email
    role: Role


class InviteOut(Model):
    id: uuid.UUID
    email: str
    role: Role
    expires_at: datetime
    created_at: datetime


class LinkOut(Model):
    url: str
    expires_at: datetime


class InviteCreatedOut(Model):
    invite: InviteOut
    link: LinkOut


def _owner_count(db: Session, workspace_id: uuid.UUID) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(WorkspaceMember)
            .where(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == Role.OWNER)
        )
        or 0
    )


def _member(db: Session, ctx: WorkspaceContext, member_id: uuid.UUID) -> WorkspaceMember:
    m = db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.id == member_id, WorkspaceMember.workspace_id == ctx.workspace_id
        )
    )
    if m is None:
        raise not_found("Member not found.")
    return m


def _link(path: str, raw: str, expires_at: datetime) -> LinkOut:
    # Token in the URL fragment: browsers don't send it to servers or in Referer.
    return LinkOut(url=f"{get_settings().public_origin}{path}#token={raw}", expires_at=expires_at)


@router.get("", response_model=WorkspaceOut)
def get_workspace(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> WorkspaceOut:
    ws = db.get(Workspace, ctx.workspace_id)
    if ws is None:
        raise not_found()
    return WorkspaceOut(id=ws.id, name=ws.name, slug=ws.slug, role=ctx.role)


@router.patch("", response_model=WorkspaceOut)
def update_workspace(
    body: WorkspacePatch, db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> WorkspaceOut:
    ws = db.get(Workspace, ctx.workspace_id)
    if ws is None:
        raise not_found()
    before = ws.name
    ws.name = body.name
    record(
        db,
        "workspace.updated",
        entity_type="workspace",
        entity_id=ws.id,
        data={"name": {"from": before, "to": body.name}},
        **ctx.audit_kwargs(),
    )
    return WorkspaceOut(id=ws.id, name=ws.name, slug=ws.slug, role=ctx.role)


@router.get("/members", response_model=list[MemberOut])
def list_members(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> list[MemberOut]:
    rows = db.execute(
        select(WorkspaceMember, User)
        .join(User, User.id == WorkspaceMember.user_id)
        .where(WorkspaceMember.workspace_id == ctx.workspace_id)
        .order_by(User.display_name)
    ).all()
    return [
        MemberOut(
            id=m.id,
            user_id=u.id,
            email=u.email,
            display_name=u.display_name,
            role=m.role,
            mfa_enabled=u.mfa_enabled,
            joined_at=m.created_at,
        )
        for m, u in rows
    ]


@router.patch("/members/{member_id}", response_model=OkOut)
def update_member(
    member_id: uuid.UUID,
    body: MemberPatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE),
) -> OkOut:
    m = _member(db, ctx, member_id)
    if not can_manage(ctx.role, m.role) or not can_assign(ctx.role, body.role):
        raise api_error(403, "forbidden", "You can't change this member to that role.")
    if (
        m.role is Role.OWNER
        and body.role is not Role.OWNER
        and _owner_count(db, ctx.workspace_id) <= 1
    ):
        raise api_error(409, "last_owner", "A workspace needs at least one owner.")
    before = m.role
    m.role = body.role
    record(
        db,
        "member.role_changed",
        entity_type="workspace_member",
        entity_id=m.id,
        data={"user_id": str(m.user_id), "from": before.value, "to": body.role.value},
        **ctx.audit_kwargs(),
    )
    return OkOut()


@router.delete("/members/{member_id}", response_model=OkOut)
def remove_member(
    member_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> OkOut:
    m = _member(db, ctx, member_id)
    if not can_manage(ctx.role, m.role):
        raise api_error(403, "forbidden", "You can't remove this member.")
    if m.role is Role.OWNER and _owner_count(db, ctx.workspace_id) <= 1:
        raise api_error(409, "last_owner", "A workspace needs at least one owner.")
    record(
        db,
        "member.removed",
        entity_type="workspace_member",
        entity_id=m.id,
        data={"user_id": str(m.user_id), "role": m.role.value},
        **ctx.audit_kwargs(),
    )
    db.delete(m)
    return OkOut()


@router.post("/members/{member_id}/password-reset", response_model=LinkOut)
def issue_password_reset(
    member_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> LinkOut:
    m = _member(db, ctx, member_id)
    if m.user_id == ctx.user_id or not can_manage(ctx.role, m.role):
        raise api_error(403, "forbidden", "You can't issue a reset link for this member.")
    # A reset grants access to every workspace the user belongs to, so it may only be
    # issued from here when this is their only workspace. Otherwise: admin CLI.
    count = db.scalar(text("SELECT nf_user_workspace_count(:u)"), {"u": m.user_id})
    if count != 1:
        raise api_error(
            409,
            "multiple_workspaces",
            "This person belongs to other workspaces. Reset from the admin CLI.",
        )
    now = utcnow()
    db.execute(
        update(AuthToken)
        .where(
            AuthToken.purpose == TokenPurpose.PASSWORD_RESET,
            AuthToken.user_id == m.user_id,
            AuthToken.used_at.is_(None),
            AuthToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    raw, digest = new_token()
    expires = now + RESET_TTL
    db.add(
        AuthToken(
            purpose=TokenPurpose.PASSWORD_RESET,
            token_sha256=digest,
            user_id=m.user_id,
            created_by_user_id=ctx.user_id,
            expires_at=expires,
        )
    )
    record(
        db,
        "member.password_reset_issued",
        entity_type="workspace_member",
        entity_id=m.id,
        data={"user_id": str(m.user_id)},
        **ctx.audit_kwargs(),
    )
    return _link("/reset-password", raw, expires)


@router.get("/invites", response_model=list[InviteOut])
def list_invites(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> list[InviteOut]:
    rows = db.scalars(
        select(AuthToken)
        .where(
            AuthToken.workspace_id == ctx.workspace_id,
            AuthToken.purpose == TokenPurpose.INVITE,
            AuthToken.used_at.is_(None),
            AuthToken.revoked_at.is_(None),
            AuthToken.expires_at > utcnow(),
        )
        .order_by(AuthToken.created_at.desc())
    ).all()
    return [
        InviteOut(
            id=t.id,
            email=t.email or "",
            role=t.role or Role.VIEWER,
            expires_at=t.expires_at,
            created_at=t.created_at,
        )
        for t in rows
    ]


@router.post("/invites", response_model=InviteCreatedOut, status_code=201)
def create_invite(
    body: InviteIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> InviteCreatedOut:
    if not can_assign(ctx.role, body.role):
        raise api_error(403, "forbidden", "You can't invite someone with that role.")
    existing_member = db.scalar(
        select(WorkspaceMember.id)
        .join(User, User.id == WorkspaceMember.user_id)
        .where(WorkspaceMember.workspace_id == ctx.workspace_id, User.email == body.email)
    )
    if existing_member is not None:
        raise api_error(409, "already_member", "That person is already in this workspace.")
    now = utcnow()
    db.execute(
        update(AuthToken)
        .where(
            AuthToken.workspace_id == ctx.workspace_id,
            AuthToken.purpose == TokenPurpose.INVITE,
            AuthToken.email == body.email,
            AuthToken.used_at.is_(None),
            AuthToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    raw, digest = new_token()
    t = AuthToken(
        purpose=TokenPurpose.INVITE,
        token_sha256=digest,
        workspace_id=ctx.workspace_id,
        email=body.email,
        role=body.role,
        created_by_user_id=ctx.user_id,
        expires_at=now + INVITE_TTL,
    )
    db.add(t)
    db.flush()
    record(
        db,
        "invite.created",
        entity_type="invite",
        entity_id=t.id,
        data={"email": body.email, "role": body.role.value},
        **ctx.audit_kwargs(),
    )
    return InviteCreatedOut(
        invite=InviteOut(
            id=t.id,
            email=body.email,
            role=body.role,
            expires_at=t.expires_at,
            created_at=t.created_at,
        ),
        link=_link("/accept-invite", raw, t.expires_at),
    )


@router.delete("/invites/{invite_id}", response_model=OkOut)
def revoke_invite(
    invite_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> OkOut:
    t = db.scalar(
        select(AuthToken).where(
            AuthToken.id == invite_id,
            AuthToken.workspace_id == ctx.workspace_id,
            AuthToken.purpose == TokenPurpose.INVITE,
        )
    )
    if t is None or t.used_at is not None or t.revoked_at is not None:
        raise not_found("Invite not found.")
    if t.role is not None and not can_assign(ctx.role, t.role):
        raise api_error(403, "forbidden", "You can't revoke this invite.")
    t.revoked_at = utcnow()
    record(
        db,
        "invite.revoked",
        entity_type="invite",
        entity_id=t.id,
        data={"email": t.email},
        **ctx.audit_kwargs(),
    )
    return OkOut()
