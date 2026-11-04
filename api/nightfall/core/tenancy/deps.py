"""Workspace authorization dependency. Every workspace route uses require(permission)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select

from nightfall.core.audit.writer import AuditActor, record_detached
from nightfall.core.db.models import Role, WorkspaceMember
from nightfall.core.db.session import DB, set_workspace_context
from nightfall.core.errors import api_error, not_found
from nightfall.core.identity.deps import Auth, AuthContext
from nightfall.core.tenancy.permissions import MFA_REQUIRED_ROLES, Permission, has_permission


@dataclass
class WorkspaceContext:
    workspace_id: uuid.UUID
    auth: AuthContext
    member: WorkspaceMember

    @property
    def role(self) -> Role:
        return self.member.role

    @property
    def user_id(self) -> uuid.UUID:
        return self.auth.user.id

    def audit_kwargs(self) -> AuditActor:
        return {
            "actor_id": self.auth.user.id,
            "workspace_id": self.workspace_id,
            "ip": self.auth.ip,
            "user_agent": self.auth.user_agent,
        }


def require(permission: Permission) -> Callable[..., WorkspaceContext]:
    def dependency(workspace_id: uuid.UUID, auth: Auth, db: DB) -> WorkspaceContext:
        member = db.scalar(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == auth.user.id,
            )
        )
        if member is None:
            # Don't reveal whether the workspace exists. Logged without workspace_id
            # because the caller has no right to write into that tenant's log.
            record_detached(
                "authz.denied",
                actor_id=auth.user.id,
                data={"reason": "not_member", "workspace_id": str(workspace_id)},
                ip=auth.ip,
                user_agent=auth.user_agent,
            )
            raise not_found()
        set_workspace_context(db, workspace_id)
        ctx = WorkspaceContext(workspace_id=workspace_id, auth=auth, member=member)

        if member.role in MFA_REQUIRED_ROLES and not auth.mfa_satisfied:
            record_detached("authz.denied", data={"reason": "mfa_required"}, **ctx.audit_kwargs())
            raise api_error(403, "mfa_required", "Your role requires two-factor authentication.")
        if not has_permission(member.role, permission):
            record_detached(
                "authz.denied",
                data={"reason": "permission", "permission": permission.value},
                **ctx.audit_kwargs(),
            )
            raise api_error(403, "forbidden", "Your role can't do that.")
        return ctx

    dependency._nf_authz = True  # type: ignore[attr-defined]
    dependency.__name__ = f"require_{permission.value.replace('.', '_')}"
    return dependency


def ws_permission(permission: Permission) -> WorkspaceContext:
    """Use as a parameter default: `ctx: WorkspaceContext = ws_permission(Permission.READ)`."""
    from fastapi import Depends

    return Depends(require(permission), scope="function")  # type: ignore[no-any-return]
