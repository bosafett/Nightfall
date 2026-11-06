"""Role → permission matrix (review §5). The single source of truth for RBAC."""

from __future__ import annotations

import enum

from nightfall.core.db.models import Role


class Permission(enum.StrEnum):
    READ = "read"
    REGISTRY_WRITE = "registry.write"  # orgs, projects, assets
    MEMBERS_MANAGE = "members.manage"  # workspace settings, members, invites
    SCOPE_AUTHORIZE = "scope.authorize"  # Phase 3
    OPERATIONS_PROPOSE = "operations.propose"  # Phase 3
    OPERATIONS_APPROVE = "operations.approve"  # Phase 3/6
    FINDINGS_EDIT = "findings.edit"  # Phase 4
    FINDINGS_VALIDATE = "findings.validate"  # Phase 4
    PLAYBOOKS_RUN = "playbooks.run"  # BLACK OPS (Addendum 4): BLACKSITE is owner-only
    PLAYBOOKS_MANAGE = "playbooks.manage"  # enable/disable playbooks in the workspace


P = Permission
_ANALYST = {P.READ, P.REGISTRY_WRITE, P.OPERATIONS_PROPOSE, P.FINDINGS_EDIT, P.FINDINGS_VALIDATE}
_OPERATOR = _ANALYST | {P.OPERATIONS_APPROVE}
_ADMIN = _OPERATOR | {P.MEMBERS_MANAGE, P.SCOPE_AUTHORIZE}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(_ADMIN | {P.PLAYBOOKS_RUN, P.PLAYBOOKS_MANAGE}),
    Role.ADMIN: frozenset(_ADMIN),
    Role.OPERATOR: frozenset(_OPERATOR),
    Role.ANALYST: frozenset(_ANALYST),
    Role.VIEWER: frozenset({P.READ}),
}

# Roles that can approve operations or change scope must use MFA.
MFA_REQUIRED_ROLES = frozenset({Role.OWNER, Role.ADMIN, Role.OPERATOR})

_RANK = {Role.OWNER: 4, Role.ADMIN: 3, Role.OPERATOR: 2, Role.ANALYST: 1, Role.VIEWER: 0}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]


def can_assign(actor: Role, role: Role) -> bool:
    """Owners may grant any role; everyone else only roles below their own."""
    return actor is Role.OWNER or _RANK[role] < _RANK[actor]


def can_manage(actor: Role, target: Role) -> bool:
    """Owners may manage anyone (last-owner rules apply separately); others only lower roles."""
    return actor is Role.OWNER or _RANK[target] < _RANK[actor]
