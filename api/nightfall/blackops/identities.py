"""Profile B designated test identities (design G2): register, list, retire.

* Owner only, with two-factor in the last 15 minutes, and with the owner's attestation
  that the account exists for testing and holds no real person's data.
* The credential is sealed to the self-hosted worker's key on arrival and never returned:
  the API shows only that one is set. Audit events and every response carry
  `<test-identity:label>` in its place.
* An identity belongs to one HTTPS origin and can't be used against any other (checked in
  the preflight, at launch by the database, and by the worker).
* AI agents have no route here and their prompts never include identities.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import StringConstraints
from sqlalchemy import select, text

from nightfall.blackops import profile_b
from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import TestIdentity, User
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.scope import normalize
from nightfall.scope.normalize import NormalizationError

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["blackops"])
Text = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]


class IdentityIn(Model):
    origin: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)]
    label: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
    role_description: Text = ""
    login_method: Literal["form", "basic"]
    login_path: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = "/"
    username: Annotated[str, StringConstraints(min_length=1, max_length=300)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    attestation: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000)
    ]
    attest: bool  # must be true: "this account exists for testing and holds no real data"


class IdentityOut(Model):
    id: uuid.UUID
    origin: str
    label: str
    role_description: str
    login_method: str
    login_path: str
    credential: Literal["set"]
    attestation: str
    attested_by: str
    attested_at: datetime
    lockout_test_allowed: bool
    retired_at: datetime | None


class IdentitiesOut(Model):
    identities: list[IdentityOut]
    can_register: bool
    unavailable_reason: str | None  # why Profile B can't run here (registration may still work)


def _origin(raw: str) -> str:
    m = re.fullmatch(r"https://([^/:]+)(?::(\d{1,5}))?/?", raw.strip(), flags=re.IGNORECASE)
    if not m:
        raise api_error(422, "invalid_origin", "Use an HTTPS origin like https://app.example.com.")
    try:
        host = normalize.hostname(m.group(1))
    except NormalizationError as exc:
        raise api_error(422, "invalid_origin", str(exc)) from exc
    port = m.group(2)
    if port and not (0 < int(port) < 65536):
        raise api_error(422, "invalid_origin", "That port isn't valid.")
    return f"https://{host}" + (f":{int(port)}" if port and int(port) != 443 else "")


def _out(db: DB, rows: list[TestIdentity]) -> list[IdentityOut]:
    ids = {r.attested_by_user_id for r in rows}
    names = (
        {u: n for u, n in db.execute(select(User.id, User.display_name).where(User.id.in_(ids)))}
        if ids
        else {}
    )
    return [
        IdentityOut(
            id=r.id,
            origin=r.origin,
            label=r.label,
            role_description=r.role_description,
            login_method=r.login_method,
            login_path=r.login_path,
            credential="set",
            attestation=r.attestation,
            attested_by=names.get(r.attested_by_user_id, "Unknown"),
            attested_at=r.attested_at,
            lockout_test_allowed=r.lockout_test_allowed,
            retired_at=r.retired_at,
        )
        for r in rows
    ]


@router.get("/test-identities", response_model=IdentitiesOut)
def list_identities(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> IdentitiesOut:
    rows = db.scalars(
        select(TestIdentity)
        .where(TestIdentity.workspace_id == ctx.workspace_id)
        .order_by(TestIdentity.retired_at.is_not(None), TestIdentity.origin, TestIdentity.label)
    ).all()
    s = get_settings()
    return IdentitiesOut(
        identities=_out(db, list(rows)),
        can_register=bool(s.profile_b_public_key),
        unavailable_reason=profile_b.unavailable_reason(s),
    )


@router.post("/test-identities", response_model=IdentityOut, status_code=201)
def register_identity(
    body: IdentityIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.IDENTITIES_MANAGE, fresh_mfa=True),
) -> IdentityOut:
    s = get_settings()
    if not s.profile_b_public_key:
        raise api_error(
            409,
            "no_worker_key",
            "No worker key is configured (NIGHTFALL_PROFILE_B_PUBLIC_KEY), so a credential "
            "can't be stored safely.",
        )
    if not body.attest:
        raise api_error(422, "attestation_required", "Confirm the account exists for testing only.")
    origin = _origin(body.origin)
    if not body.login_path.startswith("/") or any(c.isspace() for c in body.login_path):
        raise api_error(422, "invalid_path", "The login path starts with / and has no spaces.")
    taken = db.scalar(
        select(TestIdentity.id).where(
            TestIdentity.workspace_id == ctx.workspace_id,
            TestIdentity.origin == origin,
            TestIdentity.label == body.label,
            TestIdentity.retired_at.is_(None),
        )
    )
    if taken is not None:
        raise api_error(409, "identity_exists", "An active identity has that label and origin.")
    new_id = uuid.uuid4()
    sealed = profile_b.seal(
        s.profile_b_public_key,
        {"username": body.username, "password": body.password},
        new_id,
        ctx.workspace_id,
    )
    db.execute(
        text(
            "INSERT INTO test_identities (id, workspace_id, origin, label, role_description, "
            "login_method, login_path, secret_sealed, attestation, attested_by_user_id) "
            "VALUES (:id, :ws, :origin, :label, :role, :method, :path, :sealed, :att, :by)"
        ),
        {
            "id": new_id,
            "ws": ctx.workspace_id,
            "origin": origin,
            "label": body.label,
            "role": body.role_description,
            "method": body.login_method,
            "path": body.login_path,
            "sealed": sealed,
            "att": body.attestation,
            "by": ctx.user_id,
        },
    )
    ident = db.get(TestIdentity, new_id)
    if ident is None:
        raise not_found("Identity not found.")
    record(
        db,
        "test_identity.registered",
        entity_type="test_identity",
        entity_id=new_id,
        data={**profile_b.summary(ident), "attestation": body.attestation},
        **ctx.audit_kwargs(),
    )
    return _out(db, [ident])[0]


@router.post("/test-identities/{identity_id}/retire", response_model=IdentityOut)
def retire_identity(
    identity_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.IDENTITIES_MANAGE, fresh_mfa=True),
) -> IdentityOut:
    ident = db.get(TestIdentity, identity_id)
    if ident is None or ident.workspace_id != ctx.workspace_id:
        raise not_found("Identity not found.")
    if ident.retired_at is not None:
        raise api_error(409, "identity_retired", "That identity is already retired.")
    ident.retired_at, ident.retired_by_user_id = utcnow(), ctx.user_id
    db.flush()
    record(
        db,
        "test_identity.retired",
        entity_type="test_identity",
        entity_id=ident.id,
        data=profile_b.summary(ident),
        **ctx.audit_kwargs(),
    )
    return _out(db, [ident])[0]
