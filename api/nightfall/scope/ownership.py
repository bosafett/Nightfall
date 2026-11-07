"""Proof of control over a target (BLACK OPS Profile B design, gate G1; review F3).

A written authorization reference shows intent, not control. Here the owner proves control
of a hostname by publishing a random token where only someone who controls it could:

  * dns:  a TXT record at _janus-verify.<name>. Covers <name> and every name under it.
  * file: https://<name>/.well-known/janus-verify.txt. Covers that host only.

IP-address targets are never eligible. The token is shown once and stored as SHA-256 only.

A check is made against one scope version and recorded insert-only with what was observed
(DNS answers or the HTTP response) and that observation's SHA-256, so a report can show the
proof. A scope target counts as "control proven" when an active claim covering it passed a
check for that scope version within FRESH. Later Profile B gates (approval, worker start)
will call `proof_for` again; nothing here enables Profile B.

The checks themselves are small and read-only: one DNS TXT lookup, or one HTTPS GET of a
fixed path on a host that's in the active scope, through the same address-pinning client
the collectors use (no private addresses, no excluded networks, no redirects followed).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Protocol

import httpx
from fastapi import APIRouter
from pydantic import StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    OwnershipCheck,
    OwnershipClaim,
    OwnershipMethod,
    Scope,
    ScopeEntryKind,
    ScopeExclusion,
    ScopeStatus,
    ScopeTarget,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.scope import normalize
from nightfall.scope.engine import evaluate
from nightfall.scope.normalize import NormalizationError
from nightfall.scope.repository import snapshot

FRESH = timedelta(hours=24)
TOKEN_PREFIX = "janus-verify="  # noqa: S105 - a label, not a secret
DNS_LABEL = "_janus-verify"
FILE_PATH = "/.well-known/janus-verify.txt"
MAX_ANSWERS = 20
MAX_TEXT = 300

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.strip().encode()).digest()


def record_name(claim: OwnershipClaim) -> str:
    return f"{DNS_LABEL}.{claim.name}"


def covers(claim: OwnershipClaim, kind: ScopeEntryKind, value: str) -> bool:
    if kind not in (ScopeEntryKind.HOST, ScopeEntryKind.DOMAIN_TREE):
        return False  # IP and CIDR targets are never eligible
    if claim.method is OwnershipMethod.FILE:
        return kind is ScopeEntryKind.HOST and value == claim.name
    return value == claim.name or value.endswith("." + claim.name)


# --- Probes (replaceable in tests) -------------------------------------------------------


@dataclass
class Observed:
    candidates: list[str]  # strings that might be the token
    observation: dict[str, Any]
    problem: str | None = None  # set when nothing usable came back


class Probes(Protocol):
    def txt(self, name: str) -> Observed: ...
    def file(self, host: str, excluded: Sequence[Network]) -> Observed: ...


class LiveProbes:
    def txt(self, name: str) -> Observed:
        import dns.exception
        import dns.resolver

        from nightfall.recon.collectors import DNS_LIFETIME

        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_LIFETIME
        obs: dict[str, Any] = {"method": "dns", "query": name, "type": "TXT"}
        try:
            answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            obs["answers"] = []
            return Observed([], obs, f"{name} doesn't exist in DNS.")
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            obs["error"] = type(exc).__name__
            return Observed([], obs, f"The DNS lookup for {name} failed ({type(exc).__name__}).")
        texts = [
            b"".join(r.strings).decode("utf-8", "replace")[:MAX_TEXT]
            for r in answer
        ][:MAX_ANSWERS]
        obs["answers"] = texts
        return Observed(texts, obs, None if texts else f"{name} has no TXT record.")

    def file(self, host: str, excluded: Sequence[Network]) -> Observed:
        from nightfall.recon.safe_http import Refused, SafeHttp

        obs: dict[str, Any] = {"method": "file", "url": f"https://{host}{FILE_PATH}"}
        try:
            ex = SafeHttp(excluded_networks=list(excluded)).request(
                host, "https", True, path=FILE_PATH
            )
        except Refused as exc:
            obs["refused"] = str(exc)
            return Observed([], obs, str(exc))
        except (httpx.HTTPError, OSError) as exc:
            obs["error"] = type(exc).__name__
            return Observed([], obs, f"https://{host}{FILE_PATH} couldn't be fetched.")
        body = ex.body[:4096].decode("utf-8", "replace")
        obs |= {
            "status": ex.status,
            "connected_ip": ex.connected_ip,
            "location": ex.location,
            "body": body[:MAX_TEXT],
            "elapsed_ms": ex.elapsed_ms,
        }
        if ex.status != 200:
            return Observed([], obs, f"The file returned HTTP {ex.status}, not 200.")
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()][:MAX_ANSWERS]
        return Observed(lines, obs, None if lines else "The file is empty.")


PROBES: Probes | None = None  # tests set this


def _probes() -> Probes:
    if PROBES is not None:
        return PROBES
    if get_settings().collector_mode != "live":
        raise api_error(
            409,
            "fixture_mode",
            "Proof-of-control checks contact real DNS and web servers, so they only run "
            "with live collection.",
        )
    return LiveProbes()


# --- Queries ------------------------------------------------------------------------------


def latest_ok(
    db: Session, claim_id: uuid.UUID, scope_id: uuid.UUID, now: datetime
) -> OwnershipCheck | None:
    """The most recent check, if it passed within FRESH."""
    last = db.scalar(
        select(OwnershipCheck)
        .where(OwnershipCheck.claim_id == claim_id, OwnershipCheck.scope_id == scope_id)
        .order_by(OwnershipCheck.checked_at.desc())
        .limit(1)
    )
    if last is None or not last.ok or last.checked_at < now - FRESH:
        return None
    return last


@dataclass
class Proof:
    claim: OwnershipClaim
    check: OwnershipCheck


def proof_for(
    db: Session, scope: Scope, kind: ScopeEntryKind, value: str, now: datetime | None = None
) -> Proof | None:
    """Fresh proof that the workspace controls this target of this scope version, or None.
    A failed latest check means not proven, even if an older one passed."""
    now = now or utcnow()
    claims = db.scalars(
        select(OwnershipClaim)
        .where(
            OwnershipClaim.workspace_id == scope.workspace_id, OwnershipClaim.retired_at.is_(None)
        )
        .order_by(OwnershipClaim.method)  # dns first: it covers the most
    ).all()
    for c in claims:
        if covers(c, kind, value) and (chk := latest_ok(db, c.id, scope.id, now)):
            return Proof(c, chk)
    return None


# --- Routes -------------------------------------------------------------------------------

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["scope"])
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]


class ClaimIn(Model):
    name: Name
    method: OwnershipMethod


class CheckSummary(Model):
    id: uuid.UUID
    scope_id: uuid.UUID
    ok: bool
    detail: str
    checked_at: datetime
    checked_by: str
    observation: dict[str, Any]
    observation_sha256: str


class ClaimOut(Model):
    id: uuid.UUID
    name: str
    method: OwnershipMethod
    where: str  # the DNS name or URL the token goes in
    created_by: str
    created_at: datetime
    retired_at: datetime | None
    last_check: CheckSummary | None


class ClaimCreated(ClaimOut):
    token: str  # shown once; only its SHA-256 is stored


def _names(db: Session, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).all()
    return {r[0]: r[1] for r in rows}


def _check_out(c: OwnershipCheck, names: dict[uuid.UUID, str]) -> CheckSummary:
    return CheckSummary(
        id=c.id,
        scope_id=c.scope_id,
        ok=c.ok,
        detail=c.detail,
        checked_at=c.checked_at,
        checked_by=names.get(c.checked_by_user_id, "Unknown"),
        observation=c.observation,
        observation_sha256=c.observation_sha256.hex(),
    )


def _where(c: OwnershipClaim) -> str:
    if c.method is OwnershipMethod.DNS:
        return f"TXT record {record_name(c)}"
    return f"https://{c.name}{FILE_PATH}"


def _claim_out(db: Session, c: OwnershipClaim) -> ClaimOut:
    last = db.scalar(
        select(OwnershipCheck)
        .where(OwnershipCheck.claim_id == c.id)
        .order_by(OwnershipCheck.checked_at.desc())
        .limit(1)
    )
    names = _names(
        db, {c.created_by_user_id} | ({last.checked_by_user_id} if last is not None else set())
    )
    return ClaimOut(
        id=c.id,
        name=c.name,
        method=c.method,
        where=_where(c),
        created_by=names.get(c.created_by_user_id, "Unknown"),
        created_at=c.created_at,
        retired_at=c.retired_at,
        last_check=_check_out(last, names) if last is not None else None,
    )


def _claim(db: Session, ctx: WorkspaceContext, claim_id: uuid.UUID) -> OwnershipClaim:
    c = db.get(OwnershipClaim, claim_id)
    if c is None or c.workspace_id != ctx.workspace_id:
        raise not_found("Ownership claim not found.")
    return c


@router.get("/ownership/claims", response_model=list[ClaimOut])
def list_claims(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> list[ClaimOut]:
    claims = db.scalars(
        select(OwnershipClaim)
        .where(OwnershipClaim.workspace_id == ctx.workspace_id)
        .order_by(OwnershipClaim.retired_at.is_not(None), OwnershipClaim.name)
    ).all()
    return [_claim_out(db, c) for c in claims]


@router.post("/ownership/claims", response_model=ClaimCreated, status_code=201)
def create_claim(
    body: ClaimIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OWNERSHIP_MANAGE, fresh_mfa=True),
) -> ClaimCreated:
    """Owner only. Returns the token once; publish it, then run a check."""
    try:
        name = normalize.hostname(body.name)
    except NormalizationError as exc:
        raise api_error(422, "invalid_name", str(exc)) from exc
    taken = db.scalar(
        select(OwnershipClaim.id).where(
            OwnershipClaim.workspace_id == ctx.workspace_id,
            OwnershipClaim.name == name,
            OwnershipClaim.method == body.method,
            OwnershipClaim.retired_at.is_(None),
        )
    )
    if taken is not None:
        raise api_error(
            409,
            "claim_exists",
            "There's already an active claim for that name and method. Retire it to issue "
            "a new token.",
        )
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    c = OwnershipClaim(
        workspace_id=ctx.workspace_id,
        name=name,
        method=body.method,
        token_sha256=token_hash(token),
        created_by_user_id=ctx.user_id,
    )
    db.add(c)
    db.flush()
    db.refresh(c)
    record(
        db,
        "ownership.claim_created",
        entity_type="ownership_claim",
        entity_id=c.id,
        data={"name": name, "method": body.method.value},
        **ctx.audit_kwargs(),
    )
    return ClaimCreated(**_claim_out(db, c).model_dump(), token=token)


@router.post("/ownership/claims/{claim_id}/retire", response_model=ClaimOut)
def retire_claim(
    claim_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OWNERSHIP_MANAGE, fresh_mfa=True),
) -> ClaimOut:
    c = _claim(db, ctx, claim_id)
    if c.retired_at is not None:
        raise api_error(409, "claim_retired", "That claim is already retired.")
    c.retired_at, c.retired_by_user_id = utcnow(), ctx.user_id
    db.flush()
    record(
        db,
        "ownership.claim_retired",
        entity_type="ownership_claim",
        entity_id=c.id,
        data={"name": c.name, "method": c.method.value},
        **ctx.audit_kwargs(),
    )
    return _claim_out(db, c)


@router.post("/scopes/{scope_id}/ownership/{claim_id}/check", response_model=CheckSummary)
def check_claim(
    scope_id: uuid.UUID,
    claim_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.SCOPE_AUTHORIZE),
) -> CheckSummary:
    """Look for the token now and record the result against this scope version."""
    c = _claim(db, ctx, claim_id)
    scope = db.get(Scope, scope_id)
    if scope is None or scope.workspace_id != ctx.workspace_id:
        raise not_found("Scope not found.")
    if c.retired_at is not None:
        raise api_error(409, "claim_retired", "That claim is retired.")
    if scope.status is not ScopeStatus.ACTIVE or scope.is_lab:
        raise api_error(
            409, "scope_not_active", "Control is proven against the active, non-lab scope."
        )
    targets = db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id == scope.id)).all()
    if not any(covers(c, t.kind, t.value) for t in targets):
        raise api_error(409, "not_in_scope", f"No target in this scope is covered by {c.name}.")
    probes = _probes()
    now = utcnow()
    if c.method is OwnershipMethod.DNS:
        seen = probes.txt(record_name(c))
    else:
        # The file check contacts the host, so the host itself must pass the scope now.
        decision = evaluate(snapshot(db, scope), c.name, now)
        if not decision.allowed:
            raise api_error(409, "not_in_scope", decision.reason)
        excluded = [
            ipaddress.ip_network(v)
            for (v,) in db.execute(
                select(ScopeExclusion.value).where(
                    ScopeExclusion.scope_id == scope.id,
                    ScopeExclusion.kind.in_([ScopeEntryKind.IP, ScopeEntryKind.CIDR]),
                )
            ).all()
        ]
        seen = probes.file(c.name, excluded)
    ok = any(hmac.compare_digest(token_hash(v), c.token_sha256) for v in seen.candidates)
    if ok:
        detail = f"Token found ({_where(c)})."
    elif seen.problem:
        detail = seen.problem
    else:
        detail = f"The token wasn't found ({_where(c)})."
    obs = seen.observation | {"observed_at": now.isoformat()}
    raw = json.dumps(obs, sort_keys=True, separators=(",", ":")).encode()
    chk = OwnershipCheck(
        workspace_id=ctx.workspace_id,
        claim_id=c.id,
        scope_id=scope.id,
        ok=ok,
        detail=detail[:1000],
        observation=obs,
        observation_sha256=hashlib.sha256(raw).digest(),
        checked_by_user_id=ctx.user_id,
        checked_at=now,
    )
    db.add(chk)
    db.flush()
    record(
        db,
        "ownership.checked",
        entity_type="ownership_claim",
        entity_id=c.id,
        data={
            "name": c.name,
            "method": c.method.value,
            "scope_id": str(scope.id),
            "scope_version": scope.version,
            "ok": ok,
            "detail": detail[:300],
        },
        **ctx.audit_kwargs(),
    )
    return _check_out(chk, _names(db, {ctx.user_id}))
