"""BLACK OPS Profile B, step 2: test identities and the run gates (design G1-G5).

Credentials are sealed, not just encrypted. The API seals each test identity's credential to
the self-hosted worker's X25519 public key (ephemeral key agreement, HKDF-SHA256, AES-256-GCM,
bound to the identity and workspace ids), and only the worker holds the private key. The
hosted API can store a credential but can never read one back, which is stronger than the
design's "key derived from the deployment secret" and is what G5 (self-hosted worker only)
needs.

Gates, all of which must hold (checked by the preflight, again at launch, and again by the
worker before anything is sent):
  G1  proof of control of the target, passed for this scope version in the last 24 hours
  G2  the identities are active, of this workspace, and registered for the target's origin
  G3  NIGHTFALL_PROFILE_B_ENABLED and NIGHTFALL_PROFILE_B_REVIEW_REF (the recorded review)
  G4  per-run approval with fresh two-factor (the approval routes already require it);
      Profile B approvals expire after 24 hours
  G5  a self-hosted worker: refused on the hosted (on-demand) platform
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from nightfall.config import Settings
from nightfall.core.db.models import (
    OwnershipCheck,
    PlaybookRun,
    Scope,
    ScopeEntryKind,
    ScopeStatus,
    TestIdentity,
)
from nightfall.scope.ownership import FRESH, proof_for

APPROVAL_TTL = timedelta(hours=24)
MAX_IDENTITIES = 5
_INFO = b"janus/profile-b/test-identity/v1"
_VERSION = b"\x01"


class SealError(ValueError):
    pass


# --- Sealing ---------------------------------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    """(public, private), each base64. The private key goes only to the self-hosted worker."""
    k = X25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    priv = k.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = k.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode(), base64.b64encode(priv).decode()


def _key(shared: bytes, eph: bytes, recipient: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph + recipient, info=_INFO).derive(
        shared
    )


def _aad(identity_id: uuid.UUID, workspace_id: uuid.UUID) -> bytes:
    return identity_id.bytes + workspace_id.bytes


def seal(
    public_b64: str, secret: dict[str, str], identity_id: uuid.UUID, workspace_id: uuid.UUID
) -> bytes:
    try:
        recipient = base64.b64decode(public_b64, validate=True)
        pub = X25519PublicKey.from_public_bytes(recipient)
    except ValueError as exc:
        raise SealError("NIGHTFALL_PROFILE_B_PUBLIC_KEY isn't a valid X25519 key.") from exc
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    nonce = os.urandom(12)
    plain = json.dumps(secret, separators=(",", ":")).encode()
    ct = AESGCM(_key(eph.exchange(pub), eph_pub, recipient)).encrypt(
        nonce, plain, _aad(identity_id, workspace_id)
    )
    return _VERSION + eph_pub + nonce + ct


def unseal(
    private_b64: str, blob: bytes, identity_id: uuid.UUID, workspace_id: uuid.UUID
) -> dict[str, str]:
    """Worker only. Raises SealError on any mismatch (wrong key, other row, tampering)."""
    if blob[:1] != _VERSION or len(blob) < 1 + 32 + 12 + 16:
        raise SealError("Unknown sealed-credential format.")
    try:
        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64, validate=True))
        recipient = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        eph_pub, nonce, ct = blob[1:33], blob[33:45], blob[45:]
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        plain = AESGCM(_key(shared, eph_pub, recipient)).decrypt(
            nonce, ct, _aad(identity_id, workspace_id)
        )
    except Exception as exc:  # noqa: BLE001 - any failure is the same refusal
        raise SealError("The credential couldn't be opened with this worker's key.") from exc
    data = json.loads(plain)
    if not isinstance(data, dict):
        raise SealError("Unexpected credential content.")
    return {str(k): str(v) for k, v in data.items()}


def load_secret(db: Session, s: Settings, identity: TestIdentity) -> dict[str, str]:
    """Worker only: the app role has no SELECT on secret_sealed, so this fails in the API."""
    if not s.profile_b_private_key:
        raise SealError("This worker has no NIGHTFALL_PROFILE_B_PRIVATE_KEY.")
    blob = db.scalar(
        text("SELECT secret_sealed FROM test_identities WHERE id = :i"), {"i": identity.id}
    )
    if blob is None:
        raise SealError("Identity not found.")
    return unseal(s.profile_b_private_key, bytes(blob), identity.id, identity.workspace_id)


# --- Gates -----------------------------------------------------------------------------------


def unavailable_reason(s: Settings) -> str | None:
    """G3 and G5, plus the key the API needs to accept credentials."""
    if not s.profile_b_enabled:
        return "Profile B is switched off on this deployment (NIGHTFALL_PROFILE_B_ENABLED)."
    if not s.profile_b_review_ref:
        return "Profile B has no recorded independent review (NIGHTFALL_PROFILE_B_REVIEW_REF)."
    if s.on_demand_worker:
        return "Profile B runs only on a self-hosted worker, not on the hosted platform."
    if not s.profile_b_public_key:
        return "No worker key is configured (NIGHTFALL_PROFILE_B_PUBLIC_KEY)."
    return None


def origin_host(origin: str) -> str:
    return origin.removeprefix("https://").split(":", 1)[0]


def identity_problems(
    db: Session, workspace_id: uuid.UUID, target: str, ids: list[uuid.UUID]
) -> str | None:
    """G2. None when every identity is active, of this workspace and for this target."""
    if len(ids) > MAX_IDENTITIES or len(set(ids)) != len(ids):
        return f"Use at most {MAX_IDENTITIES} different test identities."
    if not ids:
        return None
    found = db.scalars(select(TestIdentity).where(TestIdentity.id.in_(ids))).all()
    by_id = {i.id: i for i in found if i.workspace_id == workspace_id}
    for i in ids:
        ident = by_id.get(i)
        if ident is None:
            return "A test identity wasn't found."
        if ident.retired_at is not None:
            return f"Test identity {ident.label!r} is retired."
        if origin_host(ident.origin) != target:
            return f"Test identity {ident.label!r} belongs to {ident.origin}, not {target}."
    return None


def control_proof(db: Session, scope: Scope, target: str, now: datetime) -> OwnershipCheck | None:
    """G1 for a host target: a passing check of a covering claim, this scope version, fresh."""
    p = proof_for(db, scope, ScopeEntryKind.HOST, target, now)
    return p.check if p else None


def worker_check(db: Session, s: Settings, run: PlaybookRun, now: datetime) -> str | None:
    """Everything again, immediately before the worker sends anything for a Profile B run.
    Returns the refusal reason, or None."""
    if why := unavailable_reason(s):
        return why
    if not s.profile_b_private_key:
        return "This worker has no NIGHTFALL_PROFILE_B_PRIVATE_KEY."
    scope = db.get(Scope, run.scope_id)
    if scope is None or scope.status is not ScopeStatus.ACTIVE or scope.is_lab:
        return "The scope changed after this run was approved."
    if control_proof(db, scope, run.target_value, now) is None:
        return (
            f"Proof of control of {run.target_value} isn't fresh any more "
            f"(it must have passed within {int(FRESH.total_seconds() // 3600)} hours)."
        )
    return identity_problems(db, run.workspace_id, run.target_value, list(run.identity_ids))


def summary(identity: TestIdentity) -> dict[str, Any]:
    """What may be shown or recorded about an identity: never the credential."""
    return {
        "id": str(identity.id),
        "label": identity.label,
        "origin": identity.origin,
        "credential": f"<test-identity:{identity.label}>",
    }
