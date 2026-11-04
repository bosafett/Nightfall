"""Password hashing, opaque tokens, TOTP, and at-rest encryption of TOTP secrets."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import uuid

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASSWORD_MIN = 12
PASSWORD_MAX = 1024
TOTP_PERIOD = 30
TOTP_ISSUER = "NIGHTFALL"

_hasher = PasswordHasher()  # argon2id with library-recommended parameters
# Verified when the email is unknown, so response time doesn't reveal which emails exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


class PasswordPolicyError(ValueError):
    pass


def check_password_policy(password: str) -> None:
    if len(password) < PASSWORD_MIN:
        raise PasswordPolicyError(f"Use at least {PASSWORD_MIN} characters.")
    if len(password) > PASSWORD_MAX:
        raise PasswordPolicyError(f"Use at most {PASSWORD_MAX} characters.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def new_token() -> tuple[str, bytes]:
    """Returns (raw token for the client, sha256 digest for storage)."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def hash_token(raw: str) -> bytes:
    return hashlib.sha256(raw.encode()).digest()


# --- TOTP -----------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return str(pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=TOTP_ISSUER))


def verify_totp(
    secret: str, code: str, last_step: int | None, now: float | None = None
) -> int | None:
    """Returns the matched time step, or None. Accepts ±1 step of clock drift and
    rejects any step at or before last_step (no code reuse)."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // TOTP_PERIOD)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(str(totp.at(step * TOTP_PERIOD)), code):
            return step
    return None


# --- At-rest encryption ------------------------------------------------------


def encrypt_secret(key: bytes, plaintext: str, user_id: uuid.UUID) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), b"totp:" + user_id.bytes)


def decrypt_secret(key: bytes, blob: bytes, user_id: uuid.UUID) -> str:
    return AESGCM(key).decrypt(blob[:12], blob[12:], b"totp:" + user_id.bytes).decode()
