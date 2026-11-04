"""Runtime configuration, read once from the environment.

Required:
  NIGHTFALL_DATABASE_URL   API connection (role nightfall_app: no superuser, no BYPASSRLS).
  NIGHTFALL_SECRET_KEY     base64 of exactly 32 random bytes; encrypts TOTP secrets at rest.
  NIGHTFALL_PUBLIC_ORIGIN  origin the browser uses, e.g. https://nightfall.example (CSRF check).

Optional:
  NIGHTFALL_MIGRATION_DATABASE_URL  schema-owner connection (migrations, admin CLI).
  NIGHTFALL_COOKIE_SECURE           "true" (default) / "false".
  NIGHTFALL_FORWARDED_HOPS          trusted reverse proxies in front of the API (default 0).
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from functools import lru_cache


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    migration_database_url: str | None
    secret_key: bytes
    public_origin: str
    cookie_secure: bool
    forwarded_hops: int
    session_idle_seconds: int = 12 * 3600
    session_absolute_seconds: int = 7 * 86400
    version: str = "0.1.0"


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def _sqlalchemy_url(url: str) -> str:
    # Accept plain postgres URLs; always use the psycopg 3 driver.
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def load_settings() -> Settings:
    try:
        key = base64.b64decode(_require("NIGHTFALL_SECRET_KEY"), validate=True)
    except binascii.Error as exc:
        raise ConfigError("NIGHTFALL_SECRET_KEY must be base64") from exc
    if len(key) != 32:
        raise ConfigError("NIGHTFALL_SECRET_KEY must decode to exactly 32 bytes")

    origin = _require("NIGHTFALL_PUBLIC_ORIGIN").rstrip("/")
    migration_url = os.environ.get("NIGHTFALL_MIGRATION_DATABASE_URL", "").strip() or None
    hops = int(os.environ.get("NIGHTFALL_FORWARDED_HOPS", "0"))
    if hops < 0:
        raise ConfigError("NIGHTFALL_FORWARDED_HOPS must be >= 0")

    return Settings(
        database_url=_sqlalchemy_url(_require("NIGHTFALL_DATABASE_URL")),
        migration_database_url=_sqlalchemy_url(migration_url) if migration_url else None,
        secret_key=key,
        public_origin=origin,
        cookie_secure=os.environ.get("NIGHTFALL_COOKIE_SECURE", "true").lower() != "false",
        forwarded_hops=hops,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
