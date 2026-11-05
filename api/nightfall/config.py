"""Runtime configuration, read once from the environment.

Required:
  NIGHTFALL_DATABASE_URL   API connection (role nightfall_app: no superuser, no BYPASSRLS).
  NIGHTFALL_SECRET_KEY     base64 of exactly 32 random bytes; encrypts TOTP secrets at rest.
  NIGHTFALL_PUBLIC_ORIGIN  origin the browser uses, e.g. https://nightfall.example (CSRF check).

Optional:
  NIGHTFALL_MIGRATION_DATABASE_URL  schema-owner connection (migrations, admin CLI).
  NIGHTFALL_COOKIE_SECURE           "true" (default) / "false".
  NIGHTFALL_EVIDENCE_DIR            content-addressed evidence store (default ./var/evidence).
  NIGHTFALL_EVIDENCE_BACKEND        "fs" (default: NIGHTFALL_EVIDENCE_DIR) or "postgres" (table
                                    evidence_blobs; for hosts without a shared disk).
  NIGHTFALL_EMBEDDED_WORKER         "true" runs the worker loop inside the API process (single-
                                    container hosting). Needs NIGHTFALL_WORKER_DATABASE_URL.
  NIGHTFALL_WORKER_DATABASE_URL     worker connection (role nightfall_worker).
  NIGHTFALL_COLLECTOR_MODE          "live" (default) or "fixture" (tests only: canned results,
                                    labelled as fixture evidence; never contacts the network).
  NIGHTFALL_FORWARDED_HOPS          trusted reverse proxies in front of the API that set
                                    X-Forwarded-For themselves (default 0). Never count the
                                    Next.js rewrite proxy: it forwards the client's header as-is.
  NIGHTFALL_NUCLEI_BIN              absolute path to the pinned nuclei binary (worker only).
  NIGHTFALL_TOOL_SANDBOX            "uid" (default) or "none". "uid" runs tools as
                                    NIGHTFALL_TOOL_USER (default nftool), whose only network
                                    route is the egress proxy port (infra/tools/egress-lock.sh).
                                    With "none", live tool runs refuse to start.
  NIGHTFALL_EGRESS_PORT             loopback port of the per-run egress proxy (default 3128;
                                    must match the firewall rule).
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal


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
    evidence_dir: Path
    worker_database_url: str | None
    collector_mode: Literal["live", "fixture"]
    nuclei_bin: str | None = None
    evidence_backend: Literal["fs", "postgres"] = "fs"
    embedded_worker: bool = False
    tool_sandbox: Literal["uid", "none"] = "uid"
    tool_user: str = "nftool"
    egress_port: int = 3128
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
    raw_key = _require("NIGHTFALL_SECRET_KEY")
    try:
        key = base64.b64decode(raw_key, validate=True)
    except binascii.Error:
        try:  # URL-safe alphabet (some hosts' generated secrets)
            key = base64.urlsafe_b64decode(raw_key + "=" * (-len(raw_key) % 4))
        except (binascii.Error, ValueError) as exc:
            raise ConfigError("NIGHTFALL_SECRET_KEY must be base64") from exc
    if len(key) != 32:
        raise ConfigError("NIGHTFALL_SECRET_KEY must decode to exactly 32 bytes")

    origin = _require("NIGHTFALL_PUBLIC_ORIGIN").rstrip("/")
    migration_url = os.environ.get("NIGHTFALL_MIGRATION_DATABASE_URL", "").strip() or None
    hops = int(os.environ.get("NIGHTFALL_FORWARDED_HOPS", "0"))
    if hops < 0:
        raise ConfigError("NIGHTFALL_FORWARDED_HOPS must be >= 0")

    mode = os.environ.get("NIGHTFALL_COLLECTOR_MODE", "live").strip() or "live"
    if mode not in ("live", "fixture"):
        raise ConfigError("NIGHTFALL_COLLECTOR_MODE must be 'live' or 'fixture'")
    worker_url = os.environ.get("NIGHTFALL_WORKER_DATABASE_URL", "").strip() or None
    nuclei_bin = os.environ.get("NIGHTFALL_NUCLEI_BIN", "").strip() or None
    if nuclei_bin and not os.path.isabs(nuclei_bin):
        raise ConfigError("NIGHTFALL_NUCLEI_BIN must be an absolute path")
    sandbox = os.environ.get("NIGHTFALL_TOOL_SANDBOX", "uid").strip() or "uid"
    if sandbox not in ("uid", "none"):
        raise ConfigError("NIGHTFALL_TOOL_SANDBOX must be 'uid' or 'none'")
    backend = os.environ.get("NIGHTFALL_EVIDENCE_BACKEND", "fs").strip() or "fs"
    if backend not in ("fs", "postgres"):
        raise ConfigError("NIGHTFALL_EVIDENCE_BACKEND must be 'fs' or 'postgres'")
    embedded = os.environ.get("NIGHTFALL_EMBEDDED_WORKER", "false").strip().lower() == "true"
    if embedded and not worker_url:
        raise ConfigError("NIGHTFALL_EMBEDDED_WORKER needs NIGHTFALL_WORKER_DATABASE_URL")
    egress_port = int(os.environ.get("NIGHTFALL_EGRESS_PORT", "3128"))
    if not 0 < egress_port < 65536:
        raise ConfigError("NIGHTFALL_EGRESS_PORT must be a TCP port")

    return Settings(
        database_url=_sqlalchemy_url(_require("NIGHTFALL_DATABASE_URL")),
        migration_database_url=_sqlalchemy_url(migration_url) if migration_url else None,
        secret_key=key,
        public_origin=origin,
        cookie_secure=os.environ.get("NIGHTFALL_COOKIE_SECURE", "true").lower() != "false",
        forwarded_hops=hops,
        evidence_dir=Path(os.environ.get("NIGHTFALL_EVIDENCE_DIR", "var/evidence")).resolve(),
        worker_database_url=_sqlalchemy_url(worker_url) if worker_url else None,
        collector_mode="fixture" if mode == "fixture" else "live",
        nuclei_bin=nuclei_bin,
        tool_sandbox="none" if sandbox == "none" else "uid",
        tool_user=os.environ.get("NIGHTFALL_TOOL_USER", "nftool").strip() or "nftool",
        egress_port=egress_port,
        evidence_backend="postgres" if backend == "postgres" else "fs",
        embedded_worker=embedded,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
