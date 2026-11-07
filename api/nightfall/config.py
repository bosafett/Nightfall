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
  NIGHTFALL_ON_DEMAND_WORKER        "true" for serverless hosting: no loop; queued jobs run when
                                    requested, approved, or drained (see nightfall/serverless.py).
  NIGHTFALL_CRON_SECRET             bearer secret for the scheduled drain endpoint.
  NIGHTFALL_RATE_LIMIT_BACKEND      "memory" (default, one API process) or "postgres" (many
                                    instances, e.g. serverless).
  NIGHTFALL_AI_PROVIDER             "none" (default: agents off), "ollama" (a local model on a
                                    self-hosted machine; no paid calls) or "anthropic" (needs
                                    ANTHROPIC_API_KEY; worker only).
  NIGHTFALL_AI_MODEL                model id (default claude-opus-5-5; required for ollama,
                                    e.g. "qwen3:14b").
  NIGHTFALL_OLLAMA_URL              Ollama endpoint (default http://127.0.0.1:11434). Must be
                                    loopback, a private address or a single-label host name
                                    (e.g. a compose service), so assessment data stays local.
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
  NIGHTFALL_LAB_NETWORKS            comma-separated CIDRs of the isolated lab network (default
                                    172.30.99.0/24, matching infra/lab/compose.yml). Lab scopes
                                    may only name addresses inside them; normal scopes never.
  NIGHTFALL_WORKER_MODE             "standard" (default) or "lab": the lab machine's worker,
                                    which only claims lab operations and only contacts
                                    addresses inside NIGHTFALL_LAB_NETWORKS.
  NIGHTFALL_LAB_WORKER_DB_PASSWORD  (bootstrap-roles only) enables the lab worker's login.
  NIGHTFALL_BLACKSITE_ENABLED       "true" to allow the host-only BLACKSITE listener
                                    (nightfall-blacksite) to start. Off by default; refused
                                    together with NIGHTFALL_ON_DEMAND_WORKER (hosted platform).
  NIGHTFALL_BLACKSITE_PORT          its loopback port (default 8443). It always binds 127.0.0.1.
  NIGHTFALL_BLACKSITE_BIND          its bind address (default 127.0.0.1). Inside a container,
                                    0.0.0.0 with the port published to the host's 127.0.0.1 only.
  NIGHTFALL_BLACKSITE_ALLOWED_PEERS comma-separated CIDRs whose connections it accepts (default
                                    127.0.0.1/32,::1/128). Its NIGHTFALL_DATABASE_URL must be
                                    role nightfall_blacksite (checked at start-up).
  NIGHTFALL_BLACKSITE_REVIEW_REF    reference of the recorded independent review (D4). Without
                                    it BLACKSITE refuses to create or approve lab execution.
  NIGHTFALL_BLACKSITE_DB_PASSWORD   (bootstrap-roles only) enables the BLACKSITE role's login.
  NIGHTFALL_LAB_PACK1_REVIEW_REF    reference of the recorded independent review of lab tool
                                    pack 1. Without it (and BLACKSITE) the pack is unavailable.
  NIGHTFALL_LAB_PACK1_DIR           (lab worker) the pack's templates, from the lab tool image
                                    (default /opt/nuclei-pack1), checked against pack1.json.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, cast


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
    on_demand_worker: bool = False
    cron_secret: str | None = None
    rate_limit_backend: Literal["memory", "postgres"] = "memory"
    ai_provider: Literal["none", "anthropic", "ollama", "fixture"] = "none"
    ai_model: str = "claude-opus-5-5"
    ollama_url: str = "http://127.0.0.1:11434"
    tool_sandbox: Literal["uid", "none"] = "uid"
    tool_user: str = "nftool"
    egress_port: int = 3128
    lab_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
        ipaddress.ip_network("172.30.99.0/24"),
    )
    worker_mode: Literal["standard", "lab"] = "standard"
    session_idle_seconds: int = 12 * 3600
    session_absolute_seconds: int = 7 * 86400
    # Two-factor must have been verified this recently for sensitive actions (D1).
    step_up_seconds: int = 15 * 60
    blacksite_enabled: bool = False
    blacksite_port: int = 8443
    blacksite_bind: str = "127.0.0.1"
    blacksite_allowed_peers: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("::1/128"),
    )
    blacksite_review_ref: str | None = None
    # Lab tool pack 1 (docs/designs/2026-11-lab-tool-pack-1.md): off without its own review.
    lab_pack1_review_ref: str | None = None
    lab_pack1_dir: Path = Path("/opt/nuclei-pack1")
    version: str = "0.1.0"


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def _local_url(url: str) -> str:
    """The Ollama endpoint must stay on this machine or network: assessment data is sent to it."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme not in ("http", "https") or not host or parts.path not in ("", "/"):
        raise ConfigError("NIGHTFALL_OLLAMA_URL must be http(s)://host[:port]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        local = host == "localhost" or "." not in host
    else:
        local = ip.is_loopback or ip.is_private
    if not local:
        raise ConfigError(
            "NIGHTFALL_OLLAMA_URL must be loopback, a private address or a single-label host "
            "name, so assessment data stays local"
        )
    return f"{parts.scheme}://{parts.netloc}"


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
    on_demand = os.environ.get("NIGHTFALL_ON_DEMAND_WORKER", "false").strip().lower() == "true"
    if on_demand and not worker_url:
        raise ConfigError("NIGHTFALL_ON_DEMAND_WORKER needs NIGHTFALL_WORKER_DATABASE_URL")
    if on_demand and embedded:
        raise ConfigError("Choose either the embedded or the on-demand worker, not both")
    cron_secret = os.environ.get("NIGHTFALL_CRON_SECRET", "").strip() or None
    if cron_secret is not None and len(cron_secret) < 32:
        raise ConfigError("NIGHTFALL_CRON_SECRET must be at least 32 characters")
    rl = os.environ.get("NIGHTFALL_RATE_LIMIT_BACKEND", "memory").strip() or "memory"
    if rl not in ("memory", "postgres"):
        raise ConfigError("NIGHTFALL_RATE_LIMIT_BACKEND must be 'memory' or 'postgres'")
    ai = os.environ.get("NIGHTFALL_AI_PROVIDER", "none").strip() or "none"
    if ai not in ("none", "anthropic", "ollama", "fixture"):
        raise ConfigError("NIGHTFALL_AI_PROVIDER must be 'none', 'ollama' or 'anthropic'")
    if ai == "fixture" and mode != "fixture":
        raise ConfigError("NIGHTFALL_AI_PROVIDER=fixture is for tests (fixture collector mode)")
    raw_model = os.environ.get("NIGHTFALL_AI_MODEL", "").strip()
    ai_model = raw_model or "claude-opus-5-5"
    ollama_url = os.environ.get("NIGHTFALL_OLLAMA_URL", "").strip() or "http://127.0.0.1:11434"
    if ai == "ollama":
        if on_demand:
            raise ConfigError(
                "NIGHTFALL_AI_PROVIDER=ollama needs a self-hosted worker; the hosted platform "
                "(on-demand worker) can't reach a local model."
            )
        if not raw_model:
            raise ConfigError("NIGHTFALL_AI_PROVIDER=ollama needs NIGHTFALL_AI_MODEL")
        ollama_url = _local_url(ollama_url)
    raw_lab = os.environ.get("NIGHTFALL_LAB_NETWORKS", "").strip() or "172.30.99.0/24"
    try:
        lab_networks = tuple(
            ipaddress.ip_network(n.strip()) for n in raw_lab.split(",") if n.strip()
        )
    except ValueError as exc:
        raise ConfigError(f"NIGHTFALL_LAB_NETWORKS: {exc}") from exc
    if not lab_networks or any(not n.is_private for n in lab_networks):
        raise ConfigError("NIGHTFALL_LAB_NETWORKS must be private address ranges")
    worker_mode = os.environ.get("NIGHTFALL_WORKER_MODE", "standard").strip() or "standard"
    if worker_mode not in ("standard", "lab"):
        raise ConfigError("NIGHTFALL_WORKER_MODE must be 'standard' or 'lab'")
    blacksite = os.environ.get("NIGHTFALL_BLACKSITE_ENABLED", "false").strip().lower() == "true"
    if blacksite and on_demand:
        raise ConfigError("BLACKSITE never runs on the hosted platform (on-demand worker).")
    blacksite_port = int(os.environ.get("NIGHTFALL_BLACKSITE_PORT", "8443"))
    if not 0 < blacksite_port < 65536:
        raise ConfigError("NIGHTFALL_BLACKSITE_PORT must be a TCP port")
    raw_peers = os.environ.get("NIGHTFALL_BLACKSITE_ALLOWED_PEERS", "").strip()
    try:
        peers = tuple(ipaddress.ip_network(n.strip()) for n in raw_peers.split(",") if n.strip())
    except ValueError as exc:
        raise ConfigError(f"NIGHTFALL_BLACKSITE_ALLOWED_PEERS: {exc}") from exc
    if any(not (n.is_private or n.is_loopback) for n in peers):
        raise ConfigError("NIGHTFALL_BLACKSITE_ALLOWED_PEERS must be loopback or private ranges")
    review_ref = os.environ.get("NIGHTFALL_BLACKSITE_REVIEW_REF", "").strip()[:200]
    pack1_ref = os.environ.get("NIGHTFALL_LAB_PACK1_REVIEW_REF", "").strip()[:200]
    pack1_dir = Path(os.environ.get("NIGHTFALL_LAB_PACK1_DIR", "/opt/nuclei-pack1").strip())
    if not pack1_dir.is_absolute():
        raise ConfigError("NIGHTFALL_LAB_PACK1_DIR must be an absolute path")
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
        on_demand_worker=on_demand,
        cron_secret=cron_secret,
        rate_limit_backend="postgres" if rl == "postgres" else "memory",
        ai_provider=cast(Literal["none", "anthropic", "ollama", "fixture"], ai),
        ai_model=ai_model,
        ollama_url=ollama_url,
        lab_networks=lab_networks,
        worker_mode="lab" if worker_mode == "lab" else "standard",
        blacksite_enabled=blacksite,
        blacksite_port=blacksite_port,
        blacksite_bind=os.environ.get("NIGHTFALL_BLACKSITE_BIND", "").strip() or "127.0.0.1",
        blacksite_allowed_peers=peers or Settings.blacksite_allowed_peers,
        blacksite_review_ref=review_ref or None,
        lab_pack1_review_ref=pack1_ref or None,
        lab_pack1_dir=pack1_dir,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
