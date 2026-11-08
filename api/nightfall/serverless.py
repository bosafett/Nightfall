"""Serverless hosting (Vercel Services + Neon Postgres).

What changes compared with a long-running host:
  * Configuration is derived from the platform's variables (apply_platform_env). The API and
    worker database passwords are derived from the database owner's password with HMAC, so
    no extra database secret has to be created or handled. bootstrap-roles keeps the role
    passwords in step at every cold start.
  * Migrations run at cold start under an advisory lock (migrate_on_start). The owner
    connection string is then removed from this process's environment.
  * There is no worker loop: queued jobs run on demand (drain), triggered after a request
    or an approval, by the browser while an operation page is open, and by a daily cron.
    Each run still connects as nightfall_worker, never with the API's role.
  * Rate limits are shared through Postgres; evidence content lives in Postgres.

Known weaker points than a dedicated host (docs/PHASE0_ARCHITECTURE_REVIEW.md §10c):
the owner credentials are present in the platform environment (Neon injects them), and the
tool sandbox can't run, so Nuclei is refused.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time
from collections.abc import MutableMapping
from pathlib import Path
from urllib.parse import quote

log = logging.getLogger("nightfall.serverless")

_ADVISORY_LOCK = 7_274_272


def _derive(secret: str, purpose: str) -> str:
    return hmac.new(secret.encode(), f"nightfall:{purpose}".encode(), hashlib.sha256).hexdigest()


def apply_platform_env(env: MutableMapping[str, str] | None = None) -> None:
    """Fills NIGHTFALL_* settings from Vercel/Neon variables. Explicit settings win."""
    env = os.environ if env is None else env
    if not env.get("VERCEL"):
        return
    host = env.get("PGHOST_UNPOOLED") or env.get("PGHOST")
    db, user, pw = env.get("PGDATABASE"), env.get("PGUSER"), env.get("PGPASSWORD")
    if host and db and user and pw:
        base = f"{host}/{quote(db, safe='')}?sslmode=require"
        env.setdefault(
            "NIGHTFALL_MIGRATION_DATABASE_URL",
            f"postgresql://{quote(user, safe='')}:{quote(pw, safe='')}@{base}",
        )
        env.setdefault("NIGHTFALL_APP_DB_PASSWORD", _derive(pw, "db:nightfall_app"))
        env.setdefault("NIGHTFALL_WORKER_DB_PASSWORD", _derive(pw, "db:nightfall_worker"))
        env.setdefault(
            "NIGHTFALL_DATABASE_URL",
            f"postgresql://nightfall_app:{env['NIGHTFALL_APP_DB_PASSWORD']}@{base}",
        )
        env.setdefault(
            "NIGHTFALL_WORKER_DATABASE_URL",
            f"postgresql://nightfall_worker:{env['NIGHTFALL_WORKER_DB_PASSWORD']}@{base}",
        )
    if prod := env.get("VERCEL_PROJECT_PRODUCTION_URL"):
        env.setdefault("NIGHTFALL_PUBLIC_ORIGIN", f"https://{prod}")
    if cron := env.get("CRON_SECRET"):
        env.setdefault("NIGHTFALL_CRON_SECRET", cron)
    for key, value in {
        "NIGHTFALL_EVIDENCE_BACKEND": "postgres",
        "NIGHTFALL_ON_DEMAND_WORKER": "true",
        "NIGHTFALL_RATE_LIMIT_BACKEND": "postgres",
        "NIGHTFALL_TOOL_SANDBOX": "none",
        # Vercel's edge overwrites X-Forwarded-For with the client address.
        "NIGHTFALL_FORWARDED_HOPS": "1",
        "NIGHTFALL_AUTO_MIGRATE": "true",
    }.items():
        env.setdefault(key, value)


def migrate_on_start() -> None:
    """Roles, migrations and the first owner, once per cold start, serialized across
    instances. Exits the process (startup fails) if a role could bypass isolation."""
    if os.environ.get("NIGHTFALL_AUTO_MIGRATE", "").lower() != "true":
        return
    url = os.environ.get("NIGHTFALL_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("NIGHTFALL_AUTO_MIGRATE needs NIGHTFALL_MIGRATION_DATABASE_URL")
    import argparse

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool

    from nightfall import cli
    from nightfall.config import _sqlalchemy_url

    started = time.monotonic()
    engine = create_engine(_sqlalchemy_url(url), poolclass=NullPool)
    with engine.connect() as lock_conn:
        lock_conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _ADVISORY_LOCK})
        try:
            cli.bootstrap_roles(argparse.Namespace())
            root = Path(__file__).resolve().parent.parent
            cfg = Config(str(root / "alembic.ini"))
            cfg.set_main_option("script_location", str(root / "migrations"))
            cfg.attributes["url"] = url
            command.upgrade(cfg, "head")
            cli.bootstrap_owner(argparse.Namespace())
        finally:
            lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _ADVISORY_LOCK})
            lock_conn.commit()
    engine.dispose()
    # The running API never needs the owner credentials again.
    for key in ("NIGHTFALL_MIGRATION_DATABASE_URL", "NIGHTFALL_ADMIN_PASSWORD"):
        os.environ.pop(key, None)
    log.info("start-up migrations done in %.1fs", time.monotonic() - started)


# --- on-demand worker ------------------------------------------------------------------

_worker_lock = threading.Lock()
_worker = None


def drain(budget_seconds: float = 25.0, max_jobs: int = 3) -> int:
    """Runs queued jobs until the queue is empty, the budget is spent or max_jobs ran.
    One drain per process at a time; returns how many jobs ran."""
    global _worker
    if not _worker_lock.acquire(blocking=False):
        return 0
    try:
        if _worker is None:
            from nightfall.recon.worker import build_worker

            _worker = build_worker()
        _worker.heartbeat()
        deadline = time.monotonic() + budget_seconds
        ran = 0
        while ran < max_jobs and time.monotonic() < deadline and _worker.run_once():
            ran += 1
        return ran
    finally:
        _worker_lock.release()


def schedule_monitors() -> int:
    """SHIELD: queue the scheduled checks that are due (worker role). Called by the daily
    cron before the queue is drained; returns how many checks were queued."""
    global _worker
    from nightfall.core.clock import utcnow
    from nightfall.shield.scheduler import schedule

    with _worker_lock:
        if _worker is None:
            from nightfall.recon.worker import build_worker

            _worker = build_worker()
        sessions = _worker.sessions
    return schedule(sessions, utcnow())
