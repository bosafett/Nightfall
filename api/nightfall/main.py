"""FastAPI application."""

from __future__ import annotations

import hmac
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from nightfall.agents.routes import router as agents_router
from nightfall.blackice.routes import router as blackice_router
from nightfall.blackops.routes import router as blackops_router
from nightfall.config import get_settings
from nightfall.core.audit.routes import router as audit_router
from nightfall.core.db.session import get_engine
from nightfall.core.identity.routes import router as auth_router
from nightfall.core.identity.throttle import mutations_by_ip
from nightfall.core.request_info import client_ip
from nightfall.core.schemas import Model
from nightfall.core.tenancy.routes import router as workspace_router
from nightfall.findings.paths import router as paths_router
from nightfall.findings.routes import router as findings_router
from nightfall.overview.routes import router as overview_router
from nightfall.recon.routes import router as recon_router
from nightfall.registry.assets import router as assets_router
from nightfall.registry.routes import router as registry_router
from nightfall.reports.routes import router as reports_router
from nightfall.scope.routes import router as scope_router
from nightfall.warroom.routes import router as warroom_router
from nightfall.watchtower.routes import router as watchtower_router

log = logging.getLogger("nightfall.api")

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

health_router = APIRouter(prefix="/api", tags=["system"])
HEALTH_ROUTES = {("GET", "/api/health")}


class ComponentStatus(Model):
    name: str
    status: Literal["ok", "down", "on_demand", "off"]


class HealthOut(Model):
    status: Literal["ok", "degraded"]
    version: str
    components: list[ComponentStatus]


def _ai_status() -> ComponentStatus:
    """Configuration only: whether agents are turned on. AI being off never degrades the
    platform; everything else works without it."""
    return ComponentStatus(
        name="ai", status="off" if get_settings().ai_provider == "none" else "ok"
    )


@health_router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    db_status: Literal["ok", "down"] = "ok"
    worker_status: Literal["ok", "down"] = "down"
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SET LOCAL statement_timeout = 2000"))
            conn.execute(text("SELECT 1"))
            fresh = conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM worker_heartbeats "
                    "WHERE last_seen_at > now() - interval '30 seconds' "
                    "AND worker_id NOT LIKE 'lab:%')"
                )
            ).scalar()
            worker_status = "ok" if fresh else "down"
    except Exception:
        db_status = "down"
    if get_settings().on_demand_worker:
        # Serverless: no loop to heartbeat; jobs run when requested (nightfall.serverless).
        components = [
            ComponentStatus(name="api", status="ok"),
            ComponentStatus(name="database", status=db_status),
            ComponentStatus(name="worker", status="on_demand"),
            _ai_status(),
        ]
        return HealthOut(
            status="ok" if db_status == "ok" else "degraded",
            version=get_settings().version,
            components=components,
        )
    components = [
        ComponentStatus(name="api", status="ok"),
        ComponentStatus(name="database", status=db_status),
        ComponentStatus(name="worker", status=worker_status),
        _ai_status(),
    ]
    return HealthOut(
        status="ok" if db_status == worker_status == "ok" else "degraded",
        version=get_settings().version,
        components=components,
    )


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"detail": {"code": code, "message": message}}, status_code=status)


def _public_origins() -> set[str]:
    return {get_settings().public_origin}


class RequestGuard(BaseHTTPMiddleware):
    """CSRF origin check + per-IP mutation rate limit + no caching of API responses."""

    def __init__(self, app: Any, origins: Callable[[], set[str]] = _public_origins) -> None:
        super().__init__(app)
        self.origins = origins

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in MUTATING and request.url.path.startswith("/api/"):
            allowed = self.origins()
            if request.headers.get("origin") not in allowed:
                log.warning(
                    "rejected mutating request from origin %r (allowed: %r)",
                    request.headers.get("origin"),
                    sorted(allowed),
                )
                return _error(403, "bad_origin", "Request origin not allowed.")
            if mutations_by_ip.hit_and_check(client_ip(request)):
                return _error(429, "rate_limited", "Too many requests. Slow down.")
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response


internal_router = APIRouter(prefix="/api/internal", tags=["internal"])


def _cron_auth(request: Request) -> None:
    """Scheduled calls only: the platform sends `Authorization: Bearer <CRON_SECRET>`."""
    secret = get_settings().cron_secret
    given = request.headers.get("authorization", "")
    if not secret or not hmac.compare_digest(given.encode(), f"Bearer {secret}".encode()):
        raise HTTPException(status_code=404)


_cron_auth._nf_authz = True  # type: ignore[attr-defined]  # marker checked by tests


@internal_router.get("/worker/drain", dependencies=[Depends(_cron_auth)])
def cron_drain() -> dict[str, int]:
    if not get_settings().on_demand_worker:
        raise HTTPException(status_code=404)
    from nightfall.serverless import drain

    return {"processed": drain(budget_seconds=50.0, max_jobs=10)}


ROUTERS = (
    health_router,
    auth_router,
    workspace_router,
    registry_router,
    overview_router,
    assets_router,
    scope_router,
    recon_router,
    findings_router,
    paths_router,
    reports_router,
    agents_router,
    blackice_router,
    blackops_router,
    warroom_router,
    audit_router,
    watchtower_router,
    internal_router,
)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Serverless: start-up migrations. Single container: starts the embedded worker."""
    from nightfall.serverless import migrate_on_start

    migrate_on_start()
    embedded = None
    if get_settings().embedded_worker:
        from nightfall.recon.worker import start_embedded

        embedded = start_embedded()
    try:
        yield
    finally:
        if embedded is not None:
            thread, stop = embedded
            stop.set()
            thread.join(timeout=15)


def create_app(*, check_settings: bool = True) -> FastAPI:
    if check_settings:
        get_settings()  # fail fast on bad configuration
    app = FastAPI(
        lifespan=_lifespan if check_settings else None,
        title="JANUS API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(RequestGuard)
    for r in ROUTERS:
        app.include_router(r)
    return app
