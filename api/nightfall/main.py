"""FastAPI application."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from nightfall.config import get_settings
from nightfall.core.db.session import get_engine
from nightfall.core.identity.routes import router as auth_router
from nightfall.core.identity.throttle import mutations_by_ip
from nightfall.core.request_info import client_ip
from nightfall.core.schemas import Model
from nightfall.core.tenancy.routes import router as workspace_router
from nightfall.overview.routes import router as overview_router
from nightfall.registry.routes import router as registry_router

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

health_router = APIRouter(prefix="/api", tags=["system"])
HEALTH_ROUTES = {("GET", "/api/health")}


class ComponentStatus(Model):
    name: str
    status: Literal["ok", "down"]


class HealthOut(Model):
    status: Literal["ok", "degraded"]
    version: str
    components: list[ComponentStatus]


@health_router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    db_status: Literal["ok", "down"] = "ok"
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SET LOCAL statement_timeout = 2000"))
            conn.execute(text("SELECT 1"))
    except Exception:
        db_status = "down"
    components = [
        ComponentStatus(name="api", status="ok"),
        ComponentStatus(name="database", status=db_status),
    ]
    return HealthOut(
        status="ok" if db_status == "ok" else "degraded",
        version=get_settings().version,
        components=components,
    )


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"detail": {"code": code, "message": message}}, status_code=status)


class RequestGuard(BaseHTTPMiddleware):
    """CSRF origin check + per-IP mutation rate limit + no caching of API responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in MUTATING and request.url.path.startswith("/api/"):
            if request.headers.get("origin") != get_settings().public_origin:
                return _error(403, "bad_origin", "Request origin not allowed.")
            if mutations_by_ip.hit_and_check(client_ip(request)):
                return _error(429, "rate_limited", "Too many requests. Slow down.")
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response


ROUTERS = (health_router, auth_router, workspace_router, registry_router, overview_router)


def create_app(*, check_settings: bool = True) -> FastAPI:
    if check_settings:
        get_settings()  # fail fast on bad configuration
    app = FastAPI(
        title="NIGHTFALL API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(RequestGuard)
    for r in ROUTERS:
        app.include_router(r)
    return app
