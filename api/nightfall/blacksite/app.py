"""The host-only BLACKSITE listener (owner decisions D1, D3, D4).

A separate ASGI app, started only by `nightfall-blacksite` on the lab machine. It is never
part of the public app (nightfall.main.create_app), so the hosted deployment has no route
to any of this. Layers, each of which must hold:

  1. Feature flag NIGHTFALL_BLACKSITE_ENABLED (off by default; refused on hosted platforms).
  2. Network: binds 127.0.0.1, reached through an SSH tunnel. Every request is checked
     against the socket's peer address (never forwarded headers) and the Host header (so a
     web page can't use DNS rebinding to reach it through the operator's browser).
  3. Database: connects as nightfall_blacksite, confined to lab records (migration 0013).
  4. Identity: workspace owner, with two-factor verified in the last 15 minutes, on every
     workspace route; every allowed request is audited in its own transaction.
  5. Lab execution additionally needs the independent review reference (D4).

Only a curated set of existing routes is mounted; nothing here runs commands.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from nightfall.blackops import routes as blackops
from nightfall.config import get_settings
from nightfall.core.audit.writer import record_detached
from nightfall.core.db.session import DB
from nightfall.core.identity import routes as auth
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.recon import routes as recon

log = logging.getLogger("nightfall.blacksite")


def allowed_hosts() -> set[str]:
    port = get_settings().blacksite_port
    return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}


def allowed_origins() -> set[str]:
    return {f"http://{h}" for h in allowed_hosts()}


class HostOnly(BaseHTTPMiddleware):
    """Refuses any request whose TCP peer isn't an allowed (loopback) address, or whose Host
    isn't the loopback listener. Uses the socket address only: uvicorn runs with proxy
    headers off, and X-Forwarded-For / Forwarded are never consulted."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        s = get_settings()
        peer = request.client.host if request.client else ""
        try:
            addr = ipaddress.ip_address(peer)
            peer_ok = any(addr in n for n in s.blacksite_allowed_peers)
        except ValueError:
            peer_ok = False
        host_ok = request.headers.get("host", "").lower() in allowed_hosts()
        if not (s.blacksite_enabled and peer_ok and host_ok):
            reason = "disabled" if not s.blacksite_enabled else "peer" if not peer_ok else "host"
            log.warning("BLACKSITE refused a request (%s) from peer %r", reason, peer)
            record_detached(
                "blacksite.network_denied",
                data={"reason": reason, "path": request.url.path[:200]},
                ip=peer[:64] or None,
            )
            return JSONResponse(
                {"detail": {"code": "not_host_access", "message": "Not available."}},
                status_code=404,
            )
        return await call_next(request)


class StatusOut(Model):
    enabled: bool
    review_recorded: bool
    review_reference: str | None
    database_role: str
    approval_policy: str
    operator: str
    mfa_verified_at: str | None


router = APIRouter(prefix="/api/workspaces/{workspace_id}/blacksite", tags=["blacksite"])


@router.get("/status", response_model=StatusOut)
def status(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> StatusOut:
    from nightfall.core.db.models import Workspace

    s = get_settings()
    policy = db.get(Workspace, ctx.workspace_id)
    at = ctx.auth.session.mfa_verified_at
    return StatusOut(
        enabled=s.blacksite_enabled,
        review_recorded=bool(s.blacksite_review_ref),
        review_reference=s.blacksite_review_ref,
        database_role=str(db.scalar(text("SELECT current_user"))),
        approval_policy=policy.approval_policy if policy else "single_operator",
        operator=ctx.auth.user.display_name,
        mfa_verified_at=at.isoformat() if at else None,
    )


def _curated() -> list[APIRouter]:
    """The existing routes BLACKSITE re-serves. Their own permission checks apply, plus the
    owner + fresh-two-factor gate and audit that require() adds inside this app."""
    a = APIRouter(prefix="/api/auth", tags=["blacksite"])
    auth_routes: list[tuple[str, Callable[..., Any], list[str]]] = [
        ("/login", auth.login, ["POST"]),
        ("/logout", auth.logout, ["POST"]),
        ("/logout-all", auth.logout_all, ["POST"]),
        ("/me", auth.me, ["GET"]),
        ("/mfa/verify", auth.mfa_verify, ["POST"]),
    ]
    for path, fn, methods in auth_routes:
        a.add_api_route(path, fn, methods=methods, response_model=None)
    w = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["blacksite"])
    ws_routes: list[tuple[str, Callable[..., Any], list[str], int]] = [
        ("/projects/{project_id}/collections", recon.request_collection, ["POST"], 202),
        ("/operations", recon.list_operations, ["GET"], 200),
        ("/operations/{op_id}", recon.get_operation, ["GET"], 200),
        ("/operations/{op_id}/approve", recon.approve_operation, ["POST"], 200),
        ("/operations/{op_id}/reject", recon.reject_operation, ["POST"], 200),
        ("/operations/{op_id}/cancel", recon.cancel_operation, ["POST"], 200),
        ("/blackops/playbooks", blackops.list_playbooks, ["GET"], 200),
        ("/blackops/projects/{project_id}/preflight", blackops.run_preflight, ["POST"], 200),
        ("/blackops/projects/{project_id}/runs", blackops.launch_run, ["POST"], 201),
        ("/blackops/runs", blackops.list_runs, ["GET"], 200),
        ("/blackops/runs/{run_id}", blackops.get_run, ["GET"], 200),
        ("/blackops/runs/{run_id}/approve", blackops.approve_run, ["POST"], 200),
        ("/blackops/runs/{run_id}/reject", blackops.reject_run, ["POST"], 200),
        ("/blackops/runs/{run_id}/cancel", blackops.cancel_run, ["POST"], 200),
    ]
    for path, fn, methods, code in ws_routes:
        w.add_api_route(path, fn, methods=methods, status_code=code, response_model=None)
    from nightfall.blacksite.probe_routes import router as probes

    # /compare is declared before /{op_id}/... paths; static path first is fine either way.
    return [a, w, router, probes]


def create_blacksite_app() -> FastAPI:
    from nightfall.main import RequestGuard

    app = FastAPI(title="JANUS BLACKSITE", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.blacksite = True  # read by require(): owner + fresh two-factor + audit
    app.add_middleware(RequestGuard, origins=allowed_origins)
    app.add_middleware(HostOnly)  # outermost: runs before anything else
    for r in _curated():
        app.include_router(r)
    return app


def preflight_checks(db_role: str, superuser: bool, bypassrls: bool) -> list[str]:
    """Reasons the listener must not start (empty list = ok)."""
    s = get_settings()
    problems = []
    if not s.blacksite_enabled:
        problems.append("NIGHTFALL_BLACKSITE_ENABLED is not 'true'.")
    if s.on_demand_worker:
        problems.append("BLACKSITE never runs on the hosted platform.")
    if db_role != "nightfall_blacksite" or superuser or bypassrls:
        problems.append(
            f"NIGHTFALL_DATABASE_URL must connect as nightfall_blacksite (got {db_role!r}, "
            f"superuser={superuser}, bypassrls={bypassrls})."
        )
    loopback = s.blacksite_bind in ("127.0.0.1", "::1")
    if not loopback and s.blacksite_allowed_peers == type(s).blacksite_allowed_peers:
        problems.append(
            "A non-loopback bind needs NIGHTFALL_BLACKSITE_ALLOWED_PEERS (the container's "
            "gateway) and the port published to the host's 127.0.0.1 only."
        )
    return problems


def main() -> None:
    """Entry point `nightfall-blacksite`: checks, then serves on the loopback listener."""
    import uvicorn

    from nightfall.core.db.session import get_engine

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    s = get_settings()
    with get_engine().connect() as conn:
        row: Any = conn.execute(
            text(
                "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = current_user"
            )
        ).one()
    if problems := preflight_checks(row[0], row[1], row[2]):
        raise SystemExit("BLACKSITE REFUSED TO START: " + " ".join(problems))
    log.info(
        "BLACKSITE on %s:%d (review %s)",
        s.blacksite_bind,
        s.blacksite_port,
        "recorded" if s.blacksite_review_ref else "NOT recorded: lab execution off",
    )
    uvicorn.run(
        create_blacksite_app(),
        host=s.blacksite_bind,
        port=s.blacksite_port,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()
