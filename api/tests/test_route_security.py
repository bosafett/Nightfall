"""Every API route must declare authentication or a workspace permission, unless it is
explicitly listed as public. New routes fail this test until they do."""

from typing import Any

from fastapi.routing import APIRoute

from nightfall.core.identity.routes import PUBLIC_ROUTES
from nightfall.main import HEALTH_ROUTES, ROUTERS, create_app


def _has_authz(dependant: Any) -> bool:
    for dep in dependant.dependencies:
        if getattr(dep.call, "_nf_authz", False) or _has_authz(dep):
            return True
    return False


def _routes() -> list[APIRoute]:
    routes = [r for router in ROUTERS for r in router.routes if isinstance(r, APIRoute)]
    assert len(routes) > 20  # guard against the walk silently finding nothing
    return routes


def test_router_list_covers_the_whole_api() -> None:
    documented = set(create_app().openapi()["paths"])
    assert documented == {r.path for r in _routes()}


def test_all_routes_are_protected_or_explicitly_public() -> None:
    allowed = PUBLIC_ROUTES | HEALTH_ROUTES
    unprotected = []
    for route in _routes():
        for method in route.methods:
            if (method, route.path) not in allowed and not _has_authz(route.dependant):
                unprotected.append(f"{method} {route.path}")
    assert unprotected == []


def test_public_routes_exist() -> None:
    paths = {(m, r.path) for r in _routes() for m in r.methods}
    assert paths >= (PUBLIC_ROUTES | HEALTH_ROUTES)


def test_health(client: Any) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert {c["name"]: c["status"] for c in body["components"]} == {"api": "ok", "database": "ok"}
