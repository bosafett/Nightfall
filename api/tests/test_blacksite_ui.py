# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""BLACKSITE operator console: served only by the host-only listener, with a strict CSP,
and backed by read endpoints that only show lab data."""

import re
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from nightfall.blacksite import app as bs_app
from tests.conftest import blacksite_client, use
from tests.test_agents import ai_on, env  # noqa: F401 - fixtures
from tests.test_lab import APP
from tests.test_probes import lab, lab_asset, probe  # noqa: F401 - fixtures

STATIC = Path(bs_app.__file__).parent / "static"


def test_console_is_served_with_a_strict_policy(blacksite: TestClient) -> None:
    for path, kind in (
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/app.css", "text/css"),
    ):
        r = blacksite.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith(kind), path
        csp = r.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert r.headers["x-frame-options"] == "DENY"
    assert blacksite.get("/index.html").status_code == 404
    assert blacksite.get("/static/app.js").status_code == 404


def test_console_is_not_served_publicly(client: TestClient, env) -> None:
    for path in ("/", "/app.js"):
        assert client.get(path).status_code == 404
    with blacksite_client(peer="203.0.113.9") as outside:
        assert outside.get("/").status_code == 404  # host-only check covers the page too


def test_console_never_builds_html_from_strings() -> None:
    js = (STATIC / "app.js").read_text()
    for unsafe in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert unsafe not in js, unsafe
    html = (STATIC / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script"
    assert "style=" not in html and "on" + "click=" not in html


def test_targets_list_lab_assets_with_bounds(
    blacksite: TestClient, env, lab: str, owner_db: Session
) -> None:
    lab_asset(owner_db, env, "172.30.99.20")  # registered but not in the lab scope
    use(blacksite, env["owner"])
    projects = blacksite.get(f"/api/workspaces/{env['ws']}/blacksite/targets").json()
    assets = {a["value"]: a for p in projects for a in p["assets"]}
    assert set(assets) == {APP, "172.30.99.20"}
    assert assets[APP]["in_scope"] and assets[APP]["allowed_ports"] == [80, 443]
    assert assets[APP]["max_rps"] == 1 and assets[APP]["daily_budget"] == 200
    assert assets["172.30.99.20"]["in_scope"] is False


def test_probe_result_endpoint(blacksite: TestClient, env, lab: str) -> None:
    op = probe(blacksite, env, lab, {"type": "tcp", "ports": [80]}).json()
    r = blacksite.get(f"/api/workspaces/{env['ws']}/blacksite/probes/{op['id']}/result").json()
    assert r["operation"]["status"] == "awaiting_approval" and r["record"] is None
