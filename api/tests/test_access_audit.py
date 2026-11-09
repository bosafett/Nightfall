# ruff: noqa: F811  (pytest fixtures imported from other test modules)
"""Profile B playbook 8: Access-Control Assessment, against a fake application."""

from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import from_posture
from nightfall.blackops.catalog import PLAYBOOKS
from nightfall.core.clock import utcnow
from nightfall.recon.access_audit import AccessAudit, valid_paths
from nightfall.recon.collectors import RunContext
from nightfall.recon.safe_http import Refused
from tests.phase3_helpers import make_worker
from tests.test_auth_audit import client_for, live_gates  # noqa: F401 - fixture
from tests.test_ownership import FakeProbes, env, probes  # noqa: F401 - fixtures
from tests.test_profile_b import TARGET, W, prove, register

FORM = (
    b'<form method="post" action="/login"><input type="email" name="email">'
    b'<input type="password" name="pw"></form>'
)
USERS = {
    "admin@example.com": ("Adm1n-canary", "admin"),
    "user@example.com": ("Us3r-canary", "user"),
}
PAGES = {
    "/admin/users": {"admin": b"ALL USERS", "user": b"ALL USERS", None: None},  # broken
    "/admin/billing": {"admin": b"BILLING", "user": None, None: b"public billing"},  # leak
    "/admin/settings": {"admin": b"SETTINGS", "user": None, None: None},  # fine
    "/missing": {},  # the higher role can't see it either: not judged
}


def app(seen: list[tuple[str, str]]):  # type: ignore[no-untyped-def]
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path))
        cookie = req.headers.get("cookie", "")
        role = cookie.split("sid=", 1)[1].split("-", 1)[0] if "sid=" in cookie else None
        if req.url.path == "/login" and req.method == "GET":
            return httpx.Response(200, content=FORM)
        if req.url.path == "/login" and req.method == "POST":
            f = parse_qs(req.content.decode())
            email, pw = f["email"][0], f["pw"][0]
            if USERS.get(email, ("", ""))[0] != pw:
                return httpx.Response(200, content=FORM)
            r = USERS[email][1]
            return httpx.Response(302, headers={"Location": "/", "Set-Cookie": f"sid={r}-s"})
        views = PAGES.get(req.url.path)
        if not views:
            return httpx.Response(404)
        body = views.get(role)
        if body is None:
            return httpx.Response(302, headers={"Location": "/login"})
        return httpx.Response(200, content=body)

    return handler


def ident(label: str, email: str) -> dict[str, str]:
    return {
        "label": label, "origin": f"https://{TARGET}", "login_method": "form",
        "login_path": "/login", "username": email, "password": USERS[email][0],
    }  # fmt: skip


HIGH, LOW = ident("admin", "admin@example.com"), ident("customer", "user@example.com")


def run(paths, ids=(HIGH, LOW)):  # type: ignore[no-untyped-def]
    seen: list[tuple[str, str]] = []
    res = AccessAudit(make_client=lambda n: client_for(app(seen)), sleep=lambda s: None).run(
        TARGET, RunContext(identities=list(ids), params={"paths": paths})
    )
    return res, seen


def test_compares_three_views_of_each_path() -> None:
    res, seen = run(list(PAGES))
    a = res.posture["access"]
    rows = {r["path"]: r for r in a["paths"]}
    assert rows["/admin/users"]["lower_access"] and rows["/admin/users"]["lower_same"]
    assert not rows["/admin/users"]["anonymous_access"]
    assert (
        rows["/admin/billing"]["anonymous_access"] and not rows["/admin/billing"]["anonymous_same"]
    )
    assert (
        not rows["/admin/settings"]["lower_access"]
        and not rows["/admin/settings"]["anonymous_access"]
    )
    assert rows["/missing"]["baseline"] is False
    drafts = {d.check_id: d for d in from_posture(res.posture, utcnow())}
    assert set(drafts) == {"access.lower-role./admin/users", "access.no-session./admin/billing"}
    assert drafts["access.lower-role./admin/users"].severity.value == "high"
    assert drafts["access.no-session./admin/billing"].severity.value == "medium"
    # One sign-in POST per identity, everything else GET; three GETs per path.
    assert [m for m, _ in seen].count("POST") == 2
    assert sum(1 for m, p in seen if m == "GET" and p != "/login") == 3 * len(PAGES)
    # Nothing stored but statuses and short hashes: no bodies, cookies or credentials.
    for secret in (b"ALL USERS", b"BILLING", b"admin-s", b"Adm1n-canary", b"Us3r-canary",
                   b"admin@example.com"):  # fmt: skip
        assert secret not in res.raw


@pytest.mark.parametrize(
    "bad", [[], ["http://x/admin"], ["//evil.test/x"], ["admin"], ["/a b"], ["/x#y"],
            [f"/p{i}" for i in range(51)]],
)  # fmt: skip
def test_paths_are_checked(bad: list[str]) -> None:
    with pytest.raises(ValueError):
        valid_paths(bad)
    assert valid_paths(["/a", "/a", "/b?x=1"]) == ["/a", "/b?x=1"]


def test_needs_two_identities_of_this_target() -> None:
    with pytest.raises(Refused, match="exactly two"):
        run(["/admin/users"], ids=(HIGH,))
    other = {**LOW, "origin": "https://other.test"}
    with pytest.raises(Refused, match="origin"):
        run(["/admin/users"], ids=(HIGH, other))


def test_profile_b_access_run_end_to_end(
    client: TestClient, env: dict, owner_db: Session, probes: FakeProbes, live_gates: None
) -> None:
    p = PLAYBOOKS["access-control-assessment"]
    hi = register(
        client,
        env,
        label="admin",
        username="admin@example.com",
        password=USERS["admin@example.com"][0],
    ).json()  # noqa: E501
    lo = register(
        client,
        env,
        label="customer",
        username="user@example.com",
        password=USERS["user@example.com"][0],
    ).json()  # noqa: E501
    prove(client, env, probes)
    url = f"{W(env)}/blackops/projects/{env['pid']}"
    pre = client.post(
        f"{url}/preflight",
        json={"playbook_id": p.id, "target": TARGET, "identity_ids": [hi["id"], lo["id"]]},
    ).json()
    assert {c["key"]: c["status"] for c in pre["checks"]}["paths"] == "fail"  # none given
    body = {
        "playbook_id": p.id, "target": TARGET, "identity_ids": [hi["id"], lo["id"]],
        "paths": list(PAGES), "version": p.version, "definition_sha256": p.sha256,
    }  # fmt: skip
    r = client.post(f"{url}/runs", json=body)
    assert r.status_code == 201, r.text
    params = owner_db.execute(text("SELECT params FROM operations")).scalar_one()
    assert params["paths"] == list(PAGES)
    owner_db.execute(text("UPDATE workspaces SET approval_policy = 'single_operator'"))
    owner_db.commit()
    assert (
        client.post(
            f"{W(env)}/blackops/runs/{r.json()['id']}/approve", json={"reason": "ok"}
        ).status_code
        == 200
    )  # noqa: E501
    seen: list[tuple[str, str]] = []
    worker = make_worker(
        {
            "access-audit": AccessAudit(
                make_client=lambda n: client_for(app(seen)), sleep=lambda s: None
            )
        },
        profile_b=True,
    )
    while worker.run_once():
        pass
    assert owner_db.execute(text("SELECT status FROM operations")).scalar_one() == "succeeded"
    checks = set(owner_db.execute(text("SELECT check_id FROM findings")).scalars())
    assert checks == {"access.lower-role./admin/users", "access.no-session./admin/billing"}
    assert [m for m, _ in seen].count("POST") == 2  # both identities were opened and used
