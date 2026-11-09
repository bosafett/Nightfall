# ruff: noqa: F811  (pytest fixtures imported from other test modules)
"""Profile B playbook 7: Authentication Configuration Audit, against fake applications."""

from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import from_posture
from nightfall.blackops.catalog import PLAYBOOKS
from nightfall.config import get_settings
from nightfall.core.clock import utcnow
from nightfall.recon.auth_audit import AuthAudit
from nightfall.recon.collectors import RunContext
from nightfall.recon.safe_http import SafeHttp
from tests.conftest import use
from tests.phase3_helpers import make_worker
from tests.test_ownership import FakeProbes, env, probes  # noqa: F401 - fixtures
from tests.test_profile_b import CANARY, PRIVATE, PUBLIC, TARGET, W, prove, register

USER = "qa-customer@example.com"
FORM = (
    b'<form method="post" action="/login"><input type="hidden" name="csrf" value="t0k">'
    b'<input type="email" name="email"><input type="password" name="pw"></form>'
)


def fake_app(
    *,
    http_redirects: bool = False,
    rotates: bool = False,
    secure_cookie: bool = False,
    logout_kills: bool = False,
    login_status: int | None = None,
    login_body: bytes | None = None,
) -> tuple[Callable[[httpx.Request], httpx.Response], list[tuple[str, str, str]]]:
    seen: list[tuple[str, str, str]] = []
    sessions = {"pre-1"}
    state = {"post_cookie": "pre-1"}

    def flags() -> str:
        return "; Secure; HttpOnly; SameSite=Lax" if secure_cookie else ""

    def handler(req: httpx.Request) -> httpx.Response:
        scheme = req.url.scheme
        seen.append((req.method, scheme, req.url.path))
        cookie = req.headers.get("cookie", "")
        sid = cookie.split("sid=", 1)[1].split(";", 1)[0] if "sid=" in cookie else None
        if login_status is not None and req.method == "POST":
            return httpx.Response(login_status, content=login_body or b"")
        if scheme == "http":
            if http_redirects:
                return httpx.Response(301, headers={"Location": f"https://{TARGET}/login"})
            return httpx.Response(200, content=FORM)
        if req.url.path in ("/login", "/signin") and req.method == "GET":
            return httpx.Response(200, content=FORM, headers={"Set-Cookie": f"sid=pre-1{flags()}"})
        if req.url.path == "/login" and req.method == "POST":
            form = parse_qs(req.content.decode())
            assert form["csrf"] == ["t0k"]
            if form["email"] != [USER] or form["pw"] != [CANARY]:
                return httpx.Response(200, content=FORM)
            new = "post-2" if rotates else "pre-1"
            sessions.add(new)
            if rotates:
                sessions.discard("pre-1")
            state["post_cookie"] = new
            return httpx.Response(
                302, headers={"Location": "/home", "Set-Cookie": f"sid={new}{flags()}"}
            )
        if req.url.path == "/logout":
            if logout_kills:
                sessions.discard(sid or "")
            return httpx.Response(302, headers={"Location": "/login"})
        if req.url.path == "/home":
            if sid in sessions and sid == state["post_cookie"]:
                return httpx.Response(200, content=b'<p>Hi</p><a href="/logout">Log out</a>')
            return httpx.Response(302, headers={"Location": "/login"})
        return httpx.Response(404)

    return handler, seen


def client_for(handler: Callable[[httpx.Request], httpx.Response]) -> SafeHttp:
    return SafeHttp(
        resolver=lambda h: ["127.0.0.1"], allow_private=True, transport=httpx.MockTransport(handler)
    )


IDENT = {
    "label": "low-priv customer",
    "origin": f"https://{TARGET}",
    "login_method": "form",
    "login_path": "/login",
    "username": USER,
    "password": CANARY,
}


def audit(handler, **ident):  # type: ignore[no-untyped-def]
    waits: list[float] = []
    res = AuthAudit(make_client=lambda nets: client_for(handler), sleep=waits.append).run(
        TARGET, RunContext(identity={**IDENT, **ident})
    )
    return res, waits


def checks(res) -> set[str]:  # type: ignore[no-untyped-def]
    return {d.check_id for d in from_posture(res.posture, utcnow())}


def test_form_login_audit_finds_weak_sessions() -> None:
    handler, seen = fake_app()
    res, waits = audit(handler)
    a = res.posture["auth"]
    assert a["authenticated"] and a["stopped"] is None
    assert a["login_over_http"] is True and a["rotated"] is False
    assert a["logout_found"] is True and a["logout_invalidates"] is False
    assert checks(res) == {
        "auth.login-page-over-http",
        "auth.session-cookie-not-secure.sid",
        "auth.session-cookie-not-httponly.sid",
        "auth.session-cookie-no-samesite.sid",
        "auth.session-not-rotated",
        "auth.logout-not-invalidating",
    }
    # One POST, to the registered login path; everything else GET. Paced at 1 per second.
    assert [m for m, _, _ in seen].count("POST") == 1
    assert ("POST", "https", "/login") in seen and len(seen) == a["requests"] <= 10
    assert len(waits) == len(seen) - 1
    # The credential, the username and session values are never stored.
    for secret in (CANARY.encode(), USER.encode(), b"pre-1"):
        assert secret not in res.raw
    assert b"<test-identity:low-priv customer>" in res.raw


def test_well_configured_app_produces_no_findings() -> None:
    handler, _ = fake_app(http_redirects=True, rotates=True, secure_cookie=True, logout_kills=True)
    res, _ = audit(handler)
    a = res.posture["auth"]
    assert a["authenticated"] and a["rotated"] is True and a["logout_invalidates"] is True
    assert checks(res) == set()


@pytest.mark.parametrize(
    ("kwargs", "words"),
    [
        ({"login_status": 429}, "429"),
        ({"login_status": 200, "login_body": b"Your account is locked."}, "locked"),
        ({"login_status": 401}, "didn't succeed"),
    ],
)
def test_stop_conditions(kwargs: dict, words: str) -> None:
    handler, seen = fake_app(http_redirects=True, **kwargs)
    res, _ = audit(handler)
    assert words in (res.posture["auth"]["stopped"] or "")
    assert checks(res) == set()  # nothing about the session is judged from a stopped run
    assert [m for m, _, _ in seen].count("POST") <= 1


def test_refuses_other_endpoints_and_other_targets() -> None:
    handler, seen = fake_app()
    res, _ = audit(handler, login_path="/signin")  # the form posts to /login, not /signin
    assert "registered login path" in (res.posture["auth"]["stopped"] or "")
    assert all(m == "GET" for m, _, _ in seen)
    from nightfall.recon.safe_http import Refused

    with pytest.raises(Refused):
        audit(handler, origin="https://other.test")


def test_basic_auth_over_http_is_reported() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if "authorization" in req.headers and req.url.scheme == "https":
            return httpx.Response(200)
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="x"'})

    res, _ = audit(handler, login_method="basic", login_path="/admin")
    assert res.posture["auth"]["authenticated"] and checks(res) == {"auth.basic-over-http"}
    assert CANARY.encode() not in res.raw


# --- End to end: Profile B run, approval, worker, findings -----------------------------------


@pytest.fixture
def live_gates(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    for k, v in {
        "NIGHTFALL_PROFILE_B_ENABLED": "true",
        "NIGHTFALL_PROFILE_B_REVIEW_REF": "PB-REVIEW-1",
        "NIGHTFALL_PROFILE_B_PUBLIC_KEY": PUBLIC,
        "NIGHTFALL_PROFILE_B_PRIVATE_KEY": PRIVATE,
        "NIGHTFALL_COLLECTOR_MODE": "live",
        "NIGHTFALL_WORKER_MODE": "profile-b",
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    make_worker(profile_b=True).heartbeat()  # the self-hosted Profile B worker is online
    yield
    get_settings.cache_clear()


def test_profile_b_run_end_to_end(
    client: TestClient, env: dict, owner_db: Session, probes: FakeProbes, live_gates: None
) -> None:
    p = PLAYBOOKS["authentication-configuration-audit"]
    ident = register(client, env, username=USER).json()
    prove(client, env, probes)
    body = {
        "playbook_id": p.id, "target": TARGET, "identity_ids": [ident["id"]],
        "version": p.version, "definition_sha256": p.sha256,
    }  # fmt: skip
    r = client.post(f"{W(env)}/blackops/projects/{env['pid']}/runs", json=body)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    op = owner_db.execute(text("SELECT risk_class, is_lab, status FROM operations")).one()
    assert (op.risk_class, op.is_lab, op.status) == ("moderate", False, "awaiting_approval")
    owner_db.execute(text("UPDATE workspaces SET approval_policy = 'single_operator'"))
    owner_db.commit()
    assert (
        client.post(f"{W(env)}/blackops/runs/{run_id}/approve", json={"reason": "ok"}).status_code
        == 200
    )

    handler, seen = fake_app()
    worker = make_worker(
        {
            "auth-audit": AuthAudit(
                make_client=lambda nets: client_for(handler), sleep=lambda s: None
            )
        },
        profile_b=True,
    )
    while worker.run_once():
        pass
    status = owner_db.execute(text("SELECT status, error FROM operations")).one()
    assert status.status == "succeeded", status
    titles = set(owner_db.execute(text("SELECT check_id FROM findings")).scalars())
    assert "auth.session-not-rotated" in titles and "auth.logout-not-invalidating" in titles
    assert set(owner_db.execute(text("SELECT validation_status FROM findings")).scalars()) == {
        "unverified"
    }
    # The credential reached the fake app (so it was opened) but nothing stored holds it.
    assert ("POST", "https", "/login") in seen
    blobs = owner_db.execute(text("SELECT content FROM evidence_blobs")).scalars().all()
    stored = b"".join(bytes(b) for b in blobs)
    from pathlib import Path

    from tests.phase3_helpers import EVIDENCE_DIR

    for f in Path(EVIDENCE_DIR).rglob("*"):
        if f.is_file():
            stored += f.read_bytes()
    assert CANARY.encode() not in stored and USER.encode() not in stored
    audit_rows = owner_db.execute(text("SELECT data::text FROM audit_events")).scalars().all()
    assert not any(CANARY in d or USER in d for d in audit_rows)


def test_auth_audit_never_runs_outside_profile_b(
    client: TestClient, env: dict, app_engine: Engine, owner_db: Session
) -> None:
    # Not offered as a collection, and the schema refuses moderate risk outside the lab
    # unless the operation is a step of a Profile B run.
    use(client, env["owner"])
    r = client.post(
        f"{W(env)}/projects/{env['pid']}/collections", json={"tool": "auth-audit", "target": TARGET}
    )
    assert r.status_code == 422
    user = owner_db.execute(text("SELECT id FROM users LIMIT 1")).scalar_one()
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        with pytest.raises(DBAPIError, match="Profile B"):
            with conn.begin():
                conn.execute(
                    text(
                        "INSERT INTO operations (workspace_id, project_id, scope_id, tool, "
                        "risk_class, target_value, requested_by_user_id) VALUES (:w, :p, :s, "
                        "'auth-audit', 'moderate', :t, :u)"
                    ),
                    {
                        "w": env["ws"],
                        "p": env["pid"],
                        "s": env["scope"]["id"],
                        "t": TARGET,
                        "u": user,
                    },
                )
