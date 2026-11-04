from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.core.identity.deps import SESSION_COOKIE
from tests.conftest import ORIGIN, PASSWORD, Factory, audit_actions, current_code, use


def login(client: TestClient, email: str, password: str = PASSWORD, code: str | None = None):
    body = {"email": email, "password": password}
    if code:
        body["totp_code"] = code
    return client.post("/api/auth/login", json=body)


def test_login_sets_httponly_cookie_and_me_works(client: TestClient, factory: Factory) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    r = login(client, m.user.email.upper())  # emails are case-insensitive
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    me = client.get("/api/auth/me").json()
    assert me["user"]["email"] == m.user.email
    assert me["workspaces"][0]["role"] == "analyst"


def test_bad_credentials_are_indistinguishable(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    wrong = login(client, m.user.email, "not the right password")
    unknown = login(client, "nobody@example.test")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert audit_actions(owner_db).count("auth.login_failed") == 2


def test_lockout_after_repeated_failures(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    for _ in range(5):
        assert login(client, m.user.email, "not the right password").status_code == 401
    r = login(client, m.user.email)  # correct password, still locked
    assert r.status_code == 429
    assert "auth.login_throttled" in audit_actions(owner_db)


def test_mfa_login_requires_valid_unused_code(client: TestClient, factory: Factory) -> None:
    m = factory.member(factory.workspace(), Role.OWNER)
    assert m.totp_secret
    r = login(client, m.user.email)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "mfa_required"
    assert login(client, m.user.email, code="000000").status_code == 401
    code = current_code(m.totp_secret)
    r = login(client, m.user.email, code=code)
    assert r.status_code == 200 and r.json()["session"]["mfa_verified"] is True
    client.cookies.clear()
    replay = login(client, m.user.email, code=code)
    assert replay.status_code == 401 and replay.json()["detail"]["code"] == "invalid_mfa_code"


def test_logout_revokes_session(client: TestClient, factory: Factory) -> None:
    m = factory.sign_in(factory.member(factory.workspace(), Role.ANALYST))
    use(client, m)
    assert client.get("/api/auth/me").status_code == 200
    token = m.token
    assert client.post("/api/auth/logout").status_code == 200
    client.cookies.set(SESSION_COOKIE, token or "")
    assert client.get("/api/auth/me").status_code == 401


def test_logout_all_revokes_every_session(client: TestClient, factory: Factory) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    first = factory.sign_in(m).token
    second = factory.sign_in(m).token
    client.cookies.set(SESSION_COOKIE, second or "")
    assert client.post("/api/auth/logout-all").status_code == 200
    client.cookies.set(SESSION_COOKIE, first or "")
    assert client.get("/api/auth/me").status_code == 401


def test_expired_idle_and_disabled_sessions_rejected(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    m = factory.sign_in(factory.member(factory.workspace(), Role.ANALYST))
    use(client, m)
    assert client.get("/api/auth/me").status_code == 200
    owner_db.execute(text("UPDATE sessions SET last_seen_at = now() - interval '13 hours'"))
    owner_db.commit()
    assert client.get("/api/auth/me").status_code == 401

    m2 = factory.sign_in(factory.member(m.workspace_id, Role.VIEWER))
    use(client, m2)
    owner_db.execute(text("UPDATE users SET is_disabled = true WHERE id = :u"), {"u": m2.user.id})
    owner_db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_mutations_require_matching_origin(client: TestClient, factory: Factory) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    body = {"email": m.user.email, "password": PASSWORD}
    r = client.post("/api/auth/login", json=body, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "bad_origin"
    client.headers.pop("Origin")
    assert client.post("/api/auth/login", json=body).status_code == 403
    client.headers["Origin"] = ORIGIN


def test_mfa_enrollment(client: TestClient, factory: Factory) -> None:
    m = factory.sign_in(factory.member(factory.workspace(), Role.OWNER, mfa=False))
    use(client, m)
    setup = client.post("/api/auth/mfa/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/NIGHTFALL")
    assert client.post("/api/auth/mfa/confirm", json={"code": "000000"}).status_code == 400
    code = pyotp.TOTP(setup["secret"]).now()
    r = client.post("/api/auth/mfa/confirm", json={"code": code})
    assert r.status_code == 200
    assert r.json()["user"]["mfa_enabled"] and r.json()["session"]["mfa_verified"]
    assert client.post("/api/auth/mfa/setup").status_code == 409
    # The confirmed session now satisfies the owner's MFA requirement.
    assert client.get(f"/api/workspaces/{m.workspace_id}").status_code == 200


def test_admin_issued_password_reset(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    target = factory.member(ws, Role.ANALYST)
    old_session = factory.sign_in(target).token
    use(client, admin)
    link = client.post(f"/api/workspaces/{ws}/members/{target.member_id}/password-reset").json()
    token = link["url"].split("#token=")[1]
    assert link["url"].startswith(f"{ORIGIN}/reset-password#token=")

    client.cookies.clear()
    new_pw = "a brand new long password"
    weak = client.post("/api/auth/password-reset", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422
    ok = client.post("/api/auth/password-reset", json={"token": token, "new_password": new_pw})
    assert ok.status_code == 200
    again = client.post("/api/auth/password-reset", json={"token": token, "new_password": new_pw})
    assert again.status_code == 400  # single use
    client.cookies.set(SESSION_COOKIE, old_session or "")
    assert client.get("/api/auth/me").status_code == 401  # sessions revoked
    client.cookies.clear()
    assert login(client, target.user.email, new_pw).status_code == 200
    assert "auth.password_reset_completed" in audit_actions(owner_db)


def test_expired_reset_token_rejected(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    target = factory.member(ws, Role.VIEWER)
    use(client, admin)
    url = client.post(f"/api/workspaces/{ws}/members/{target.member_id}/password-reset").json()
    owner_db.execute(text("UPDATE auth_tokens SET expires_at = now() - interval '1 minute'"))
    owner_db.commit()
    client.cookies.clear()
    r = client.post(
        "/api/auth/password-reset",
        json={"token": url["url"].split("#token=")[1], "new_password": "another long password"},
    )
    assert r.status_code == 400


def test_invite_new_user(client: TestClient, factory: Factory, owner_db: Session) -> None:
    ws = factory.workspace("Raccoon Ops")
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    use(client, admin)
    created = client.post(
        f"/api/workspaces/{ws}/invites",
        json={"email": "New.Person@Example.test", "role": "analyst"},
    )
    assert created.status_code == 201
    token = created.json()["link"]["url"].split("#token=")[1]
    assert len(client.get(f"/api/workspaces/{ws}/invites").json()) == 1

    client.cookies.clear()
    info = client.get(f"/api/auth/invites/{token}").json()
    assert info == {
        "workspace_name": "Raccoon Ops",
        "email": "new.person@example.test",
        "role": "analyst",
        "existing_account": False,
    }
    r = client.post(
        "/api/auth/accept-invite",
        json={"token": token, "password": PASSWORD, "display_name": "New Person"},
    )
    assert r.status_code == 200 and r.json()["signed_in"] is True
    me = client.get("/api/auth/me").json()
    assert me["workspaces"][0]["role"] == "analyst"
    reuse = client.post(
        "/api/auth/accept-invite", json={"token": token, "password": PASSWORD, "display_name": "X"}
    )
    assert reuse.status_code == 400
    assert "member.joined" in audit_actions(owner_db)


def test_invite_existing_user_needs_password_and_no_session(
    client: TestClient, factory: Factory
) -> None:
    ws_a, ws_b = factory.workspace("A"), factory.workspace("B")
    existing = factory.member(ws_a, Role.OWNER)  # has MFA
    admin = factory.sign_in(factory.member(ws_b, Role.ADMIN))
    use(client, admin)
    token = (
        client.post(
            f"/api/workspaces/{ws_b}/invites", json={"email": existing.user.email, "role": "viewer"}
        )
        .json()["link"]["url"]
        .split("#token=")[1]
    )
    client.cookies.clear()
    bad = client.post(
        "/api/auth/accept-invite", json={"token": token, "password": "wrong password!"}
    )
    assert bad.status_code == 401
    ok = client.post("/api/auth/accept-invite", json={"token": token, "password": PASSWORD})
    assert ok.status_code == 200 and ok.json()["signed_in"] is False
    assert SESSION_COOKIE not in client.cookies


def test_session_absolute_expiry(client: TestClient, factory: Factory, owner_db: Session) -> None:
    m = factory.sign_in(factory.member(factory.workspace(), Role.ANALYST))
    owner_db.execute(
        text("UPDATE sessions SET expires_at = now() - :d"), {"d": timedelta(seconds=1)}
    )
    owner_db.commit()
    use(client, m)
    assert client.get("/api/auth/me").status_code == 401
