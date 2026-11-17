"""SHIELD v3 phase 1: sign-in alerts (migration 0024)."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.test_auth import login


def _alerts(db: Session) -> list[tuple[str, str, int]]:
    db.expire_all()
    return [
        (r.kind, r.severity, r.count)
        for r in db.execute(
            text("SELECT kind, severity::text, count FROM sign_in_alerts ORDER BY kind")
        )
    ]


def test_lockout_raises_one_alert_and_unknown_emails_raise_none(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    for _ in range(5):
        login(client, m.user.email, "not the right password")
    for _ in range(5):
        login(client, "nobody@example.test", "guess")
    assert _alerts(owner_db) == [("signin.locked", "medium", 1)]


def test_correct_password_wrong_code_is_high(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    m = factory.member(factory.workspace(), Role.OWNER)
    assert login(client, m.user.email, code="000000").status_code == 401
    assert login(client, m.user.email, code="000001").status_code == 401
    assert _alerts(owner_db) == [("signin.password_known", "high", 2)]


def test_own_and_admin_views_and_acknowledge(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    victim = factory.sign_in(factory.member(ws, Role.ANALYST))
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    operator = factory.sign_in(factory.member(ws, Role.OPERATOR))
    outsider_ws = factory.workspace("Other")
    outsider = factory.sign_in(factory.member(outsider_ws, Role.OWNER))
    for _ in range(5):
        login(client, victim.user.email, "not the right password")

    mine = use(client, victim).get("/api/auth/sign-in-alerts").json()
    assert [a["kind"] for a in mine] == ["signin.locked"]
    assert mine[0]["addresses"] and mine[0]["state"] == "open"
    alert_id = mine[0]["id"]

    seen = use(client, admin).get(f"/api/workspaces/{ws}/sign-in-alerts").json()
    assert [(a["email"], a["kind"]) for a in seen] == [(victim.user.email, "signin.locked")]
    assert use(client, admin).get("/api/auth/sign-in-alerts").json() == []
    r = use(client, operator).get(f"/api/workspaces/{ws}/sign-in-alerts")
    assert r.status_code == 403
    assert use(client, outsider).get(f"/api/workspaces/{outsider_ws}/sign-in-alerts").json() == []

    # Only the account's own user acknowledges.
    r = use(client, admin).post(f"/api/auth/sign-in-alerts/{alert_id}/acknowledge")
    assert r.status_code == 404
    r = use(client, victim).post(f"/api/auth/sign-in-alerts/{alert_id}/acknowledge")
    assert r.status_code == 200 and r.json()["state"] == "acknowledged"
    assert "auth.sign_in_alert_acknowledged" in audit_actions(owner_db)

    # A new attack opens a new alert; the acknowledged one stays on the record.
    from nightfall.core.identity import throttle

    throttle.login_failures_by_account.clear()
    for _ in range(5):
        login(client, victim.user.email, "not the right password")
    states = sorted(a["state"] for a in use(client, victim).get("/api/auth/sign-in-alerts").json())
    assert states == ["acknowledged", "open"]


def test_repeats_keep_ten_newest_addresses(owner_engine: Engine, factory: Factory) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    with owner_engine.begin() as conn:
        for i in range(14):
            conn.execute(
                text("SELECT nf_record_sign_in_alert(:u, 'signin.locked', :a)"),
                {"u": m.user.id, "a": f"198.51.100.{i}"},
            )
        conn.execute(
            text("SELECT nf_record_sign_in_alert(:u, 'signin.locked', '198.51.100.13')"),
            {"u": m.user.id},
        )
        count, addrs = conn.execute(text("SELECT count, addresses FROM sign_in_alerts")).one()
    assert count == 15
    assert addrs == [f"198.51.100.{i}" for i in range(4, 14)]


def test_app_role_can_only_record_through_the_function(
    app_engine: Engine, factory: Factory
) -> None:
    m = factory.member(factory.workspace(), Role.ANALYST)
    with app_engine.connect() as conn:
        with pytest.raises(DBAPIError):
            conn.execute(
                text(
                    "INSERT INTO sign_in_alerts (user_id, kind, severity) "
                    "VALUES (:u, 'signin.locked', 'low')"
                ),
                {"u": m.user.id},
            )
        conn.rollback()
        with pytest.raises(DBAPIError):
            conn.execute(
                text("SELECT nf_record_sign_in_alert(:u, 'signin.whatever', '')"),
                {"u": m.user.id},
            )
        conn.rollback()
        conn.execute(
            text("SELECT nf_record_sign_in_alert(:u, 'signin.stepup_locked', '')"),
            {"u": m.user.id},
        )
        conn.commit()
        # Without a user or workspace context, the app role reads nothing.
        assert conn.execute(text("SELECT count(*) FROM sign_in_alerts")).scalar_one() == 0
        conn.execute(text("SELECT set_config('app.user_id', :v, false)"), {"v": str(m.user.id)})
        sev = conn.execute(text("SELECT severity::text FROM sign_in_alerts")).scalar_one()
        assert sev == "medium"
        # Severity and count can't be changed by the app role.
        with pytest.raises(DBAPIError):
            conn.execute(text("UPDATE sign_in_alerts SET severity = 'low'"))
        conn.rollback()
        conn.execute(text("SELECT set_config('app.user_id', :v, false)"), {"v": str(uuid.uuid4())})
        assert conn.execute(text("SELECT count(*) FROM sign_in_alerts")).scalar_one() == 0


def test_step_up_lock_raises_alert(client: TestClient, factory: Factory, owner_db: Session) -> None:
    m = factory.sign_in(factory.member(factory.workspace(), Role.OWNER))
    use(client, m)
    for _ in range(5):
        assert client.post("/api/auth/mfa/verify", json={"code": "000000"}).status_code == 400
    assert _alerts(owner_db) == [("signin.stepup_locked", "medium", 1)]
