# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""BLACKSITE security foundation (JANUS Phase 1): negative tests first.

Layers: feature flag, host-only network path, owner + fresh two-factor, confined database
role, lab boundary for the hosted app, review gate, audit of every refusal.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.blacksite.app import preflight_checks
from nightfall.config import ConfigError, _sqlalchemy_url, get_settings, load_settings
from tests.conftest import (
    APP_URL,
    BLACKSITE_URL,
    blacksite_client,
    current_code,
    use,
)
from tests.test_agents import ai_on, env  # noqa: F401 - fixtures
from tests.test_lab import APP, _active_lab_scope

_bs_engine = create_engine(_sqlalchemy_url(BLACKSITE_URL))
_app_engine = create_engine(_sqlalchemy_url(APP_URL))


def status_url(env) -> str:
    return f"/api/workspaces/{env['ws']}/blacksite/status"


def denials(db: Session, action: str = "authz.denied") -> list[str]:
    db.expire_all()
    return list(
        db.execute(
            text("SELECT data->>'reason' FROM audit_events WHERE action = :a"), {"a": action}
        ).scalars()
    )


def stale_mfa(db: Session, minutes: int = 16) -> None:
    db.execute(
        text("UPDATE sessions SET mfa_verified_at = now() - make_interval(mins => :m)"),
        {"m": minutes},
    )
    db.commit()


# --- Not reachable from the public app -----------------------------------------------


def test_public_app_has_no_blacksite_routes(client: TestClient, env) -> None:
    use(client, env["owner"])
    assert client.get(status_url(env)).status_code == 404
    assert not [r for r in client.app.routes if "blacksite" in getattr(r, "path", "")]


def test_disabled_by_default_fails_closed(env, owner_db: Session) -> None:
    get_settings.cache_clear()
    with blacksite_client() as bs:
        use(bs, env["owner"])
        r = bs.get(status_url(env))
    assert r.status_code == 404 and r.json()["detail"]["code"] == "not_host_access"
    assert "disabled" in denials(owner_db, "blacksite.network_denied")


def test_flag_is_refused_on_the_hosted_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIGHTFALL_BLACKSITE_ENABLED", "true")
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    with pytest.raises(ConfigError, match="hosted platform"):
        load_settings()


# --- Network path --------------------------------------------------------------------


@pytest.mark.parametrize("peer", ["203.0.113.5", "10.0.0.7", "testclient"])
def test_non_loopback_peers_are_refused(blacksite_on, env, owner_db: Session, peer: str) -> None:
    with blacksite_client(peer=peer) as bs:
        use(bs, env["owner"])
        # Forwarded headers are never trusted as proof of host access.
        r = bs.get(
            status_url(env), headers={"X-Forwarded-For": "127.0.0.1", "Forwarded": "for=127.0.0.1"}
        )
    assert r.status_code == 404
    assert "peer" in denials(owner_db, "blacksite.network_denied")


def test_foreign_host_header_is_refused(blacksite_on, env, owner_db: Session) -> None:
    """A web page using DNS rebinding reaches 127.0.0.1 with its own Host name."""
    with blacksite_client(base_url="http://attacker.test:8443") as bs:
        use(bs, env["owner"])
        assert bs.get(status_url(env)).status_code == 404
    assert "host" in denials(owner_db, "blacksite.network_denied")


def test_mutations_need_the_loopback_origin(blacksite: TestClient, env) -> None:
    use(blacksite, env["owner"])
    r = blacksite.post("/api/auth/logout", headers={"Origin": "https://janus.example"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "bad_origin"


# --- Identity ------------------------------------------------------------------------


def test_unauthenticated_and_non_owner_are_refused(
    blacksite: TestClient, env, owner_db: Session
) -> None:
    assert blacksite.get(status_url(env)).status_code == 401
    for who in ("operator", "analyst", "viewer"):
        use(blacksite, env[who])
        r = blacksite.get(status_url(env))
        assert r.status_code == 403, who
    assert "blacksite_owner_only" in denials(owner_db)


def test_owner_access_is_audited_and_uses_the_confined_role(
    blacksite: TestClient, env, owner_db: Session
) -> None:
    use(blacksite, env["owner"])
    r = blacksite.get(status_url(env))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["database_role"] == "nightfall_blacksite"
    assert body["review_recorded"] is True and body["approval_policy"] == "single_operator"
    row = owner_db.execute(
        text("SELECT actor_id, data FROM audit_events WHERE action = 'blacksite.access'")
    ).one()
    assert row[0] == env["owner"].user.id and row[1]["path"].endswith("/blacksite/status")


def test_stale_or_missing_two_factor_needs_a_step_up(
    blacksite: TestClient, env, owner_db: Session
) -> None:
    use(blacksite, env["owner"])
    stale_mfa(owner_db)
    r = blacksite.get(status_url(env))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "step_up_required"
    assert "mfa_stale" in denials(owner_db)

    bad = blacksite.post("/api/auth/mfa/verify", json={"code": "000000"})
    assert bad.status_code == 400
    owner_db.expire_all()
    assert (
        owner_db.execute(
            text("SELECT count(*) FROM audit_events WHERE action = 'auth.mfa_failed'")
        ).scalar_one()
        == 1
    )

    ok = blacksite.post(
        "/api/auth/mfa/verify", json={"code": current_code(env["owner"].totp_secret)}
    )
    assert ok.status_code == 200, ok.text
    assert blacksite.get(status_url(env)).status_code == 200
    # The same code can't be replayed for another step-up.
    again = blacksite.post(
        "/api/auth/mfa/verify", json={"code": current_code(env["owner"].totp_secret)}
    )
    assert again.status_code == 400

    owner_db.execute(text("UPDATE sessions SET mfa_verified_at = NULL"))
    owner_db.commit()
    assert blacksite.get(status_url(env)).status_code == 403


def test_expired_and_revoked_sessions(blacksite: TestClient, env, owner_db: Session) -> None:
    use(blacksite, env["owner"])
    assert blacksite.post("/api/auth/logout-all").status_code == 200
    assert blacksite.get(status_url(env)).status_code == 401
    assert "auth.logout_all" in [
        a for (a,) in owner_db.execute(text("SELECT action FROM audit_events"))
    ]
    other = env["operator"]
    owner_db.execute(
        text("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE user_id = :u"),
        {"u": other.user.id},
    )
    owner_db.commit()
    use(blacksite, other)
    assert blacksite.get(status_url(env)).status_code == 401


# --- Lab boundary and review gate ----------------------------------------------------


def test_blacksite_acts_on_lab_work_only(blacksite: TestClient, env, owner_db: Session) -> None:
    use(blacksite, env["owner"])
    r = blacksite.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "dns", "target": "www.example.com"},
    )
    # The confined role can't even see the non-lab project's scope.
    assert r.status_code in (403, 404, 422)
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0


def test_lab_execution_needs_the_recorded_review(
    client: TestClient, env, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _active_lab_scope(client, env)
    monkeypatch.setenv("NIGHTFALL_BLACKSITE_ENABLED", "true")
    monkeypatch.delenv("NIGHTFALL_BLACKSITE_REVIEW_REF", raising=False)
    get_settings.cache_clear()
    try:
        with blacksite_client() as bs:
            use(bs, env["owner"])
            assert bs.get(status_url(env)).json()["review_recorded"] is False
            r = bs.post(
                f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
                json={"tool": "http", "target": APP},
            )
    finally:
        get_settings.cache_clear()
    assert r.status_code == 403 and r.json()["detail"]["code"] == "review_required"
    assert "review_not_recorded" in denials(owner_db)
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0


def test_hosted_app_refusals_are_audited(client: TestClient, env, owner_db: Session) -> None:
    _active_lab_scope(client, env)
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": APP},
    )
    assert r.status_code == 403 and r.json()["detail"]["code"] == "lab_from_blacksite"
    assert "lab_outside_blacksite" in denials(owner_db)


# --- Database permission boundaries --------------------------------------------------


def _ctx(db: Session, ws: object) -> None:
    db.execute(text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(ws)})


def test_hosted_role_cannot_create_or_approve_lab_work(
    client: TestClient, blacksite: TestClient, env, owner_db: Session
) -> None:
    _active_lab_scope(client, env)
    use(blacksite, env["owner"])
    op = blacksite.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": APP},
    ).json()
    with Session(_app_engine) as db:
        _ctx(db, env["ws"])
        with pytest.raises(DBAPIError, match="row-level security"):
            db.execute(
                text(
                    "INSERT INTO operations (workspace_id, project_id, scope_id, tool, "
                    "risk_class, target_value, is_lab) SELECT workspace_id, project_id, "
                    "scope_id, 'http', 'low', '172.30.99.11', true FROM operations"
                )
            )
        db.rollback()
        _ctx(db, env["ws"])
        changed = db.execute(text("UPDATE operations SET status = 'queued' WHERE is_lab"))
        assert changed.rowcount == 0  # type: ignore[attr-defined]
        db.rollback()
        _ctx(db, env["ws"])
        with pytest.raises(DBAPIError, match="row-level security"):
            db.execute(
                text(
                    "INSERT INTO approvals (workspace_id, operation_id, approver_user_id, "
                    "decision, scope_id_at_decision) VALUES (:w, :o, :u, 'approved', "
                    "(SELECT scope_id FROM operations WHERE id = :o))"
                ),
                {"w": env["ws"], "o": op["id"], "u": env["owner"].user.id},
            )
        db.rollback()


def test_blacksite_role_is_confined(client: TestClient, env, owner_db: Session) -> None:
    use(client, env["owner"])
    client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "ct", "target": "example.com"},
    )
    with Session(_bs_engine) as db:
        _ctx(db, env["ws"])
        assert db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0
        assert db.execute(text("SELECT count(*) FROM scopes")).scalar_one() == 0
        assert db.execute(text("SELECT count(*) FROM projects")).scalar_one() == 0
        for stmt in (
            "UPDATE audit_events SET action = 'x'",
            "DELETE FROM audit_events",
            "SELECT 1 FROM audit_events",
            "SELECT 1 FROM evidence_blobs",
            "SELECT 1 FROM auth_tokens",
            "SELECT 1 FROM agent_tasks",
            "SELECT 1 FROM attack_paths",
            "INSERT INTO workspace_members (workspace_id, user_id, role) "
            "SELECT workspace_id, user_id, 'owner' FROM workspace_members",
        ):
            with pytest.raises(DBAPIError, match="permission denied"):
                db.execute(text(stmt))
            db.rollback()
            _ctx(db, env["ws"])
        with pytest.raises(DBAPIError, match="row-level security"):
            db.execute(
                text(
                    "INSERT INTO operations (workspace_id, project_id, scope_id, tool, "
                    "risk_class, target_value, is_lab) VALUES (:w, :p, "
                    "(SELECT id FROM scopes LIMIT 1), 'ct', 'passive', 'example.com', false)"
                ),
                {"w": env["ws"], "p": env["pid"]},
            )
        db.rollback()


def test_start_up_checks() -> None:
    import dataclasses

    from nightfall.blacksite import app as bs_app

    base = dataclasses.replace(get_settings(), blacksite_enabled=True)
    for settings, role, su, bypass, expect in (
        (base, "nightfall_blacksite", False, False, None),
        (base, "nightfall_app", False, False, "must connect as nightfall_blacksite"),
        (base, "nightfall_blacksite", True, False, "must connect as nightfall_blacksite"),
        (
            dataclasses.replace(base, blacksite_enabled=False),
            "nightfall_blacksite",
            False,
            False,
            "not 'true'",
        ),
        (
            dataclasses.replace(base, on_demand_worker=True),
            "nightfall_blacksite",
            False,
            False,
            "hosted platform",
        ),
        (
            dataclasses.replace(base, blacksite_bind="0.0.0.0"),  # noqa: S104
            "nightfall_blacksite",
            False,
            False,
            "ALLOWED_PEERS",
        ),
    ):
        original = bs_app.get_settings
        bs_app.get_settings = lambda s=settings: s  # type: ignore[assignment]
        try:
            problems = preflight_checks(role, su, bypass)
        finally:
            bs_app.get_settings = original  # type: ignore[assignment]
        if expect is None:
            assert problems == []
        else:
            assert any(expect in p for p in problems), problems


def test_owner_signs_in_through_the_listener(blacksite: TestClient, env, owner_db: Session) -> None:
    """Sign-in works with the confined role, and a fresh sign-in counts as fresh two-factor."""
    from tests.conftest import PASSWORD

    blacksite.cookies.clear()
    owner = env["owner"]
    r = blacksite.post(
        "/api/auth/login",
        json={
            "email": owner.user.email,
            "password": PASSWORD,
            "totp_code": current_code(owner.totp_secret),
        },
    )
    assert r.status_code == 200, r.text
    assert blacksite.get(status_url(env)).status_code == 200
    bad = blacksite.post("/api/auth/login", json={"email": owner.user.email, "password": "nope"})
    assert bad.status_code == 401
