"""Serverless hosting: platform configuration, on-demand worker, cron drain, shared rate
limits."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

import nightfall.serverless as serverless
from nightfall.config import get_settings
from nightfall.core.db.models import Role
from nightfall.core.identity.throttle import SlidingWindow
from tests.conftest import Factory, use
from tests.phase3_helpers import authorize_scope, org_project

CRON = "c" * 40


@pytest.fixture
def on_demand(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    monkeypatch.setenv("NIGHTFALL_CRON_SECRET", CRON)
    monkeypatch.setenv("NIGHTFALL_RATE_LIMIT_BACKEND", "postgres")
    get_settings.cache_clear()
    monkeypatch.setattr(serverless, "_worker", None)
    yield
    get_settings.cache_clear()


def test_platform_env_is_derived_without_overriding_explicit_values() -> None:
    env = {
        "VERCEL": "1",
        "PGHOST_UNPOOLED": "ep-x.neon.tech",
        "PGDATABASE": "neondb",
        "PGUSER": "neondb_owner",
        "PGPASSWORD": "p@ss/word",
        "VERCEL_PROJECT_PRODUCTION_URL": "nightfall.vercel.app",
        "CRON_SECRET": CRON,
        "NIGHTFALL_FORWARDED_HOPS": "2",
    }
    serverless.apply_platform_env(env)
    assert env["NIGHTFALL_MIGRATION_DATABASE_URL"] == (
        "postgresql://neondb_owner:p%40ss%2Fword@ep-x.neon.tech/neondb?sslmode=require"
    )
    app_pw = env["NIGHTFALL_APP_DB_PASSWORD"]
    assert len(app_pw) == 64 and app_pw != env["NIGHTFALL_WORKER_DB_PASSWORD"]
    assert env["NIGHTFALL_DATABASE_URL"].startswith(f"postgresql://nightfall_app:{app_pw}@")
    assert env["NIGHTFALL_PUBLIC_ORIGIN"] == "https://nightfall.vercel.app"
    assert env["NIGHTFALL_CRON_SECRET"] == CRON
    assert env["NIGHTFALL_ON_DEMAND_WORKER"] == "true"
    assert env["NIGHTFALL_EVIDENCE_BACKEND"] == "postgres"
    assert env["NIGHTFALL_FORWARDED_HOPS"] == "2"  # explicit value kept
    again = dict(env)
    serverless.apply_platform_env(again)
    assert again == env  # stable: same derived passwords every cold start


def test_platform_env_does_nothing_off_vercel() -> None:
    env = {"PGHOST": "h", "PGDATABASE": "d", "PGUSER": "u", "PGPASSWORD": "p"}
    serverless.apply_platform_env(env)
    assert env == {"PGHOST": "h", "PGDATABASE": "d", "PGUSER": "u", "PGPASSWORD": "p"}


def test_passive_collection_runs_after_the_response(
    client: TestClient, factory: Factory, owner_db: Session, on_demand
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    r = client.post(
        f"/api/workspaces/{ws}/projects/{pid}/collections",
        json={"tool": "ct", "target": "example.com"},
    )
    assert r.status_code == 202 and r.json()["status"] == "queued"
    done = client.get(f"/api/workspaces/{ws}/operations/{r.json()['id']}").json()
    assert done["status"] == "succeeded"  # the background drain ran it


def test_members_can_nudge_the_queue_only_in_on_demand_mode(
    client: TestClient, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.VIEWER)))
    assert client.post(f"/api/workspaces/{ws}/worker/run").status_code == 404
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    get_settings.cache_clear()
    monkeypatch.setattr(serverless, "_worker", None)
    try:
        r = client.post(f"/api/workspaces/{ws}/worker/run")
        assert r.status_code == 200 and r.json() == {"processed": 0}
        other = factory.workspace("Other")
        assert client.post(f"/api/workspaces/{other}/worker/run").status_code == 404
    finally:
        get_settings.cache_clear()


def test_cron_drain_needs_the_secret(client: TestClient, on_demand) -> None:
    url = "/api/internal/worker/drain"
    assert client.get(url).status_code == 404
    assert client.get(url, headers={"Authorization": "Bearer wrong"}).status_code == 404
    r = client.get(url, headers={"Authorization": f"Bearer {CRON}"})
    assert r.status_code == 200 and r.json() == {"processed": 0}


def test_cron_drain_is_off_without_a_secret(client: TestClient) -> None:
    r = client.get("/api/internal/worker/drain", headers={"Authorization": "Bearer "})
    assert r.status_code == 404


def test_health_reports_the_on_demand_worker(client: TestClient, on_demand) -> None:
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert {c["name"]: c["status"] for c in body["components"]}["worker"] == "on_demand"


def test_postgres_rate_limits_are_shared_and_hashed(owner_db: Session, on_demand) -> None:
    a = SlidingWindow(limit=2, window_seconds=60, name="t_shared")
    b = SlidingWindow(limit=2, window_seconds=60, name="t_shared")  # another "instance"
    assert not a.hit_and_check("1.2.3.4")
    assert not b.hit_and_check("1.2.3.4")
    assert a.hit_and_check("1.2.3.4")  # third hit across both instances
    assert b.blocked("1.2.3.4") and not b.blocked("5.6.7.8")
    stored = owner_db.execute(text("SELECT key_hash FROM rate_limit_hits")).scalars().all()
    assert stored and all(len(k) == 32 and b"1.2.3.4" not in k for k in stored)
    a.reset("1.2.3.4")
    assert not b.blocked("1.2.3.4")


def test_sign_in_throttling_works_with_shared_limits(
    client: TestClient, factory: Factory, owner_db: Session, on_demand
) -> None:
    from nightfall.core.identity import throttle

    for w in (throttle.login_failures_by_account, throttle.login_failures_by_ip):
        w.clear()
    ws = factory.workspace()
    m = factory.member(ws, Role.ANALYST)
    for _ in range(5):
        r = client.post(
            "/api/auth/login", json={"email": m.user.email, "password": "wrong password!"}
        )
        assert r.status_code == 401
    # Correct password, still locked: the count lives in Postgres, not in this process.
    r = client.post(
        "/api/auth/login", json={"email": m.user.email, "password": "correct horse battery staple"}
    )
    assert r.status_code == 429
