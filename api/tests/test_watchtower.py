"""WATCHTOWER and the audit log (Addendum 5, Phase B): real state only, owner and admin only."""

import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.audit.routes import redact
from nightfall.core.clock import utcnow
from nightfall.core.db.models import ActorType, AuditEvent, Role, WorkerHeartbeat
from tests.conftest import Factory, use
from tests.phase3_helpers import make_worker


@pytest.fixture
def env(factory: Factory):
    ws = factory.workspace()
    return {
        "ws": ws,
        "owner": factory.sign_in(factory.member(ws, Role.OWNER)),
        "admin": factory.sign_in(factory.member(ws, Role.ADMIN)),
        "operator": factory.sign_in(factory.member(ws, Role.OPERATOR)),
    }


def _events(db: Session, ws: uuid.UUID, actions: list[str], **data) -> None:
    start = utcnow() - timedelta(hours=1)
    for i, a in enumerate(actions):
        db.add(
            AuditEvent(
                id=uuid.uuid4(),
                workspace_id=ws,
                actor_type=ActorType.SYSTEM,
                action=a,
                data=data,
                occurred_at=start + timedelta(seconds=i),
            )
        )
    db.commit()


def test_audit_log_is_owner_and_admin_only(client: TestClient, env) -> None:
    for who, code in (("owner", 200), ("admin", 200), ("operator", 403)):
        use(client, env[who])
        assert client.get(f"/api/workspaces/{env['ws']}/audit").status_code == code


def test_audit_log_pages_filters_and_stays_in_workspace(
    client: TestClient, env, factory: Factory, owner_db: Session
) -> None:
    _events(owner_db, env["ws"], [f"operation.step_{i}" for i in range(60)] + ["auth.login"])
    other = factory.workspace("Other")
    _events(owner_db, other, ["operation.elsewhere"])
    use(client, env["owner"])
    base = f"/api/workspaces/{env['ws']}/audit"
    first = client.get(base).json()
    assert len(first["events"]) == 50 and first["events"][0]["action"] == "auth.login"
    assert {"auth", "operation"} <= set(first["categories"])
    rest = client.get(base, params={"before": first["next_before"]}).json()
    seen = [e["action"] for e in first["events"] + rest["events"]]
    assert len(seen) == len(set(seen)) == 61 and rest["next_before"] is None
    assert "operation.elsewhere" not in seen
    auth = client.get(base, params={"category": "auth"}).json()["events"]
    assert [e["action"] for e in auth] == ["auth.login"]
    other_id = owner_db.scalar(
        text("SELECT id FROM audit_events WHERE workspace_id = :w"), {"w": other}
    )
    assert client.get(base, params={"before": str(other_id)}).status_code == 404
    assert client.get(base, params={"category": "a.b"}).status_code == 422


def test_audit_data_never_echoes_secret_looking_fields(
    client: TestClient, env, owner_db: Session
) -> None:
    _events(owner_db, env["ws"], ["probe.denied"], reason="x", headers={"Authorization": "b"})
    use(client, env["admin"])
    ev = client.get(f"/api/workspaces/{env['ws']}/audit").json()["events"][0]
    assert ev["data"] == {"reason": "x", "headers": {"Authorization": "<redacted>"}}
    assert redact([{"api_token": 1, "ok": [{"password": 2}]}]) == [
        {"api_token": "<redacted>", "ok": [{"password": "<redacted>"}]}
    ]


def test_watchtower_reports_lab_separately(client: TestClient, env, owner_db: Session) -> None:
    use(client, env["owner"])
    url = f"/api/workspaces/{env['ws']}/watchtower"
    body = client.get(url).json()
    assert body["lab"]["status"] == "never" and body["audit"]["status"] == "ok"
    use(client, env["operator"])
    assert client.get(url).status_code == 403

    lab = make_worker()
    lab.lab = True
    lab.heartbeat()
    assert owner_db.get(WorkerHeartbeat, lab.heartbeat_id) is not None
    assert lab.heartbeat_id.startswith("lab:")
    use(client, env["owner"])
    body = client.get(url).json()
    assert body["lab"]["status"] == "online"
    # A lab worker alone never makes the hosted worker look healthy.
    assert body["worker"]["status"] in ("never", "on_demand")
    health = {c["name"]: c["status"] for c in client.get("/api/health").json()["components"]}
    assert health["worker"] in ("down", "on_demand")
    assert "lab" not in health  # /api/health is public; lab state stays behind sign-in

    owner_db.execute(
        text("UPDATE worker_heartbeats SET last_seen_at = now() - interval '5 minutes'")
    )
    owner_db.commit()
    assert client.get(url).json()["lab"]["status"] == "offline"


def test_watchtower_reports_the_profile_b_worker_separately(
    client: TestClient, env, owner_db: Session
) -> None:
    use(client, env["owner"])
    url = f"/api/workspaces/{env['ws']}/watchtower"
    assert client.get(url).json()["profile_b"]["status"] == "never"
    pb = make_worker(profile_b=True)
    pb.heartbeat()
    assert pb.heartbeat_id.startswith("pb:")
    body = client.get(url).json()
    assert body["profile_b"]["status"] == "online" and body["lab"]["status"] == "never"
    # It never makes the hosted worker look healthy either.
    assert body["worker"]["status"] in ("never", "on_demand")
    health = {c["name"]: c["status"] for c in client.get("/api/health").json()["components"]}
    assert health["worker"] in ("down", "on_demand")
