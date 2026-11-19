"""SHIELD v3 phase 2: the sensor API and GUARD (automatic tier), the person-approved tier, the
allow list, the per-hour cap and the kill switch, end to end through the HTTP API."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.main import create_app
from nightfall.shield import guard
from tests.conftest import ORIGIN, Factory, Member, audit_actions, use

NOW = "2026-11-17T12:00:00Z"


def _ws(client: TestClient, factory: Factory) -> tuple[Member, str]:
    ws = factory.workspace()
    owner = factory.sign_in(factory.member(ws, Role.OWNER))
    use(client, owner)
    return owner, f"/api/workspaces/{ws}/shield"


def _register(client: TestClient, base: str, name: str = "lab") -> tuple[str, str]:
    r = client.post(f"{base}/sensors", json={"name": name})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["key"].startswith("nfs_") and body["key_prefix"] == body["key"][:12]
    return body["id"], body["key"]


def _sensor(key: str) -> TestClient:
    """The sensor talks to JANUS with only its key: no cookie, no browser Origin header."""
    return TestClient(
        create_app(),
        base_url=ORIGIN,
        headers={"Authorization": f"Bearer {key}"},
    )


def _alert(source: str, scenario: str = "crowdsecurity/ssh-bf", **kw: Any) -> dict[str, Any]:
    return {"ref": str(uuid.uuid4())[:8], "scenario": scenario, "source": source,
            "events_count": 6, "start_at": NOW, **kw}  # fmt: skip


def _authorize(client: TestClient, base: str, sensors: list[str], **kw: Any) -> dict[str, Any]:
    body = {"sensor_ids": sensors, "trial_days": 0, **kw}  # the trial week has its own tests
    r = client.post(f"{base}/response-authorization", json=body)
    assert r.status_code == 201, r.text
    return dict(r.json())


def _send(sensor: TestClient, *alerts: dict[str, Any]) -> list[dict[str, Any]]:
    r = sensor.post("/api/sensor/alerts", json={"alerts": list(alerts)})
    assert r.status_code == 200, r.text
    return list(r.json())


@pytest.mark.parametrize(
    ("scenario", "category"),
    [
        ("crowdsecurity/ssh-bf", "ssh_bruteforce"),
        ("crowdsecurity/ssh-slow-bf", "ssh_bruteforce"),
        ("crowdsecurity/ssh-cve-2024-6387", "exploit_attempt"),
        ("crowdsecurity/http-generic-bf", "http_bruteforce"),
        ("crowdsecurity/http-wordpress-brute-force", "http_bruteforce"),
        ("crowdsecurity/http-probing", "web_scan"),
        ("crowdsecurity/http-sensitive-files", "web_scan"),
        ("crowdsecurity/http-cve-2021-41773", "exploit_attempt"),
        ("crowdsecurity/http-path-traversal-probing", "exploit_attempt"),
        ("someone/unknown-thing", "other"),
    ],
)
def test_categorize(scenario: str, category: str) -> None:
    assert guard.categorize(scenario) == category


def test_sensor_key_is_required_and_revocation_takes_effect(
    client: TestClient, factory: Factory
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    with _sensor("nfs_not-a-real-key") as bad:
        assert bad.post("/api/sensor/heartbeat", json={}).status_code == 401
    with TestClient(client.app, base_url=ORIGIN) as anon:
        assert anon.get("/api/sensor/decisions").status_code == 401
    with _sensor(key) as s:
        r = s.post("/api/sensor/heartbeat", json={"agent_version": "0.1.0"})
        assert r.status_code == 200 and r.json()["automatic"] is False
        assert client.post(f"{base}/sensors/{sid}/revoke", json={"reason": "rotated"}).is_success
        assert s.post("/api/sensor/heartbeat", json={}).status_code == 401
    sensors = client.get(f"{base}/intrusion").json()["sensors"]
    assert sensors[0]["agent_version"] == "0.1.0" and sensors[0]["revoked_at"]


def test_alert_only_without_an_authorization(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    _, key = _register(client, base)
    with _sensor(key) as s:
        (res,) = _send(s, _alert("203.0.113.7"))
        assert res["outcome"] == "alert_only" and res["block_id"] is None
        _send(s, _alert("203.0.113.7"))  # a repeat raises the count of the open alert
    view = client.get(f"{base}/intrusion").json()
    assert len(view["alerts"]) == 1
    a = view["alerts"][0]
    assert (a["category"], a["severity"], a["count"]) == ("ssh_bruteforce", "medium", 12)
    assert view["blocks"] == [] and view["automatic_active"] is False


def test_guard_blocks_and_the_sensor_applies_and_removes(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _authorize(client, base, [sid], default_block_seconds=1800)
    with _sensor(key) as s:
        assert s.post("/api/sensor/heartbeat", json={}).json()["automatic"] is True
        (res,) = _send(s, _alert("203.0.113.9"))
        assert res["outcome"] == "blocked", res
        block_id = res["block_id"]
        (again,) = _send(s, _alert("203.0.113.9"))
        assert again["outcome"] == "already_blocked" and again["block_id"] == block_id

        d = s.get("/api/sensor/decisions").json()
        assert [b["id"] for b in d["apply"]] == [block_id] and d["remove"] == []
        assert d["apply"][0]["target"] == "203.0.113.9/32"
        assert 1700 < d["apply"][0]["seconds_left"] <= 1800
        assert s.post("/api/sensor/decisions/report", json={"applied": [block_id]}).json() == {
            "applied": 1, "removed": 0, "refused": 0,
        }  # fmt: skip
        assert client.get(f"{base}/intrusion").json()["blocks"][0]["status"] == "active"

        lift = client.post(f"{base}/blocks/{block_id}/lift", json={"reason": "my own IP"})
        assert lift.is_success
        d = s.get("/api/sensor/decisions").json()
        assert d["apply"] == [] and [b["id"] for b in d["remove"]] == [block_id]
        s.post("/api/sensor/decisions/report", json={"removed": [block_id]})
        assert s.get("/api/sensor/decisions").json()["remove"] == []
    assert client.get(f"{base}/intrusion").json()["blocks"][0]["status"] == "lifted"
    actions = audit_actions(owner_db)
    for a in ("shield.sensor.registered", "shield.response.authorized", "shield.guard.blocked",
              "shield.sensor.decisions", "shield.block.lifted"):  # fmt: skip
        assert a in actions


def test_guard_refuses_allowlisted_reserved_and_ranges(
    client: TestClient, factory: Factory
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _authorize(client, base, [sid])
    r = client.post(f"{base}/allowlist", json={"cidr": "198.51.100.0/24", "note": "home"})
    assert r.is_success
    with _sensor(key) as s:
        allow, loop, rng, other, sim = _send(
            s,
            _alert("198.51.100.20"),
            _alert("127.0.0.1"),
            _alert("203.0.113.0/24"),
            _alert("203.0.113.50", scenario="someone/unknown-thing"),
            _alert("203.0.113.51", simulated=True),
        )
    assert allow["outcome"] == "refused" and "allow list" in allow["reason"]
    assert loop["outcome"] == "refused" and "never blocked" in loop["reason"]
    assert rng["outcome"] == "alert_only" and "range" in rng["reason"]
    assert other["outcome"] == "alert_only" and sim["outcome"] == "alert_only"
    assert client.get(f"{base}/intrusion").json()["blocks"] == []


def test_kill_switch_and_cap_fall_back_to_alert_only(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    other_sid, _ = _register(client, base, "other")
    _authorize(client, base, [sid], per_hour_cap=1)
    with _sensor(key) as s:
        assert client.post(f"{base}/response/pause", json={"reason": "testing"}).is_success
        assert _send(s, _alert("203.0.113.1"))[0]["outcome"] == "alert_only"
        assert s.post("/api/sensor/heartbeat", json={}).json()["automatic"] is False
        assert client.post(f"{base}/response/resume").is_success
        assert _send(s, _alert("203.0.113.2"))[0]["outcome"] == "blocked"
        capped = _send(s, _alert("203.0.113.3"))[0]
        assert capped["outcome"] == "alert_only" and "cap" in capped["reason"]
    # The authorization covers only the first sensor.
    view = client.get(f"{base}/intrusion").json()
    assert (
        view["authorization"]["sensor_ids"] == [sid]
        and other_sid not in view["authorization"]["sensor_ids"]
    )


def test_ending_the_authorization_stops_guard(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    first = _authorize(client, base, [sid])
    second = _authorize(client, base, [sid], per_hour_cap=10)  # supersedes the first
    assert first["id"] != second["id"]
    assert client.post(f"{base}/response-authorization/end", json={"reason": "done"}).is_success
    with _sensor(key) as s:
        assert _send(s, _alert("203.0.113.4"))[0]["outcome"] == "alert_only"
    assert client.get(f"{base}/intrusion").json()["authorization"] is None


def test_permissions(client: TestClient, factory: Factory, owner_db: Session) -> None:
    owner, base = _ws(client, factory)
    sid, _ = _register(client, base)
    admin = factory.sign_in(factory.member(owner.workspace_id, Role.ADMIN))
    use(client, admin)
    # Admins may make JANUS block less...
    assert client.post(f"{base}/response/pause", json={"reason": "x"}).is_success
    assert client.post(f"{base}/allowlist", json={"cidr": "192.0.2.1"}).status_code == 201
    # ...but not more, or blind it.
    for path, body in (
        ("/sensors", {"name": "x"}),
        (f"/sensors/{sid}/revoke", {"reason": "x"}),
        ("/response-authorization", {"sensor_ids": [sid]}),
        ("/response/resume", None),
    ):
        assert client.post(base + path, json=body).status_code == 403, path
    # Fresh two-factor for owner actions.
    use(client, owner)
    owner_db.execute(text("UPDATE sessions SET mfa_verified_at = now() - interval '16 minutes'"))
    owner_db.commit()
    r = client.post(f"{base}/sensors", json={"name": "y"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "step_up_required"
    viewer = factory.sign_in(factory.member(owner.workspace_id, Role.VIEWER))
    use(client, viewer)
    assert client.get(f"{base}/intrusion").is_success
    assert client.post(f"{base}/response/pause", json={"reason": "x"}).status_code == 403


def test_approved_blocks(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    a, _ = _register(client, base, "a")
    b, key_b = _register(client, base, "b")
    client.post(f"{base}/allowlist", json={"cidr": "198.51.100.0/24"})
    body = {"target": "203.0.113.0/24", "sensor_ids": [a, b], "seconds": 86400, "reason": "scanner"}
    r = client.post(f"{base}/blocks", json=body)
    assert r.status_code == 201 and {x["tier"] for x in r.json()} == {"approved"}
    assert client.post(f"{base}/blocks", json={**body, "target": "10.0.0.0/8"}).status_code == 422
    assert client.post(f"{base}/blocks", json={**body, "target": "127.0.0.0/24"}).status_code == 422
    assert client.post(f"{base}/blocks", json={**body, "target": "198.51.100.7"}).status_code == 409
    assert client.post(f"{base}/blocks", json={**body, "seconds": 8 * 86400}).status_code == 422
    with _sensor(key_b) as s:
        apply = s.get("/api/sensor/decisions").json()["apply"]
        assert [x["target"] for x in apply] == ["203.0.113.0/24"]


def test_sensor_sees_and_reports_only_its_own_blocks(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    a, key_a = _register(client, base, "a")
    b, _ = _register(client, base, "b")
    r = client.post(f"{base}/blocks", json={"target": "203.0.113.8", "sensor_ids": [b],
                                            "reason": "x"})  # fmt: skip
    other_block = r.json()[0]["id"]
    with _sensor(key_a) as s:
        assert s.get("/api/sensor/decisions").json()["apply"] == []
        out = s.post("/api/sensor/decisions/report", json={"applied": [other_block]}).json()
        assert out["applied"] == 0
    # And a sensor of another workspace sees nothing of this one.
    _, base2 = _ws(client, factory)
    _, key2 = _register(client, base2)
    with _sensor(key2) as s:
        assert s.get("/api/sensor/decisions").json()["apply"] == []


def test_alert_payload_limits(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    _, key = _register(client, base)
    with _sensor(key) as s:
        too_many = {"alerts": [_alert("203.0.113.1")] * 101}
        assert s.post("/api/sensor/alerts", json=too_many).status_code == 422
        big = _alert("203.0.113.1", raw={"x": "y" * 9000})
        assert s.post("/api/sensor/alerts", json={"alerts": [big]}).status_code == 422
        bad = _alert("not-an-ip")
        assert s.post("/api/sensor/alerts", json={"alerts": [bad]}).status_code == 422
