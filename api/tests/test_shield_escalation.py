"""v3 decision 4, option c: a person turns a sensor alert (intrusion or host) into incident work.
Nothing opens or joins an incident automatically."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import org_project
from tests.test_shield_guard import _alert, _register, _send, _sensor, _ws
from tests.test_shield_host import EVE, ROOT, _at, _post, _snap


def _setup(client: TestClient, factory: Factory, owner_db: Session) -> dict[str, Any]:
    owner, base = _ws(client, factory)
    _, pid = org_project(owner_db, owner.workspace_id)
    owner_db.commit()
    sid, key = _register(client, base)
    with _sensor(key) as s:
        (res,) = _send(s, _alert("203.0.113.40"))
        _post(s, _snap("accounts", [ROOT]))
        _post(s, _snap("accounts", [ROOT, EVE], _at(5)))
    host = client.get(f"{base}/sensors/{sid}/host").json()["alerts"][0]
    return {"owner": owner, "base": base, "pid": str(pid), "intrusion": res["alert_id"],
            "host": host["id"], "ws": owner.workspace_id}  # fmt: skip


def test_open_from_intrusion_alert_then_add_host_alert(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    e = _setup(client, factory, owner_db)
    base = e["base"]
    r = client.post(f"{base}/escalations/intrusion-alerts/{e['intrusion']}",
                    json={"project_id": e["pid"]})  # fmt: skip
    assert r.status_code == 201, r.text
    inc = r.json()
    assert inc["state"] == "open" and inc["severity"] == "medium"
    assert "crowdsecurity/ssh-bf" in inc["title"]
    # The intrusion alert records the incident.
    alert = next(a for a in client.get(f"{base}/intrusion").json()["alerts"])
    assert alert["id"] == e["intrusion"]
    # Add the host alert to the same incident.
    r = client.post(f"{base}/escalations/host-alerts/{e['host']}", json={"incident_id": inc["id"]})
    assert r.status_code == 201, r.text
    entries = [x["body"] for x in r.json()["timeline"]]
    assert any("Sensor alert added: crowdsecurity/ssh-bf" in b for b in entries)
    assert any("Host alert added: New local account eve" in b and "not proof" in b for b in entries)
    acts = audit_actions(owner_db)
    assert acts.count("incident.sensor_alert_added") == 2 and "incident.opened" in acts
    owner_db.expire_all()
    linked = owner_db.execute(text("SELECT incident_id FROM shield_intrusion_alerts")).scalar_one()
    assert str(linked) == inc["id"]


def test_escalation_rules(client: TestClient, factory: Factory, owner_db: Session) -> None:
    e = _setup(client, factory, owner_db)
    base = e["base"]
    url = f"{base}/escalations/host-alerts/{e['host']}"
    assert client.post(url, json={}).status_code == 422  # neither
    assert (
        client.post(url, json={"project_id": e["pid"], "incident_id": e["pid"]}).status_code == 422
    )
    assert client.post(url, json={"incident_id": e["pid"]}).status_code == 404  # not an incident
    # Viewers can't; analysts can.
    viewer = factory.sign_in(factory.member(e["ws"], Role.VIEWER))
    use(client, viewer)
    assert client.post(url, json={"project_id": e["pid"]}).status_code == 403
    analyst = factory.sign_in(factory.member(e["ws"], Role.ANALYST))
    use(client, analyst)
    r = client.post(url, json={"project_id": e["pid"], "title": "Unexpected account on lab-host"})
    assert r.status_code == 201 and r.json()["title"] == "Unexpected account on lab-host"
    # Another workspace can't reach these alerts.
    _, base2 = _ws(client, factory)
    url2 = f"{base2}/escalations/host-alerts/{e['host']}"
    assert client.post(url2, json={"project_id": e["pid"]}).status_code == 404
