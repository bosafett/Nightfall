"""SENTINEL step 3b: correlation on an incident (shared indicators, suggestions, technique
sequence) and knows versus suspects. Suggestions are only suggestions: a person adds them."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.conftest import Factory
from tests.phase3_helpers import org_project
from tests.test_sentinel import ATTACKER, _sentinel
from tests.test_shield_guard import _alert, _register, _send, _sensor, _ws
from tests.test_shield_host import _at, _post, _snap


def _setup(client: TestClient, factory: Factory, owner_db: Session) -> dict[str, Any]:
    owner, base = _ws(client, factory)
    _, pid = org_project(owner_db, owner.workspace_id)
    owner_db.commit()
    _, key_a = _register(client, base, "web-1")
    _, key_b = _register(client, base, "web-2")
    with _sensor(key_a) as s:
        (a,) = _send(s, _alert(ATTACKER, start_at=_at(20)))
        _post(s, _snap("admins", []))
        _post(s, _snap("admins", [{"username": "eve", "groupname": "sudo"}], _at(5)))
    with _sensor(key_b) as s:
        (b,) = _send(s, _alert(ATTACKER, scenario="crowdsecurity/http-probing", start_at=_at(15)))
    sid_a = client.get(f"{base}/intrusion").json()["sensors"][0]["id"]
    host = client.get(f"{base}/sensors/{sid_a}/host").json()["alerts"][0]
    inc = client.post(f"{base}/escalations/intrusion-alerts/{a['alert_id']}",
                      json={"project_id": str(pid)}).json()  # fmt: skip
    r = client.post(f"{base}/escalations/host-alerts/{host['id']}", json={"incident_id": inc["id"]})
    assert r.status_code == 201, r.text
    return {"base": base, "inc": inc["id"], "a": a["alert_id"], "b": b["alert_id"]}


def _corr(client: TestClient, base: str, inc: str) -> dict[str, Any]:
    r = client.get(f"{_sentinel(base)}/incidents/{inc}/correlation")
    assert r.status_code == 200, r.text
    return dict(r.json())


def test_shared_indicators_suggestions_and_sequence(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    e = _setup(client, factory, owner_db)
    c = _corr(client, e["base"], e["inc"])
    assert c["linked_alerts"] == 2
    (shared,) = c["shared_indicators"]
    assert shared["indicator"]["value"] == ATTACKER and shared["machines"] == ["web-1", "web-2"]
    (sug,) = c["suggestions"]
    assert sug["source_id"] == e["b"] and sug["escalation_kind"] == "intrusion-alerts"
    assert sug["reason"] == f"Shares ip {ATTACKER} with 1 linked alert(s)"
    assert sug["sensor_name"] == "web-2"
    # The sequence covers only the linked alerts, in time order: brute force, then a new admin.
    assert [s["technique_id"] for s in c["sequence"]] == ["T1110", "T1021.004", "T1098"]
    kinds = {s["kind"] for s in c["suspects"]}
    assert kinds == {"indicator_unreviewed", "possible_compromise", "correlation"}
    assert c["knows"] == [] and c["unknowns"] == []


def test_knows_unknowns_and_adding_a_suggestion(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    e = _setup(client, factory, owner_db)
    base, inc = e["base"], e["inc"]
    ind = _corr(client, base, inc)["shared_indicators"][0]["indicator"]
    client.post(f"{_sentinel(base)}/indicators/{ind['id']}/assess",
                json={"assessment": "malicious", "reason": "Both web servers"})  # fmt: skip
    entries = f"{base.replace('/shield', '')}/incidents/{inc}/entries"
    unknown = {"kind": "note", "body": "Did eve's account exist before?", "unknown": True}
    r = client.post(entries, json=unknown)
    assert r.status_code == 200, r.text
    client.post(entries, json={"kind": "note", "body": "an ordinary note"})
    c = _corr(client, base, inc)
    assert [k["kind"] for k in c["knows"]] == ["indicator_assessed"]
    assert "malicious" in c["knows"][0]["text"] and c["knows"][0]["by"]
    assert [u["text"] for u in c["unknowns"]] == ["Did eve's account exist before?"]
    assert "indicator_unreviewed" not in {s["kind"] for s in c["suspects"]}
    # A person adds the suggestion (decision 4 (c)); it's linked now, so no longer suggested.
    r = client.post(f"{base}/escalations/intrusion-alerts/{e['b']}", json={"incident_id": inc})
    assert r.status_code == 201
    c = _corr(client, base, inc)
    assert c["linked_alerts"] == 3 and c["suggestions"] == []
    assert "T1595" in [s["technique_id"] for s in c["sequence"]]


def test_suppressed_indicators_suggest_nothing_and_isolation(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    e = _setup(client, factory, owner_db)
    base, inc = e["base"], e["inc"]
    ind = _corr(client, base, inc)["shared_indicators"][0]["indicator"]
    client.post(f"{_sentinel(base)}/indicators/{ind['id']}/assess",
                json={"assessment": "false_positive", "reason": "Our uptime monitor"})  # fmt: skip
    assert _corr(client, base, inc)["suggestions"] == []
    _, base2 = _ws(client, factory)
    assert client.get(f"{_sentinel(base2)}/incidents/{inc}/correlation").status_code == 404
