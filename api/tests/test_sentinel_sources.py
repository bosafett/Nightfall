# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""SENTINEL step 3c (migration 0029): AEGIS alerts as a source (new certificate fingerprints,
names outside the authorized scope) and indicators a person enters on an incident."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.sentinel import extract
from nightfall.shield import rules
from nightfall.shield.scheduler import schedule
from tests.conftest import WORKER_URL, audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_sentinel import ATTACKER
from tests.test_shield import HOST, W, Dns, Tls, authorize, drain
from tests.test_shield_guard import _alert, _register, _send, _sensor

EVIL = "cdn.evil-host.net"


class DnsCname(Dns):
    def __init__(self) -> None:
        super().__init__()
        self.cname = ["edge.third-party.example."]

    def run(self, target, ctx):  # type: ignore[no-untyped-def]
        res = super().run(target, ctx)
        return type(res)(**{**res.__dict__, "records": {**res.records, "CNAME": self.cname}})


def _changed_site(client: TestClient, env: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Two daily runs: the certificate and a CNAME target change in between."""
    assert authorize(client, env).status_code == 201
    tls, dns = Tls(), DnsCname()
    worker = make_worker({"tls": tls, "dns": dns})
    now = utcnow()
    schedule(worker.sessions, now)
    drain(worker)
    tls.sha = "22" * 32
    dns.cname = [f"{EVIL}.", "www.example.com."]  # one outside the scope, one inside
    schedule(worker.sessions, now + timedelta(hours=21))
    drain(worker)
    use(client, env["viewer"])
    return {a["kind"]: a for a in client.get(f"{W(env)}/alerts").json()}


def _indicators(client: TestClient, env: dict[str, Any], **params: str) -> list[dict[str, Any]]:
    r = client.get(f"{W(env)}/sentinel/indicators", params=params)
    assert r.status_code == 200, r.text
    return list(r.json())


def _incident(client: TestClient, env: dict[str, Any], **body: Any) -> str:
    use(client, env["analyst"])
    r = client.post(f"{W(env)}/projects/{env['pid']}/incidents", json={"title": "Site", **body})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _enter(client: TestClient, env: dict[str, Any], inc: str, type_: str, value: str) -> Any:
    return client.post(f"{W(env)}/sentinel/incidents/{inc}/indicators",
                       json={"type": type_, "value": value, "note": "From the proxy log"})  # fmt: skip


def test_dns_rule_records_targets_outside_scope() -> None:
    prev = {t: [] for t in rules.DNS_TYPES}
    cur = {**prev, "CNAME": ["a.example.com.", "X.Other.net."], "MX": ["10 mx.mail.net."]}
    (d,) = rules.compare("dns", HOST, prev, cur, utcnow(), lambda n: n.endswith("example.com"))
    assert d.data == {"outside_scope": ["mx.mail.net", "x.other.net"]}


def test_aegis_alerts_become_indicators_through_the_worker(
    client: TestClient, env: dict[str, Any], owner_db: Session
) -> None:
    got = _changed_site(client, env)
    assert {"cert.changed", "dns.changed"} <= set(got)
    by_type = {i["type"]: i for i in _indicators(client, env)}
    assert set(by_type) == {"cert_sha256", "domain"}  # www.example.com is in scope: not one
    assert by_type["cert_sha256"]["value"] == "22" * 32
    assert by_type["domain"]["value"] == EVIL
    assert by_type["domain"]["confidence"] == "low" and by_type["domain"]["status"] == "active"
    detail = client.get(f"{W(env)}/sentinel/indicators/{by_type['domain']['id']}").json()
    (s,) = detail["sightings"]
    assert s["source_kind"] == "aegis_alert" and s["description"].startswith("AEGIS: DNS")
    kinds = owner_db.execute(text("SELECT source_kind FROM sentinel_sightings")).scalars().all()
    assert set(kinds) == {"aegis_alert"}


def test_worker_may_only_add_aegis_sightings(client: TestClient, env: dict[str, Any]) -> None:
    _changed_site(client, env)
    worker_engine = create_engine(WORKER_URL)
    with worker_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):  # it can't read sightings
            conn.execute(text("SELECT count(*) FROM sentinel_sightings"))
        conn.rollback()
        alert_id = conn.execute(text("SELECT id FROM alerts LIMIT 1")).scalar_one()
        ind = conn.execute(text("SELECT id FROM sentinel_indicators LIMIT 1")).scalar_one()
        for kind, src in (("intrusion_alert", alert_id), ("aegis_alert", ind)):
            with pytest.raises(DBAPIError, match="row-level security"):
                conn.execute(
                    text("INSERT INTO sentinel_sightings (workspace_id, indicator_id, source_kind, "
                         "source_id, event_time) VALUES (:w, :i, :k, :s, now())"),
                    {"w": str(env["ws"]), "i": ind, "k": kind, "s": src},
                )  # fmt: skip
            conn.rollback()
    worker_engine.dispose()


def test_person_entered_indicators_and_aegis_suggestions(
    client: TestClient, env: dict[str, Any], owner_db: Session
) -> None:
    got = _changed_site(client, env)
    inc = _incident(client, env)
    use(client, env["viewer"])
    assert _enter(client, env, inc, "domain", EVIL).status_code == 403
    use(client, env["analyst"])
    # Validation: a range, a bad hash, a malformed URL.
    for t, v in (("ip", "45.33.0.0/16"), ("sha256", "abc"), ("url", "ftp://x.net/")):
        assert _enter(client, env, inc, t, v).status_code == 422, (t, v)
    r = _enter(client, env, inc, "url", "HTTPS://User:pw@Evil-Host.net:8443/a/b?token=1#x")
    assert r.status_code == 201, r.text
    assert r.json()["value"] == "https://evil-host.net:8443/a/b"
    r = _enter(client, env, inc, "ip", "10.1.2.3")  # a person may add a private address
    assert r.status_code == 201 and r.json()["computed_confidence"] == "low"
    # Entering the AEGIS domain suggests the DNS alert, which a person then adds.
    r = _enter(client, env, inc, "domain", f"{EVIL.upper()}.")
    assert r.status_code == 201 and r.json()["sighting_count"] == 2
    c = client.get(f"{W(env)}/sentinel/incidents/{inc}/correlation").json()
    assert c["linked_alerts"] == 0
    (sug,) = c["suggestions"]
    assert sug["source_id"] == got["dns.changed"]["id"]
    assert sug["escalation_kind"] == "aegis-alerts"
    assert sug["reason"] == f"Shares domain {EVIL}, entered on this incident"
    r = client.post(f"{W(env)}/incidents/{inc}/items",
                    json={"kind": "alert", "item_id": sug["source_id"]})  # fmt: skip
    assert r.status_code == 200, r.text
    c = client.get(f"{W(env)}/sentinel/incidents/{inc}/correlation").json()
    assert c["linked_alerts"] == 1 and c["suggestions"] == []
    timeline = client.get(f"{W(env)}/incidents/{inc}").json()["timeline"]
    assert any(e["body"].startswith(f"Indicator added: domain {EVIL}") for e in timeline)
    assert audit_actions(owner_db).count("sentinel.indicator_entered") == 3


def test_entered_address_suggests_sensor_alerts_and_allow_list(
    client: TestClient, env: dict[str, Any]
) -> None:
    use(client, env["owner"])
    base = f"{W(env)}/shield"
    _, key = _register(client, base)
    client.post(f"{base}/allowlist", json={"cidr": "45.33.32.200"})
    with _sensor(key) as s:
        (a,) = _send(s, _alert(ATTACKER))
    inc = _incident(client, env)
    assert _enter(client, env, inc, "ip", "45.33.32.200").status_code == 422  # allow-listed
    assert _enter(client, env, inc, "ip", ATTACKER).status_code == 201
    (sug,) = client.get(f"{W(env)}/sentinel/incidents/{inc}/correlation").json()["suggestions"]
    assert sug["source_id"] == a["alert_id"] and sug["escalation_kind"] == "intrusion-alerts"


def test_normalizers() -> None:
    assert extract.domain_value("*.Example.COM.") == "example.com"
    assert extract.domain_value("localhost") is None
    assert extract.domain_value("bad_label.net") is None
    assert extract.domain_value("1.2.3.4") is None
    assert extract.sha256_value("AA:" * 31 + "AA") == "aa" * 32
    assert extract.url_value("http://[2001:db8::1]/x?y") == "http://[2001:db8::1]/x"
    assert extract.url_value("javascript:alert(1)") is None
    assert extract.user_agent_value("  curl/8.0 \n x ") == "curl/8.0 x"
    assert extract.user_agent_value("x" * 301) is None
