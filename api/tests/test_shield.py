# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""SHIELD v1: standing monitor authorizations, the daily schedule, detection and alerts."""

import copy
import dataclasses
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.core.db.models import Severity
from nightfall.recon.collectors import FixtureDnsRecords, RunContext
from nightfall.recon.posture import FixtureTlsAudit
from nightfall.shield import rules
from nightfall.shield.scheduler import schedule
from tests.conftest import audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture

HOST = "www.example.com"


class Tls(FixtureTlsAudit):
    """The fixture TLS audit, with a changeable certificate and protocol list."""

    def __init__(self) -> None:
        self.not_after = (utcnow() + timedelta(days=10)).isoformat()
        self.sha = "11" * 32
        self.accepted = ["TLSv1.2", "TLSv1.3"]

    def run(self, target: str, ctx: RunContext):  # type: ignore[no-untyped-def]
        res = super().run(target, ctx)
        posture = copy.deepcopy(res.posture)
        posture["tls"]["accepted"] = list(self.accepted)
        posture["tls"]["certificate"].update(not_after=self.not_after, sha256=self.sha)
        return dataclasses.replace(res, posture=posture)


class Dns(FixtureDnsRecords):
    def __init__(self) -> None:
        self.a = ["192.0.2.10"]

    def run(self, target: str, ctx: RunContext):  # type: ignore[no-untyped-def]
        res = super().run(target, ctx)
        return dataclasses.replace(res, records={**res.records, "A": list(self.a)})


def W(env) -> str:  # noqa: N802
    return f"/api/workspaces/{env['ws']}"


def authorize(client: TestClient, env, **body):  # type: ignore[no-untyped-def]
    use(client, env["owner"])
    return client.post(
        f"{W(env)}/projects/{env['pid']}/monitor-authorizations",
        json={"targets": [HOST], "checks": ["tls", "dns"], **body},
    )


def drain(worker) -> None:  # type: ignore[no-untyped-def]
    while worker.run_once():
        pass


def alerts(client: TestClient, env, who: str = "viewer") -> dict[str, dict]:  # type: ignore[no-untyped-def]
    use(client, env[who])
    return {a["kind"]: a for a in client.get(f"{W(env)}/alerts").json()}


def test_authorizations_are_owner_only_scoped_capped_and_short_lived(
    client: TestClient, env, owner_db: Session
) -> None:
    use(client, env["operator"])
    r = client.post(
        f"{W(env)}/projects/{env['pid']}/monitor-authorizations",
        json={"targets": [HOST], "checks": ["tls"]},
    )
    assert r.status_code == 403
    assert authorize(client, env, days=31).status_code == 422
    assert authorize(client, env, checks=["nuclei"]).status_code == 422  # not in the fixed list
    assert authorize(client, env, targets=["evil.test"]).status_code == 422
    assert authorize(client, env, targets=["mail.example.com"]).status_code == 422  # excluded
    many = [f"h{i}.example.com" for i in range(20)]
    r = authorize(client, env, targets=many, checks=["tls", "dns"])  # 40 checks a day
    assert r.status_code == 409 and r.json()["detail"]["code"] == "daily_cap"

    r = authorize(client, env)
    assert r.status_code == 201, r.text
    a = r.json()
    assert a["live"] and a["checks_per_day"] == 2 and a["scope_version"] == 1
    assert (
        datetime.fromisoformat(a["expires_at"]) - datetime.fromisoformat(a["authorized_at"])
    ).days == 30
    renewed = client.post(f"{W(env)}/monitor-authorizations/{a['id']}/renew")
    assert renewed.status_code == 201
    old = {x["id"]: x for x in client.get(f"{W(env)}/monitor-authorizations").json()}[a["id"]]
    assert old["ended_reason"] == "renewed" and not old["live"]
    r = client.post(
        f"{W(env)}/monitor-authorizations/{renewed.json()['id']}/revoke", json={"reason": "Done"}
    )
    assert r.status_code == 200 and r.json()["ended_reason"] == "revoked"
    assert {"monitor.authorized", "monitor.revoked"} <= set(audit_actions(owner_db))


def test_schedule_runs_without_approvals_and_detects_changes(
    client: TestClient, env, owner_db: Session
) -> None:
    assert authorize(client, env).status_code == 201
    tls, dns = Tls(), Dns()
    worker = make_worker({"tls": tls, "dns": dns})
    now = utcnow()
    assert schedule(worker.sessions, now) == 2
    assert schedule(worker.sessions, now + timedelta(hours=1)) == 0  # once a day
    ops = owner_db.execute(
        text("SELECT status, monitor_authorization_id IS NOT NULL AS m FROM operations")
    ).all()
    assert [(o.status, o.m) for o in ops] == [("queued", True)] * 2
    drain(worker)
    assert owner_db.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 0
    assert set(owner_db.execute(text("SELECT status FROM operations")).scalars()) == {"succeeded"}

    # First run: a baseline, but the expiry threshold fires (10 days left: high).
    first = alerts(client, env)
    assert set(first) == {"cert.expiring"} and first["cert.expiring"]["severity"] == "high"
    assert first["cert.expiring"]["recommendation"].startswith("Renew the certificate")

    # Next day: the site changed.
    tls.sha, tls.accepted = "22" * 32, ["TLSv1", "TLSv1.2", "TLSv1.3"]
    tls.not_after = (utcnow() + timedelta(days=5)).isoformat()
    dns.a = ["192.0.2.99"]
    assert schedule(worker.sessions, now + timedelta(hours=21)) == 2
    drain(worker)
    got = alerts(client, env)
    assert set(got) == {"cert.expiring", "cert.changed", "tls.weakened", "dns.changed"}
    assert got["cert.expiring"]["severity"] == "critical"  # escalated, still one alert
    assert got["cert.expiring"]["id"] == first["cert.expiring"]["id"]
    assert "TLSv1" in got["tls.weakened"]["detail"]
    assert "192.0.2.10 → 192.0.2.99" in got["dns.changed"]["detail"]

    # People acknowledge and resolve; viewers can't.
    a = got["tls.weakened"]
    assert client.post(f"{W(env)}/alerts/{a['id']}/acknowledge").status_code == 403
    use(client, env["analyst"])
    assert client.post(f"{W(env)}/alerts/{a['id']}/acknowledge").json()["state"] == "acknowledged"
    r = client.post(f"{W(env)}/alerts/{a['id']}/resolve", json={"note": "Re-disabled TLS 1.0"})
    assert r.json()["state"] == "resolved" and r.json()["resolved_by"]
    assert client.post(f"{W(env)}/alerts/{a['id']}/resolve", json={}).status_code == 409

    use(client, env["viewer"])
    o = client.get(f"{W(env)}/shield/overview").json()
    assert o["open_alerts"]["critical"] == 1 and o["checks_ran_24h"] == 4
    assert o["authorizations_live"] == 1 and o["daily_cap"] == 30
    assert "alert.raised" in [
        e["action"]
        for e in client.get(f"{W(env)}/projects/{env['pid']}/chronicle").json()["entries"]
    ]


def test_revoked_authorization_stops_queued_checks(
    client: TestClient, env, owner_db: Session
) -> None:
    a = authorize(client, env).json()
    worker = make_worker({"tls": Tls(), "dns": Dns()})
    schedule(worker.sessions, utcnow())
    client.post(f"{W(env)}/monitor-authorizations/{a['id']}/revoke", json={"reason": "Stop"})
    drain(worker)
    rows = owner_db.execute(text("SELECT status, denial_reason FROM operations")).all()
    assert {r.status for r in rows} == {"denied"} and "revoked" in rows[0].denial_reason
    assert "monitor.failed" in alerts(client, env)


def test_scope_change_and_expiry_end_monitoring(client: TestClient, env, owner_db: Session) -> None:
    a = authorize(client, env).json()
    worker = make_worker({"tls": Tls(), "dns": Dns()})
    # A new scope version ends the authorization at the next scheduled run.
    use(client, env["owner"])
    draft = client.post(f"{W(env)}/projects/{env['pid']}/scopes").json()
    assert client.post(f"{W(env)}/scopes/{draft['id']}/authorize").status_code == 200
    assert schedule(worker.sessions, utcnow()) == 0
    ended = {x["id"]: x for x in client.get(f"{W(env)}/monitor-authorizations").json()}[a["id"]]
    assert ended["ended_reason"] == "scope_changed"
    assert "monitor.ended" in alerts(client, env)

    b = authorize(client, env).json()
    owner_db.execute(
        text(
            "UPDATE monitor_authorizations SET authorized_at = now() - interval '31 days', "
            "expires_at = now() - interval '1 day' WHERE id = :i"
        ),
        {"i": b["id"]},
    )
    owner_db.commit()
    assert schedule(worker.sessions, utcnow()) == 0
    ended = {x["id"]: x for x in client.get(f"{W(env)}/monitor-authorizations").json()}[b["id"]]
    assert ended["ended_reason"] == "expired"


def test_database_keeps_scheduled_checks_inside_their_authorization(
    client: TestClient, env, app_engine: Engine, owner_db: Session
) -> None:
    a = authorize(client, env).json()
    user = owner_db.execute(text("SELECT id FROM users LIMIT 1")).scalar_one()
    insert = (
        "INSERT INTO operations (workspace_id, project_id, scope_id, tool, risk_class, "
        "target_value, requested_by_user_id, monitor_authorization_id, status) VALUES "
        "(:w, :p, :s, :tool, :risk, :t, :u, :m, 'queued')"
    )
    scope = owner_db.execute(text("SELECT scope_id FROM monitor_authorizations")).scalar_one()
    base = {"w": env["ws"], "p": env["pid"], "s": scope, "u": user, "m": a["id"]}
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        for tool, risk, target in (
            ("headers", "low", HOST),  # check not covered
            ("tls", "low", "api.example.com"),  # target not covered
            ("nuclei", "low", HOST),  # never a monitoring tool
        ):
            with pytest.raises(DBAPIError, match="monitor authorization"):
                with conn.begin():
                    conn.execute(text(insert), {**base, "tool": tool, "risk": risk, "t": target})
        conn.execute(
            text("UPDATE monitor_authorizations SET ended_at = now(), ended_reason = 'revoked'")
        )
        conn.commit()
        with pytest.raises(DBAPIError):
            with conn.begin():
                conn.execute(text("UPDATE monitor_authorizations SET end_note = 'x'"))


def test_rules_baseline_headers_and_ct_scope() -> None:
    now = utcnow()
    assert rules.compare("headers", HOST, None, {"failing": ["a"]}, now) == []  # baseline
    out = rules.compare("headers", HOST, {"failing": ["a"]}, {"failing": ["a", "b"]}, now)
    assert [d.kind for d in out] == ["headers.regressed"] and "b" in out[0].detail
    out = rules.compare(
        "ct", "example.com", {"names": ["www.example.com"]},
        {"names": ["www.example.com", "new.example.com", "examp1e.com"]}, now,
        in_scope=lambda n: n.endswith("example.com") and n != "examp1e.com",
    )  # fmt: skip
    assert out[0].severity is Severity.HIGH and "examp1e.com" in out[0].detail
    out = rules.compare("ct", "example.com", {"names": []}, {"names": ["new.example.com"]}, now)
    assert out[0].severity is Severity.INFO
