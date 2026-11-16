# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""SHIELD v2: incidents, with recovery and verification."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.config import _sqlalchemy_url
from nightfall.core.clock import utcnow
from nightfall.core.db.models import Role
from nightfall.shield import rules
from nightfall.shield.scheduler import schedule
from tests.conftest import WORKER_URL, Factory, audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_shield import HOST, Dns, Tls, W, alerts, authorize, drain


@pytest.fixture
def weak(client: TestClient, env, factory: Factory):  # type: ignore[no-untyped-def]
    """A monitored site whose TLS got weaker: alerts cert.expiring, cert.changed,
    tls.weakened and dns.changed are open."""
    env["admin"] = factory.sign_in(factory.member(env["ws"], Role.ADMIN))
    assert authorize(client, env).status_code == 201
    tls, dns = Tls(), Dns()
    worker = make_worker({"tls": tls, "dns": dns})
    now = utcnow()
    schedule(worker.sessions, now)
    drain(worker)
    tls.sha, tls.accepted = "22" * 32, ["TLSv1", "TLSv1.2", "TLSv1.3"]
    dns.a = ["192.0.2.99"]
    schedule(worker.sessions, now + timedelta(hours=21))
    drain(worker)
    return {"tls": tls, "dns": dns, "worker": worker, "alerts": alerts(client, env)}


def open_incident(client: TestClient, env, kinds, who="analyst"):  # type: ignore[no-untyped-def]
    got = alerts(client, env)
    use(client, env[who])
    return client.post(
        f"{W(env)}/projects/{env['pid']}/incidents",
        json={"title": "TLS weakened on www", "alert_ids": [got[k]["id"] for k in kinds]},
    )


REVIEW = {"review": {"what_happened": "TLS 1.0 was re-enabled.", "what_was_done": "Disabled it."}}


def test_open_work_and_roles(client: TestClient, env, weak, owner_db: Session) -> None:
    use(client, env["viewer"])
    assert (
        client.post(f"{W(env)}/projects/{env['pid']}/incidents", json={"title": "x"}).status_code
        == 403
    )
    r = open_incident(client, env, ["tls.weakened", "dns.changed"])
    assert r.status_code == 201, r.text
    inc = r.json()
    url = f"{W(env)}/incidents/{inc['id']}"
    assert inc["state"] == "open" and inc["severity"] == "high" and inc["alert_count"] == 2
    # The alerts' recommended fixes became checklist items: recommendations, nothing runs.
    assert [c["source"] for c in inc["checklist"]] == ["recommendation"] * 2
    assert any("Disable the old protocol" in c["text"] for c in inc["checklist"])
    # Only the alert a check can look for again is listed for verification.
    assert [v["title"] for v in inc["verification"]] == [weak["alerts"]["tls.weakened"]["title"]]
    assert inc["verification"][0]["state"] == "not_requested" and inc["close_blockers"]

    # An alert is in one incident in progress at a time.
    assert open_incident(client, env, ["tls.weakened"]).status_code == 409

    # Notes, recorded actions, the checklist and the state: analysts and above.
    assert (
        client.post(f"{url}/entries", json={"kind": "note", "body": "Seen at 09:10"}).status_code
        == 200
    )
    key = inc["checklist"][0]["key"]
    d = client.post(f"{url}/checklist", json={"key": key, "done": True}).json()
    assert d["checklist"][0]["done"] is True and d["checklist"][0]["changed_by"]
    d = client.post(f"{url}/checklist", json={"text": "Tell the web team"}).json()
    assert d["checklist"][-1]["source"] == "added"
    d = client.post(
        f"{url}/state", json={"state": "contained", "note": "Load balancer fixed"}
    ).json()
    assert d["state"] == "contained"
    assert (
        client.post(f"{url}/state", json={"state": "contained", "note": "again"}).status_code == 409
    )

    # Severity, lead, cancel, close and reopen: admin and owner only.
    for path, body in (
        ("severity", {"severity": "critical", "reason": "x"}),
        ("cancel", {"reason": "x"}),
        ("close", REVIEW),
        ("reopen", {"reason": "x"}),
    ):
        assert client.post(f"{url}/{path}", json=body).status_code == 403, path
    use(client, env["admin"])
    d = client.post(
        f"{url}/severity", json={"severity": "critical", "reason": "Customer-facing"}
    ).json()
    assert d["severity"] == "critical" and d["severity_reason"] == "Customer-facing"
    stranger = "00000000-0000-0000-0000-000000000001"
    assert client.post(f"{url}/lead", json={"user_id": stranger}).status_code == 422

    # Unlinking is recorded, and frees the alert for another incident.
    item = next(i for i in d["items"] if "DNS" in i["label"])
    d = client.post(f"{url}/items/{item['id']}/remove").json()
    assert d["alert_count"] == 1
    kinds = [e["kind"] for e in d["timeline"]]
    assert {"event", "note", "check"} <= set(kinds)
    assert any(e["body"].startswith("Unlinked alert") for e in d["timeline"])

    use(client, env["viewer"])
    assert client.get(url).status_code == 200
    assert [i["id"] for i in client.get(f"{W(env)}/incidents").json()] == [inc["id"]]
    chron = client.get(f"{W(env)}/projects/{env['pid']}/chronicle").json()["entries"]
    assert "incident.opened" in [e["action"] for e in chron]
    assert {"incident.opened", "incident.contained", "incident.severity_changed"} <= set(
        audit_actions(owner_db)
    )


def test_verification_runs_the_monitors_own_check_and_gates_closing(
    client: TestClient, env, weak, owner_db: Session
) -> None:
    inc = open_incident(client, env, ["tls.weakened", "cert.changed"]).json()
    url = f"{W(env)}/incidents/{inc['id']}"

    # Closing without verification is refused; an override needs a reason and fresh two-factor.
    use(client, env["admin"])
    r = client.post(f"{url}/close", json=REVIEW)
    assert r.status_code == 409 and "Not verified" in r.text
    owner_db.execute(text("UPDATE sessions SET mfa_verified_at = now() - interval '16 minutes'"))
    owner_db.commit()
    r = client.post(f"{url}/close", json={**REVIEW, "override_reason": "Decommissioned"})
    assert r.status_code == 403 and "authenticator" in r.text
    owner_db.execute(text("UPDATE sessions SET mfa_verified_at = now()"))
    owner_db.commit()

    # Verify now: one ordinary operation, the monitor's own tls check, no approval.
    use(client, env["analyst"])
    v = client.post(f"{url}/verify").json()
    assert [(q["tool"], q["target"]) for q in v["queued"]] == [("tls", HOST)] and not v["skipped"]
    op = owner_db.execute(
        text(
            "SELECT status, monitor_authorization_id IS NOT NULL AS m, risk_class, "
            "requested_by_user_id FROM operations WHERE incident_id = :i"
        ),
        {"i": inc["id"]},
    ).one()
    assert (op.status, op.m) == ("queued", True)
    assert client.get(url).json()["verification"][0]["state"] == "pending"
    assert client.post(f"{url}/verify").json()["queued"] == []  # already waiting
    drain(weak["worker"])
    assert owner_db.execute(text("SELECT count(*) FROM approvals")).scalar_one() == 0
    d = client.get(url).json()
    ver = d["verification"][0]
    assert ver["state"] == "still_present" and ver["evidence_id"] and not ver["counts"]
    entry = next(e for e in d["timeline"] if e["kind"] == "verification")
    assert entry["actor"] is None and entry["body"].startswith("Still present")

    # The fix is made outside JANUS and recorded; the next check no longer sees TLS 1.0.
    weak["tls"].accepted = ["TLSv1.2", "TLSv1.3"]
    client.post(f"{url}/entries", json={"kind": "action", "body": "Disabled TLS 1.0 on the LB"})
    client.post(f"{url}/state", json={"state": "recovering", "note": "Fix deployed"})
    client.post(f"{url}/verify")
    drain(weak["worker"])
    d = client.get(url).json()
    assert d["verification"][0]["state"] == "not_observed" and d["verification"][0]["counts"]
    assert d["close_blockers"] == []
    # A later action makes the earlier "not observed" stale.
    client.post(f"{url}/entries", json={"kind": "action", "body": "Changed the cipher list"})
    assert client.get(url).json()["close_blockers"]
    client.post(f"{url}/verify")
    drain(weak["worker"])

    use(client, env["admin"])
    r = client.post(f"{url}/close", json=REVIEW)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["state"] == "closed" and d["override_reason"] == "" and d["closed_by"]
    assert d["review"]["what_happened"].startswith("TLS 1.0")
    # Its alerts are resolved with it; a closed incident takes no more work.
    still_open = alerts(client, env)  # active alerts only
    assert "tls.weakened" not in still_open and "cert.changed" not in still_open
    assert still_open["dns.changed"]["state"] == "open"
    notes = owner_db.execute(text("SELECT note FROM alerts WHERE state = 'resolved'")).scalars()
    assert all(n == f"Closed with incident {inc['id']}" for n in notes)
    use(client, env["analyst"])
    assert client.post(f"{url}/entries", json={"kind": "note", "body": "late"}).status_code == 409
    assert client.post(f"{url}/verify").status_code == 409

    # Reopening keeps the whole history, the closing review included.
    use(client, env["admin"])
    d = client.post(f"{url}/reopen", json={"reason": "It came back"}).json()
    assert d["state"] == "open" and d["review"] is None
    closing = next(e for e in d["timeline"] if e["body"].startswith("Closed"))
    assert closing["data"]["review"]["what_was_done"] == "Disabled it."
    exported = client.get(f"{url}/export").json()
    assert exported["format"] == "janus-incident/1"
    assert exported["incident"]["timeline"][0]["body"] == "Incident opened."


def test_override_is_labelled_and_verification_never_widens_monitoring(
    client: TestClient, env, weak, owner_db: Session
) -> None:
    inc = open_incident(client, env, ["tls.weakened"]).json()
    url = f"{W(env)}/incidents/{inc['id']}"
    # Monitoring is revoked: verification has nothing to run under, and says so.
    use(client, env["owner"])
    auth = client.get(f"{W(env)}/monitor-authorizations").json()[0]
    client.post(f"{W(env)}/monitor-authorizations/{auth['id']}/revoke", json={"reason": "test"})
    v = client.post(f"{url}/verify").json()
    assert v["queued"] == [] and "No live monitor authorization" in v["skipped"][0]["reason"]
    assert (
        owner_db.execute(
            text("SELECT count(*) FROM operations WHERE incident_id IS NOT NULL")
        ).scalar_one()
        == 0
    )
    r = client.post(f"{url}/close", json={**REVIEW, "override_reason": "Host decommissioned"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["override_reason"] == "Host decommissioned"
    closing = next(e for e in d["timeline"] if e["body"].startswith("Closed"))
    assert closing["data"]["override"] is True and closing["data"]["unverified"]
    ev = owner_db.execute(
        text("SELECT data FROM audit_events WHERE action = 'incident.closed'")
    ).scalar_one()
    assert ev["override"] is True


def test_database_enforces_lifecycle_timeline_and_verification_runs(
    client: TestClient, env, weak, owner_db: Session, app_engine: Engine
) -> None:
    inc = open_incident(client, env, ["tls.weakened"]).json()
    ws, iid = str(env["ws"]), inc["id"]

    def app(sql: str, **p: object) -> None:
        with app_engine.connect() as conn:
            conn.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": ws})
            conn.commit()
            with conn.begin():
                conn.execute(text(sql), {"i": iid, **p})

    for bad in (
        "UPDATE incident_entries SET body = 'rewritten' WHERE incident_id = :i",
        "DELETE FROM incident_entries WHERE incident_id = :i",
        "DELETE FROM incidents WHERE id = :i",
        # People's entries can't pose as verification results.
        "INSERT INTO incident_entries (workspace_id, incident_id, kind, body) "
        "SELECT workspace_id, id, 'verification', 'Not observed' FROM incidents WHERE id = :i",
        # Closed needs its review and who closed it.
        "UPDATE incidents SET state = 'closed', closed_at = now() WHERE id = :i",
        # A verification run must be a monitored operation.
        "INSERT INTO operations (workspace_id, project_id, scope_id, tool, risk_class, "
        "target_value, requested_by_user_id, incident_id, status) "
        "SELECT workspace_id, project_id, scope_id, 'tls', 'low', target_value, "
        "requested_by_user_id, :i, 'queued' FROM operations LIMIT 1",
    ):
        with pytest.raises(DBAPIError):
            app(bad)
    app("UPDATE incidents SET state = 'recovering' WHERE id = :i")
    with pytest.raises(DBAPIError, match="cannot go from"):
        app("UPDATE incidents SET state = 'contained' WHERE id = :i")
    app("UPDATE incidents SET state = 'cancelled', cancel_reason = 'mistake' WHERE id = :i")
    with pytest.raises(DBAPIError, match="cancelled incident"):
        app("UPDATE incidents SET title = 'x' WHERE id = :i")
    with pytest.raises(DBAPIError, match="closed or cancelled"):
        app(
            "INSERT INTO incident_items (workspace_id, incident_id, kind, item_id, "
            "added_by_user_id) SELECT workspace_id, id, 'asset', gen_random_uuid(), "
            "opened_by_user_id FROM incidents WHERE id = :i"
        )

    # The worker writes verification results only.
    worker = create_engine(_sqlalchemy_url(WORKER_URL))
    with worker.connect() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": ws})
        conn.commit()
        entry = (
            "INSERT INTO incident_entries (workspace_id, incident_id, kind, body, actor_user_id) "
            "SELECT workspace_id, id, :k, 'x', CASE WHEN :me THEN opened_by_user_id END "
            "FROM incidents WHERE id = :i"
        )
        for kind, as_person in (("note", False), ("verification", True)):
            with pytest.raises(DBAPIError), conn.begin():
                conn.execute(text(entry), {"i": iid, "k": kind, "me": as_person})
        with conn.begin():  # a verification result with no person as its author is allowed
            conn.execute(text(entry), {"i": iid, "k": "verification", "me": False})
        with pytest.raises(DBAPIError), conn.begin():
            conn.execute(text("UPDATE incidents SET state = 'open' WHERE id = :i"), {"i": iid})


def test_still_present_rules() -> None:
    now = utcnow()
    soon, later = (now + timedelta(days=5)).isoformat(), (now + timedelta(days=80)).isoformat()
    sp = rules.still_present
    assert sp("cert.expiring", {}, {"not_after": soon}, now, False) is True
    assert sp("cert.expiring", {}, {"not_after": later}, now, False) is False
    weak_data = {"protocols": ["TLSv1"], "lost_trust": False}
    assert sp(
        "tls.weakened", weak_data, {"accepted": ["TLSv1", "TLSv1.3"], "trusted": True}, now, False
    )
    assert not sp("tls.weakened", weak_data, {"accepted": ["TLSv1.3"], "trusted": True}, now, False)
    assert sp(
        "tls.weakened",
        {"protocols": [], "lost_trust": True},
        {"accepted": [], "trusted": False},
        now,
        False,
    )
    # An alert raised before the facts were kept: judged conservatively, or not at all.
    assert sp("tls.weakened", {}, {"accepted": ["TLSv1.3"], "trusted": False}, now, False) is True
    assert sp("headers.regressed", {}, {"failing": ["hsts"]}, now, False) is None
    assert sp("headers.regressed", {"failing": ["hsts"]}, {"failing": ["csp"]}, now, False) is False
    assert sp("headers.regressed", {"failing": ["hsts"]}, {"failing": ["hsts"]}, now, False) is True
    assert sp("finding.reopened", {}, {}, now, True) is True
    # Change reports aren't conditions: a re-check can't say they're gone.
    for kind in ("cert.changed", "dns.changed", "ct.new_names", "monitor.failed", "detection.gap"):
        assert kind not in rules.VERIFY_TOOL and sp(kind, {}, {}, now, False) is None
