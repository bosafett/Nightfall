import hashlib

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from tests.conftest import audit_actions, use
from tests.test_findings import env, make_finding, run_http  # noqa: F401  (fixture reuse)


def test_attack_path_stays_hypothesis_until_findings_are_validated(client, env, owner_db) -> None:  # noqa: F811
    run_http(client, env)
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    a = make_finding(client, env, title="Exposed admin", severity="high").json()
    b = make_finding(
        client,
        env,
        title="Default credentials",
        severity="critical",
        validation_status="hypothesis",
    ).json()
    path = client.post(
        f"{base}/projects/{env['pid']}/attack-paths",
        json={
            "title": "Admin takeover",
            "narrative": "Panel is reachable, then default creds.",
            "steps": [
                {"finding_id": a["id"], "description": "Reach the panel"},
                {"finding_id": b["id"], "description": "Log in with defaults"},
            ],
        },
    )
    assert path.status_code == 201 and path.json()["status"] == "hypothesis"
    pid = path.json()["id"]
    r = client.post(
        f"{base}/attack-paths/{pid}/review", json={"status": "validated", "note": "Seen"}
    )
    assert r.json()["detail"]["code"] == "unvalidated_findings"

    ev = client.get(f"{base}/projects/{env['pid']}/evidence").json()[0]["id"]
    for f in (a, b):
        client.post(f"{base}/findings/{f['id']}/evidence", json={"evidence_id": ev})
        client.post(
            f"{base}/findings/{f['id']}/status", json={"status": "validated", "note": "Reproduced"}
        )
    ok = client.post(
        f"{base}/attack-paths/{pid}/review",
        json={"status": "validated", "note": "Demonstrated in lab"},
    )
    assert ok.json()["status"] == "validated" and ok.json()["reviewed_by"] == "Analyst"
    assert (
        client.put(
            f"{base}/attack-paths/{pid}",
            json={
                "title": "x",
                "steps": [
                    {"finding_id": a["id"], "description": "a"},
                    {"finding_id": b["id"], "description": "b"},
                ],
            },
        ).status_code
        == 409
    )
    assert "attack_path.reviewed" in audit_actions(owner_db)

    graph = client.get(f"{base}/projects/{env['pid']}/graph").json()
    kinds = {e["kind"] for e in graph["edges"]}
    assert {"path_step", "affects", "resolves_to"} <= kinds
    step = next(e for e in graph["edges"] if e["kind"] == "path_step")
    assert step["status"] == "validated" and step["path_title"] == "Admin takeover"
    rel = next(e for e in graph["edges"] if e["kind"] == "resolves_to")
    assert rel["status"] == "observed" and rel["evidence_id"] and rel["rule_id"]


def test_path_steps_must_stay_in_project(client, env) -> None:  # noqa: F811
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    a = make_finding(client, env).json()
    r = client.post(
        f"{base}/projects/{env['pid']}/attack-paths",
        json={
            "title": "x",
            "steps": [
                {"finding_id": a["id"], "description": "a"},
                {"finding_id": "00000000-0000-0000-0000-000000000000", "description": "b"},
            ],
        },
    )
    assert r.status_code == 422


def test_report_snapshot_is_frozen_hashed_and_honest(client, env, owner_db, app_engine) -> None:  # noqa: F811
    run_http(client, env)
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    make_finding(client, env, title="Guessed weakness", validation_status="hypothesis")
    created = client.post(f"{base}/projects/{env['pid']}/reports")
    assert created.status_code == 201
    rid = created.json()["id"]
    report = client.get(f"{base}/reports/{rid}").json()
    assert report["integrity_ok"] is True
    c = report["content"]
    assert c["scope"]["version"] == 1 and c["scope"]["targets"][0]["value"] == "example.com"
    assert {f["status"] for f in c["findings"]} == {"unverified", "hypothesis"}
    assert any("hypotheses" in s for s in c["limitations"])
    assert any("TEST-FIXTURE" in s for s in c["limitations"])  # fixture evidence is called out
    assert c["findings"][0]["evidence"] or c["findings"][1]["evidence"]
    assert c["methodology"]["collectors"][0]["tool"] == "http"
    assert (
        hashlib.sha256(
            __import__("nightfall.reports.routes", fromlist=["canonical"]).canonical(c)
        ).hexdigest()
        == report["sha256"]
    )

    # Later changes don't alter an existing report.
    make_finding(client, env, title="Added after the report")
    again = client.get(f"{base}/reports/{rid}").json()
    assert len(again["content"]["findings"]) == len(c["findings"])
    assert "report.generated" in audit_actions(owner_db)

    # Snapshots are insert-only for the API role.
    import pytest

    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(env["ws"])})
        conn.execute(text("UPDATE assessment_snapshots SET content = '{}'::jsonb"))

    # Tampering (done here with the schema owner) is detected.
    owner_db.execute(
        text(
            "UPDATE assessment_snapshots SET content = jsonb_set(content, "
            "'{project,name}', '\"forged\"') WHERE id = :i"
        ),
        {"i": rid},
    )
    owner_db.commit()
    assert client.get(f"{base}/reports/{rid}").json()["integrity_ok"] is False


def test_overview_counts_findings(client, env) -> None:  # noqa: F811
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    make_finding(client, env, title="c1", severity="critical")
    f = make_finding(client, env, title="c2", severity="critical").json()
    client.post(
        f"{base}/findings/{f['id']}/status", json={"status": "false_positive", "note": "dup"}
    )
    make_finding(client, env, title="h", severity="medium", validation_status="hypothesis")
    o = client.get(f"{base}/overview").json()
    assert o["critical_findings"]["open_critical"] == 1
    assert (
        o["risk"]["open_by_severity"]["critical"] == 1
        and o["risk"]["open_by_severity"]["medium"] == 1
    )
    assert o["risk"]["hypotheses"] == 1 and o["risk"]["open_total"] == 2
    assert len(o["recent_findings"]["items"]) == 3
