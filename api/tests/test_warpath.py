# ruff: noqa: F811  (pytest fixtures imported from other test modules)
"""WARPATH v1: purple-team exercise plans, runs through BLACKSITE, detection scoring."""

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.warpath.catalogue import ATTACK_FILE, MAPPING, attack, check_mapping, techniques
from tests.conftest import use
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_blackops import lab_headers
from tests.test_lab import APP, _active_lab_scope, lab_worker


def W(env) -> str:  # noqa: N802
    return f"/api/workspaces/{env['ws']}"


STEPS = [
    {"playbook_id": "http-security-assessment", "target": APP, "technique_id": "T1592.002",
     "expected_detection": "WAF log entry for header probing"},
    {"playbook_id": "http-security-assessment", "target": APP, "technique_id": "T1595",
     "expected_detection": "IDS alert for active scanning"},
]  # fmt: skip


def draft(client: TestClient, env, who: str = "analyst", **over):  # type: ignore[no-untyped-def]
    use(client, env[who])
    body = {"name": "Recon drill", "objective": "Do we see scanning?", "steps": STEPS, **over}
    return client.post(f"{W(env)}/projects/{env['pid']}/warpath/exercises", json=body)


def test_catalogue_is_pinned_and_mappings_are_real() -> None:
    check_mapping()
    a = attack()
    assert a["release"] == "20.0" and len(a["source_sha256"]) == 64
    assert len(techniques()) > 600
    assert techniques()["T1595.002"].name == "Vulnerability Scanning"
    assert set(MAPPING) <= {"web-exposure-audit", "tls-configuration-audit",
                            "http-security-assessment", "known-weakness-scan-lab"}  # fmt: skip
    assert hashlib.sha256(ATTACK_FILE.read_bytes()).hexdigest()  # file present and readable


def test_plans_are_lab_only_honest_and_frozen_once_approved(
    client: TestClient, env, owner_db: Session, app_engine: Engine
) -> None:
    assert draft(client, env).status_code == 409  # no lab scope yet
    _active_lab_scope(client, env)
    bad = draft(client, env, steps=[{**STEPS[0], "playbook_id": "surface-mapper"}])
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "not_a_lab_playbook"
    bad = draft(client, env, steps=[{**STEPS[0], "technique_id": "T1059"}])  # not performed
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "technique_not_performed"
    assert draft(client, env, steps=[{**STEPS[0], "target": "8.8.8.8"}]).status_code == 422
    ex = draft(client, env).json()
    assert ex["state"] == "draft" and ex["steps"][0]["technique"]["name"] == "Software"
    url = f"{W(env)}/warpath/exercises/{ex['id']}"
    r = client.put(url, json={"name": "Renamed", "steps": STEPS[:1]})
    assert r.status_code == 200 and len(r.json()["steps"]) == 1
    assert client.post(f"{url}/approve").status_code == 403  # analysts draft, owners approve
    use(client, env["owner"])
    r = client.post(f"{url}/approve")
    assert r.status_code == 200 and r.json()["state"] == "approved"
    assert client.put(url, json={"name": "x", "steps": STEPS}).status_code == 409
    assert client.delete(url).status_code == 409
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        with pytest.raises(DBAPIError, match="approved exercise plan"):
            with conn.begin():
                conn.execute(text("UPDATE warpath_exercises SET plan = '[]'::jsonb"))


def test_exercise_end_to_end(
    client: TestClient, blacksite: TestClient, env, owner_db: Session
) -> None:
    _active_lab_scope(client, env)
    ex = draft(client, env).json()
    url = f"{W(env)}/warpath/exercises/{ex['id']}"
    use(client, env["owner"])
    client.post(f"{url}/approve")
    ex = client.post(f"{url}/start").json()
    assert ex["state"] == "running" and ex["steps"][0]["attack_state"] == "ready"
    run_id = ex["workflow_run_id"]
    # Approving and starting ran nothing.
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0

    # The hosted app can't start a lab step (D3): the step is blocked with the reason.
    r = client.post(f"{W(env)}/workflow-runs/{run_id}/steps/s1_attack/start").json()
    s1 = {s["key"]: s for s in r["steps"]}["s1_attack"]
    assert s1["state"] == "blocked" and "BLACKSITE" in s1["detail"]

    def run_step(key: str) -> None:
        use(blacksite, env["owner"])
        r = blacksite.post(f"{W(env)}/workflow-runs/{run_id}/steps/{key}/start")
        assert r.status_code == 200, r.text
        step = {s["key"]: s for s in r.json()["steps"]}[key]
        assert step["state"] == "running", step
        for pr in step["outputs"]["playbook_run_ids"]:
            assert (
                blacksite.post(f"{W(env)}/blackops/runs/{pr}/approve", json={}).status_code == 200
            )
        w = lab_worker({"headers": lab_headers()})
        while w.run_once():
            pass

    run_step("s1_attack")
    use(client, env["viewer"])
    ex = client.get(url).json()
    assert (
        ex["steps"][0]["attack_state"] == "succeeded" and ex["steps"][0]["score_state"] == "running"
    )
    # NEXUS's generic "mark done" is refused: WARPATH reviews need a score.
    use(client, env["analyst"])
    r = client.post(f"{W(env)}/workflow-runs/{run_id}/steps/s1_score/complete", json={})
    assert r.status_code == 409
    assert client.post(f"{url}/steps/2/score", json={"attack_result": "succeeded",
                       "detection": "missed"}).status_code == 409  # not run yet  # fmt: skip
    r = client.post(
        f"{url}/steps/1/score",
        json={"attack_result": "succeeded", "detection": "missed", "note": "No WAF rule"},
    )
    assert r.status_code == 200 and r.json()["steps"][1]["attack_state"] == "ready"
    alerts = client.get(f"{W(env)}/alerts").json()
    assert [(a["kind"], a["severity"]) for a in alerts] == [("detection.gap", "medium")]
    assert "T1592.002" in alerts[0]["title"] and alerts[0]["recommendation"]

    run_step("s2_attack")
    use(client, env["analyst"])
    r = client.post(
        f"{url}/steps/2/score",
        json={"attack_result": "succeeded", "detection": "detected", "minutes_to_detect": 4},
    ).json()
    assert r["state"] == "finished"
    card = r["scorecard"]
    assert (card["steps"], card["scored"], card["detected"], card["missed"]) == (2, 2, 1, 1)
    assert card["by_tactic"]["reconnaissance"] == {
        "detected": 1, "partial": 0, "missed": 1, "not_scored": 0,
    }  # fmt: skip
    assert card["median_minutes_to_detect"] == 4.0
    # Re-scoring adds history; the latest counts.
    r = client.post(
        f"{url}/steps/1/score", json={"attack_result": "succeeded", "detection": "partial"}
    )
    assert r.json()["scorecard"]["partial"] == 1
    assert owner_db.execute(text("SELECT count(*) FROM warpath_scores")).scalar_one() == 3
    use(client, env["viewer"])
    hist = client.get(f"{W(env)}/projects/{env['pid']}/chronicle").json()["entries"]
    assert "warpath.scored" in [e["action"] for e in hist]


def test_app_role_may_only_raise_detection_gap_alerts(
    client: TestClient, env, app_engine: Engine
) -> None:
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        with pytest.raises(DBAPIError):
            with conn.begin():
                conn.execute(
                    text(
                        "INSERT INTO alerts (workspace_id, project_id, kind, severity, title, "
                        "dedupe_key, rules) VALUES (:w, :p, 'tls.weakened', 'high', 'x', 'k', 'r')"
                    ),
                    {"w": env["ws"], "p": env["pid"]},
                )
