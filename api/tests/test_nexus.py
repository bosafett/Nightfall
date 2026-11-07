# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""NEXUS v1: workflows of ordinary, separately checked and approved steps."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.nexus import engine
from nightfall.nexus.definitions import (
    WORKFLOWS,
    DefinitionError,
    StepDef,
    WorkflowDef,
    validate,
)
from tests.conftest import audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture

HOST = "www.example.com"


def W(env) -> str:  # noqa: N802
    return f"/api/workspaces/{env['ws']}"


def drain() -> None:
    w = make_worker()
    while w.run_once():
        pass


def start(client: TestClient, env, who: str = "owner", **body) -> dict:  # type: ignore[no-untyped-def]
    use(client, env[who])
    body = {"workflow_id": "exposure-review", "target": HOST, **body}
    r = client.post(f"{W(env)}/projects/{env['pid']}/workflows", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def steps(run: dict) -> dict[str, dict]:
    return {s["key"]: s for s in run["steps"]}


def act(client: TestClient, env, who: str, run: dict, path: str, body=None):  # type: ignore[no-untyped-def]
    use(client, env[who])
    return client.post(f"{W(env)}/workflow-runs/{run['id']}/{path}", json=body or {})


def get(client: TestClient, env, run: dict, who: str = "owner") -> dict:  # type: ignore[no-untyped-def]
    use(client, env[who])
    r = client.get(f"{W(env)}/workflow-runs/{run['id']}")
    assert r.status_code == 200, r.text
    return r.json()


def approve_step(client: TestClient, env, step: dict) -> None:  # type: ignore[no-untyped-def]
    use(client, env["operator"])
    for pr in step["outputs"]["playbook_run_ids"]:
        r = client.post(f"{W(env)}/blackops/runs/{pr}/approve", json={})
        assert r.status_code == 200, r.text
    drain()


def test_definitions_are_valid_and_pinned_steps_are_explicit() -> None:
    for w in WORKFLOWS.values():
        validate(w)
        assert len(w.sha256) == 64
    bad = [
        StepDef("a", "A", "review", "x", depends_on=("b",)),  # later or unknown dependency
    ]
    with pytest.raises(DefinitionError, match="isn't earlier"):
        validate(WorkflowDef("x", "X", "1", "", "target", tuple(bad), timedelta(days=1), ()))
    with pytest.raises(DefinitionError, match="isn't available"):
        validate(
            WorkflowDef(
                "x",
                "X",
                "1",
                "",
                "target",
                (StepDef("a", "A", "shield.evaluate", "x"),),  # type: ignore[arg-type]
                timedelta(days=1),
                (),
            )
        )
    with pytest.raises(DefinitionError, match="only executing steps may retry"):
        validate(
            WorkflowDef(
                "x",
                "X",
                "1",
                "",
                "target",
                (StepDef("a", "A", "review", "x", retries=1),),
                timedelta(days=1),
                (),
            )
        )


def test_exposure_review_end_to_end(client: TestClient, env, owner_db: Session) -> None:
    # Starting approves nothing: the first step waits for a person.
    run = start(client, env)
    st = steps(run)
    assert run["state"] == "running" and st["assess"]["state"] == "ready"
    assert all(st[k]["state"] == "pending" for k in ("triage", "decide", "fixed", "reassess"))
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0

    # A person starts it through the normal playbook launch: its operation awaits approval.
    run = act(client, env, "owner", run, "steps/assess/start").json()
    assess = steps(run)["assess"]
    assert assess["state"] == "running" and assess["attempt"] == 1
    status = owner_db.execute(text("SELECT status FROM operations")).scalar_one()
    assert status == "awaiting_approval"
    approve_step(client, env, assess)

    run = get(client, env, run, who="viewer")  # any member can follow it
    st = steps(run)
    assert st["assess"]["state"] == "succeeded" and st["triage"]["state"] == "running"
    assert len(run["tracked"]) == 4 and {f["status"] for f in run["tracked"]} == {"unverified"}

    # Review: analysts may complete it; checkpoint: analysts may not answer it.
    assert act(client, env, "viewer", run, "steps/triage/complete").status_code == 403
    run = act(client, env, "analyst", run, "steps/triage/complete", {"note": "Looked"}).json()
    assert steps(run)["decide"]["state"] == "running"
    no = act(client, env, "analyst", run, "steps/decide/answer", {"answer": "continue"})
    assert no.status_code == 403
    run = act(client, env, "operator", run, "steps/decide/answer", {"answer": "continue"}).json()
    assert steps(run)["fixed"]["state"] == "running"

    # Fixes are recorded by people on the findings; the wait step notices.
    use(client, env["analyst"])
    for i, f in enumerate(run["tracked"]):
        body = {"status": "remediated" if i == 0 else "false_positive", "note": "done"}
        assert client.post(f"{W(env)}/findings/{f['id']}/status", json=body).status_code == 200
    run = get(client, env, run)
    st = steps(run)
    assert st["fixed"]["state"] == "succeeded" and st["reassess"]["state"] == "ready"

    # Reassessment re-runs the same playbook: a new operation with its own approval.
    run = act(client, env, "owner", run, "steps/reassess/start").json()
    re = steps(run)["reassess"]
    assert re["state"] == "running"
    assert re["outputs"]["plan"] == [
        {"via": "playbook", "playbook_id": "http-security-assessment", "target": HOST}
    ]
    assert (
        owner_db.execute(
            text("SELECT count(*) FROM operations WHERE status = 'awaiting_approval'")
        ).scalar_one()
        == 1
    )
    approve_step(client, env, re)
    run = get(client, env, run)
    assert steps(run)["verify"]["state"] == "running"
    # BLACK ICE reopened the remediated finding, since the fixture target still shows it.
    assert sorted(f["status"] for f in run["tracked"]).count("false_positive") == 3
    run = act(client, env, "analyst", run, "steps/verify/complete").json()
    assert run["state"] == "succeeded" and run["finished_at"]

    # History: every transition recorded, automatic ones without a person.
    events = run["events"]
    assert {(e["step_key"], e["to_state"]) for e in events} >= {
        ("assess", "ready"),
        ("assess", "running"),
        ("verify", "succeeded"),
    }
    assert any(e["actor"] == "NEXUS" for e in events)
    assert any(e["actor"] != "NEXUS" for e in events)
    actions = audit_actions(owner_db)
    for a in (
        "workflow.started",
        "workflow.step_started",
        "workflow.review_completed",
        "workflow.checkpoint_answered",
        "workflow.finished",
    ):
        assert a in actions, a
    use(client, env["viewer"])
    hist = client.get(f"{W(env)}/projects/{env['pid']}/chronicle").json()["entries"]
    assert "workflow.finished" in [e["action"] for e in hist]


def test_stop_at_checkpoint_skips_the_rest(client: TestClient, env) -> None:
    run = start(client, env)
    run = act(client, env, "owner", run, "steps/assess/start").json()
    approve_step(client, env, steps(run)["assess"])
    run = act(client, env, "analyst", get(client, env, run), "steps/triage/complete").json()
    run = act(client, env, "operator", run, "steps/decide/answer", {"answer": "stop"}).json()
    st = steps(run)
    assert run["state"] == "succeeded"
    assert {st[k]["state"] for k in ("fixed", "reassess", "verify")} == {"skipped"}


def test_checks_happen_when_a_step_starts(client: TestClient, env, owner_db: Session) -> None:
    """A run started under one scope can't carry a step past a later exclusion."""
    run = start(client, env)
    use(client, env["owner"])
    base = W(env)
    draft = client.post(f"{base}/projects/{env['pid']}/scopes").json()
    assert (
        client.post(
            f"{base}/scopes/{draft['id']}/exclusions", json={"kind": "host", "value": HOST}
        ).status_code
        == 201
    )
    assert client.post(f"{base}/scopes/{draft['id']}/authorize").status_code == 200
    run = act(client, env, "owner", run, "steps/assess/start").json()
    a = steps(run)["assess"]
    assert a["state"] == "blocked" and "Couldn't start" in a["detail"]
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0
    acts = audit_actions(owner_db)
    assert "workflow.step_blocked" in acts and "playbook.denied" in acts


def test_permissions_and_refusals(client: TestClient, env) -> None:
    use(client, env["analyst"])
    url = f"{W(env)}/projects/{env['pid']}/workflows"
    body = {"workflow_id": "exposure-review", "target": HOST}
    assert client.post(url, json=body).status_code == 403  # can't run every step
    use(client, env["owner"])
    assert client.post(url, json={**body, "target": "evil.test"}).status_code == 422
    assert client.post(url, json={**body, "target": "mail.example.com"}).status_code == 422
    run = start(client, env)
    assert client.post(url, json=body).status_code == 409  # one at a time per target
    # Operators may start steps but not launch playbooks.
    r = act(client, env, "operator", run, "steps/assess/start").json()
    assert steps(r)["assess"]["state"] == "blocked"
    # Steps that start themselves can't be started by hand; a review can't be answered.
    assert act(client, env, "owner", run, "steps/triage/start").status_code == 409
    assert act(client, env, "owner", run, "steps/triage/complete").status_code == 409
    # Reassessment needs a remediated finding.
    use(client, env["owner"])
    r = client.post(url, json={"workflow_id": "remediation-reassessment"})
    assert r.status_code == 404


def test_cancel_and_deadlines(client: TestClient, env, owner_db: Session) -> None:
    run = start(client, env)
    run = act(client, env, "owner", run, "steps/assess/start").json()
    r = act(client, env, "operator", run, "cancel", {"reason": "Wrong host"}).json()
    assert r["state"] == "cancelled" and r["cancel_reason"] == "Wrong host"
    assert {s["state"] for s in r["steps"]} == {"cancelled"}
    status = owner_db.execute(text("SELECT status FROM operations")).scalar_one()
    assert status == "cancelled"  # its unapproved operation went with it
    assert act(client, env, "owner", run, "steps/assess/start").status_code == 409

    # A step past its deadline times out; with a retry left, a person can try again.
    run = start(client, env)
    run = act(client, env, "owner", run, "steps/assess/start").json()
    owner_db.execute(
        text(
            "UPDATE workflow_steps SET deadline = now() - interval '1 minute' WHERE key='assess'"
            " AND run_id = :r"
        ),
        {"r": run["id"]},
    )
    owner_db.commit()
    run = get(client, env, run)
    a = steps(run)["assess"]
    assert a["state"] == "timed_out" and a["can_retry"] and run["state"] == "running"
    run = act(client, env, "owner", run, "steps/assess/retry").json()
    assert steps(run)["assess"]["state"] == "ready"
    run = act(client, env, "owner", run, "steps/assess/start").json()
    assert steps(run)["assess"]["attempt"] == 2
    owner_db.execute(
        text(
            "UPDATE workflow_steps SET deadline = now() - interval '1 minute' WHERE key='assess'"
            " AND run_id = :r"
        ),
        {"r": run["id"]},
    )
    owner_db.commit()
    run = get(client, env, run)  # no retries left: the run fails
    assert run["state"] == "failed"
    assert act(client, env, "owner", run, "steps/assess/retry").status_code == 409


def test_remediation_reassessment(client: TestClient, env) -> None:
    run = start(client, env)
    run = act(client, env, "owner", run, "steps/assess/start").json()
    approve_step(client, env, steps(run)["assess"])
    finding = get(client, env, run)["tracked"][0]
    use(client, env["analyst"])
    client.post(
        f"{W(env)}/findings/{finding['id']}/status", json={"status": "remediated", "note": "Fixed"}
    )
    r2 = start(
        client, env, workflow_id="remediation-reassessment", target=None, finding_id=finding["id"]
    )
    assert r2["subject"].endswith(finding["title"])
    assert steps(r2)["reassess"]["state"] == "ready"
    r2 = act(client, env, "owner", r2, "steps/reassess/start").json()
    approve_step(client, env, steps(r2)["reassess"])
    r2 = get(client, env, r2)
    assert steps(r2)["verify"]["state"] == "running"
    assert r2["tracked"][0]["status"] == "unverified"  # reopened: still present


def test_database_enforces_transitions_and_history(
    client: TestClient, env, app_engine: Engine
) -> None:
    run = start(client, env)
    with app_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
        )
        conn.commit()
        for stmt in (
            "UPDATE workflow_steps SET state = 'succeeded' WHERE key = 'assess'",  # ready→done
            "UPDATE workflow_steps SET key = 'other'",
            "UPDATE workflow_runs SET definition_id = 'x'",
            "DELETE FROM workflow_step_events",
            "UPDATE workflow_step_events SET detail = 'x'",
            "DELETE FROM workflow_steps",
        ):
            with pytest.raises(DBAPIError):
                with conn.begin():
                    conn.execute(text(stmt))
    assert engine.FINAL and run["id"]
    _ = utcnow
