# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""War Room (Phase 6a): what waits on a person, read from the records."""

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from nightfall.agents.registry import CandidateFinding, GuardianOutput, HunterOutput
from nightfall.core.db.models import Role
from tests.conftest import Factory, use
from tests.phase3_helpers import authorize_scope, org_project
from tests.test_agents import (  # noqa: F401 - fixtures
    FakeProvider,
    _evidence,
    ai_on,
    drain,
    env,
    run_agent,
    worker_with,
)


def room(client: TestClient, env, who: str) -> dict[str, Any]:
    use(client, env[who])
    r = client.get(f"/api/workspaces/{env['ws']}/war-room")
    assert r.status_code == 200, r.text
    return r.json()


def request_http(client: TestClient, env, who: str) -> str:
    use(client, env[who])
    r = client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": "www.example.com"},
    )
    assert r.json()["status"] == "awaiting_approval", r.text
    return r.json()["id"]


def test_awaiting_shows_who_can_decide(client: TestClient, env) -> None:
    op = request_http(client, env, "operator")
    mine = room(client, env, "operator")["awaiting"]
    assert [a["id"] for a in mine] == [op]
    assert mine[0]["can_decide"] is False and "You requested" in mine[0]["why_not"]
    assert mine[0]["target"] == "www.example.com" and mine[0]["scope_version"] == 1
    assert room(client, env, "analyst")["awaiting"][0]["why_not"] == (
        "Your role can't approve operations."
    )
    theirs = room(client, env, "owner")["awaiting"][0]
    assert theirs["can_decide"] is True and theirs["why_not"] is None
    assert theirs["requested_by"] == env["operator"].user.display_name

    # Deciding moves it from "awaiting" to "in flight", and into the decision log.
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/operations/{op}/approve", json={"reason": "in window"}
    )
    assert r.status_code == 200
    after = room(client, env, "viewer")
    assert after["awaiting"] == []
    assert [(f["kind"], f["id"]) for f in after["in_flight"]] == [("operation", op)]
    approved = [d for d in after["decisions"] if d["action"] == "operation.approved"]
    assert approved[0]["actor"] == env["owner"].user.display_name
    assert approved[0]["details"] == {
        "tool": "http",
        "target": "www.example.com",
        "risk_class": "low",
        "reason": "in window",
    }
    # Only listed actions: requests and sign-ins aren't decisions.
    assert {d["action"] for d in after["decisions"]} <= {
        "operation.approved",
        "scope.authorized",
    }


def test_agent_hypotheses_wait_for_a_person(client: TestClient, env, ai_on) -> None:
    ev = _evidence(client, env)
    task = run_agent(client, env, "analyst", "hunter").json()
    assert any(f["kind"] == "agent_task" for f in room(client, env, "viewer")["in_flight"])
    answer = HunterOutput(
        candidates=[
            CandidateFinding(
                title="Old host still certified",
                severity="low",
                asset="www.example.com",
                description="d",
                impact="i",
                remediation="r",
                evidence_ids=[ev],
            )
        ],
        notes="",
    )
    review = GuardianOutput(
        verdict="insufficient_evidence", rationale="r", severity_assessment="agree"
    )
    drain(worker_with(FakeProvider({HunterOutput: answer, GuardianOutput: review})))
    data = room(client, env, "viewer")
    assert data["review_counts"] == {"findings": 1, "attack_paths": 0, "relationships": 0}
    item = data["to_review"][0]
    assert item["kind"] == "finding" and item["proposed_by_task_id"] == task["id"]
    assert item["detail"] == "low · Guardian: insufficient evidence"
    assert data["in_flight"] == []
    # Once a person decides, it leaves the review list.
    use(client, env["owner"])
    client.post(
        f"/api/workspaces/{env['ws']}/findings/{item['id']}/status",
        json={"status": "false_positive", "note": "names only"},
    )
    data = room(client, env, "viewer")
    assert data["review_counts"]["findings"] == 0
    changed = [d for d in data["decisions"] if d["action"] == "finding.status_changed"]
    assert changed[0]["details"] == {
        "from": "hypothesis",
        "to": "false_positive",
        "note": "names only",
    }
    refused_or_requested = {d["action"] for d in data["decisions"]}
    assert "agent_task.requested" in refused_or_requested


def test_war_room_is_tenant_isolated(
    client: TestClient, factory: Factory, env, owner_db: Session
) -> None:
    request_http(client, env, "analyst")
    other = factory.workspace("Other")
    _, opid = org_project(owner_db, other, "Rival")
    stranger = factory.sign_in(factory.member(other, Role.OWNER))
    use(client, stranger)
    authorize_scope(client, other, opid, [("domain_tree", "rival.test")])
    mine = client.get(f"/api/workspaces/{other}/war-room").json()
    assert mine["awaiting"] == [] and all(
        d["action"] == "scope.authorized" for d in mine["decisions"]
    )
    assert client.get(f"/api/workspaces/{env['ws']}/war-room").status_code in (403, 404)


def test_bell_counts_only_what_you_can_decide(client: TestClient, env) -> None:
    request_http(client, env, "operator")

    def bell(who: str) -> dict[str, int]:
        use(client, env[who])
        return client.get(f"/api/workspaces/{env['ws']}/war-room/summary").json()

    assert bell("operator") == {"awaiting_you": 0, "awaiting_total": 1}  # own request
    assert bell("analyst") == {"awaiting_you": 0, "awaiting_total": 1}  # role can't approve
    assert bell("owner") == {"awaiting_you": 1, "awaiting_total": 1}


def test_assessment_completion_counts_agent_tasks(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    from sqlalchemy import text

    owner_db.execute(text("UPDATE projects SET status = 'active' WHERE id = :p"), {"p": env["pid"]})
    owner_db.commit()

    def item() -> dict[str, Any]:
        use(client, env["viewer"])
        rows = client.get(f"/api/workspaces/{env['ws']}/overview").json()["assessments"]
        return next(r for r in rows if r["id"] == str(env["pid"]))

    assert (item()["agent_tasks_total"], item()["agent_tasks_done"]) == (0, 0)
    run_agent(client, env, "analyst", "hunter")
    assert (item()["agent_tasks_total"], item()["agent_tasks_done"]) == (1, 0)
    drain(worker_with(FakeProvider({HunterOutput: HunterOutput(candidates=[], notes="")})))
    assert (item()["agent_tasks_total"], item()["agent_tasks_done"]) == (1, 1)
