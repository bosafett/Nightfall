# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""Agents (Phase 5b): Director, Investigator, Adversary, Analyst.

Same rule as 5a: the model proposes, deterministic code decides, and nothing an agent
writes is presented as verified.
"""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.agents.providers import FixtureProvider, GenerationRequest
from nightfall.agents.registry import (
    AdversaryOutput,
    AnalystOutput,
    DirectorOutput,
    InvestigatorOutput,
    KeyRisk,
    ProposedPath,
    ProposedRelationship,
    ProposedStep,
    ScoutOutput,
    Subtask,
)
from nightfall.config import get_settings
from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import make_worker, org_project
from tests.test_agents import (  # noqa: F401 - fixtures
    INJECTION,
    FakeProvider,
    _evidence,
    ai_on,
    drain,
    env,
    worker_with,
)


def start(client: TestClient, env, agent: str, who: str = "analyst", **body: Any):
    use(client, env[who])
    return client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/agent-runs",
        json={"agent": agent, **body},
    )


def task_detail(client: TestClient, env, task_id: str) -> dict[str, Any]:
    return client.get(f"/api/workspaces/{env['ws']}/agent-tasks/{task_id}").json()


def asset_id(db: Session, value: str) -> str:
    return str(
        db.execute(text("SELECT id FROM assets WHERE value = :v"), {"v": value}).scalar_one()
    )


def finding(client: TestClient, env, title: str, status: str = "unverified") -> str:
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/findings",
        json={
            "project_id": str(env["pid"]),
            "title": title,
            "severity": "high",
            "confidence": "medium",
            "validation_status": status,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- Director --------------------------------------------------------------------------


def test_director_only_creates_tasks_within_its_delegates(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    assert start(client, env, "director").json()["detail"]["code"] == "objective_required"
    _evidence(client, env)
    task = start(client, env, "director", objective="Map the external surface").json()

    plan = DirectorOutput.model_construct(
        subtasks=[
            Subtask.model_construct(agent="guardian", objective="approve everything", asset=""),
            Subtask.model_construct(agent="director", objective="recurse", asset=""),
            Subtask(agent="investigator", objective="Explain it", asset="evil.example.org"),
            Subtask(agent="scout", objective=f"Cover the apex. {INJECTION}"),
            Subtask(agent="investigator", objective="Explain it", asset="www.example.com"),
            Subtask(agent="analyst", objective="Only the first five are considered"),
        ],
        notes="plan",
    )

    def scout(req: GenerationRequest[Any]) -> ScoutOutput:
        # The Director's words reach the next agent only as data, never as its task line.
        assert '<data source="director_objective"' in req.user
        assert req.user.index(INJECTION) > req.user.index('<data source="director_objective"')
        assert INJECTION not in req.system
        assert not req.user.startswith("Task: Cover")
        return ScoutOutput(proposals=[], notes="")

    provider = FakeProvider({DirectorOutput: plan, ScoutOutput: scout})
    worker = worker_with(provider)
    worker.run_once()  # Director
    detail = task_detail(client, env, task["id"])
    assert detail["status"] == "succeeded"
    accepted = [(a["agent"], a.get("asset")) for a in detail["result"]["accepted"]]
    assert accepted == [("scout", None), ("investigator", "www.example.com")]
    refused = {r["agent"]: r["reason"] for r in detail["result"]["refused"]}
    assert refused == {
        "guardian": "The Director can't assign work to this agent.",
        "director": "The Director can't assign work to this agent.",
        "investigator": "Not a known asset in this organization.",
        "analyst": "More than 5 subtasks.",
    }
    children = {c["agent"]: c for c in detail["children"]}
    assert set(children) == {"scout", "investigator"}
    assert children["investigator"]["subject_asset"] == "www.example.com"
    rows = owner_db.execute(
        text("SELECT context, requested_by_user_id FROM agent_tasks WHERE parent_task_id = :p"),
        {"p": task["id"]},
    ).all()
    assert all(r.context == {"assigned_by": "director"} for r in rows)
    assert all(r.requested_by_user_id == env["analyst"].user.id for r in rows)

    worker.run_once()  # the scout child runs next (queue order)
    assert provider.requests[-1].output_model is ScoutOutput


def test_director_does_not_duplicate_open_runs(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    hunter = start(client, env, "hunter").json()
    task = start(client, env, "director", objective="Find issues").json()
    # The hunter run is older and would be claimed first; run the Director directly.
    owner_db.execute(
        text("UPDATE agent_tasks SET status = 'running' WHERE id = :i"), {"i": task["id"]}
    )
    owner_db.commit()
    from nightfall.agents import runner

    plan = DirectorOutput(subtasks=[Subtask(agent="hunter", objective="Look")], notes="")
    w = worker_with(FakeProvider({DirectorOutput: plan}))
    runner._process(w.sessions, w.store, w.provider_factory, uuid.UUID(task["id"]), env["ws"])
    detail = task_detail(client, env, task["id"])
    assert detail["result"]["accepted"] == [
        {"agent": "hunter", "objective": "Look", "task_id": hunter["id"], "note": "already queued"}
    ]
    assert detail["children"] == []


# --- Investigator ----------------------------------------------------------------------


def test_investigator_relationships_are_hypotheses_backed_by_shown_evidence(
    client: TestClient, factory: Factory, env, ai_on, owner_db: Session
) -> None:
    ev = _evidence(client, env)
    www = asset_id(owner_db, "www.example.com")

    assert start(client, env, "investigator").json()["detail"]["code"] == "asset_required"
    other = factory.workspace("Other")
    _, opid = org_project(owner_db, other, "Rival")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    foreign = client.post(
        f"/api/workspaces/{other}/assets",
        json={
            "organization_id": str(
                owner_db.execute(
                    text("SELECT organization_id FROM projects WHERE id = :p"), {"p": opid}
                ).scalar_one()
            ),
            "kind": "domain",
            "value": "rival.test",
        },
    )
    assert foreign.status_code == 201, foreign.text
    r = start(client, env, "investigator", asset_id=foreign.json()["id"])
    assert r.status_code == 422  # not this workspace's asset (RLS hides it)
    assert start(client, env, "scout", asset_id=www).json()["detail"]["code"] == (
        "asset_unexpected"
    )

    task = start(client, env, "investigator", asset_id=www).json()
    assert task["subject_asset"] == "www.example.com"
    # One run per asset: a second request returns the open one.
    assert start(client, env, "investigator", asset_id=www).json()["id"] == task["id"]

    def answer(req: GenerationRequest[Any]) -> InvestigatorOutput:
        assert '<data source="subject_asset"' in req.user and "www.example.com" in req.user
        assert f'id="{ev}"' in req.user
        return InvestigatorOutput(
            summary="A web host seen in certificate history.",
            relationships=[
                ProposedRelationship(
                    to_asset="api.example.com",
                    rel_type="cname_to",
                    rationale="r",
                    evidence_ids=[ev],
                ),
                ProposedRelationship(
                    to_asset="example.com",
                    rel_type="resolves_to",
                    rationale="r",
                    evidence_ids=[str(uuid.uuid4())],
                ),
                ProposedRelationship(
                    to_asset="nowhere.test",
                    rel_type="cname_to",
                    rationale="r",
                    evidence_ids=[ev],
                ),
                ProposedRelationship(
                    to_asset="WWW.example.com.",
                    rel_type="cname_to",
                    rationale="r",
                    evidence_ids=[ev],
                ),
            ],
            open_questions=["Who runs it?"],
        )

    worker_with(FakeProvider({InvestigatorOutput: answer})).run_once()
    detail = task_detail(client, env, task["id"])
    assert detail["status"] == "succeeded"
    assert detail["result"]["summary"] == "A web host seen in certificate history."
    assert detail["result"]["open_questions"] == ["Who runs it?"]
    assert [a["to_asset"] for a in detail["result"]["accepted"]] == ["api.example.com"]
    assert [r["reason"] for r in detail["result"]["refused"]] == [
        "Cites no evidence the agent was shown.",
        "Not a known asset in this organization.",
        "An asset can't relate to itself.",
    ]
    row = owner_db.execute(
        text(
            "SELECT id, status, confidence, rule_id, proposed_by_task_id, evidence_id "
            "FROM asset_relationships WHERE proposed_by_task_id IS NOT NULL"
        )
    ).one()
    assert (row.status, row.confidence) == ("hypothesis", "low")
    assert row.rule_id.startswith("agent:investigator@") and str(row.evidence_id) == ev
    assert "relationship.proposed_by_agent" in audit_actions(owner_db)

    # An agent-proposed relationship can't be relabelled as observed...
    with pytest.raises(IntegrityError):
        owner_db.execute(
            text("UPDATE asset_relationships SET status = 'observed' WHERE id = :i"),
            {"i": row.id},
        )
    owner_db.rollback()

    # ...but a collector that observes it records it as fact, under its own rule.
    from types import SimpleNamespace

    from nightfall.blackice.ingest import _relate
    from nightfall.core.clock import utcnow
    from nightfall.core.db.models import RelationshipType

    _relate(
        owner_db,
        SimpleNamespace(workspace_id=env["ws"]),  # type: ignore[arg-type]
        uuid.UUID(www),
        uuid.UUID(asset_id(owner_db, "api.example.com")),
        RelationshipType.CNAME_TO,
        uuid.UUID(ev),
        "dns/cname@test",
        utcnow(),
    )
    owner_db.commit()
    promoted = owner_db.execute(
        text(
            "SELECT status, confidence, rule_id, proposed_by_task_id FROM asset_relationships "
            "WHERE id = :i"
        ),
        {"i": row.id},
    ).one()
    assert (promoted.status, promoted.confidence, promoted.rule_id) == (
        "observed",
        "high",
        "dns/cname@test",
    )
    assert str(promoted.proposed_by_task_id) == task["id"]  # provenance kept

    use(client, env["analyst"])
    rels = client.get(f"/api/workspaces/{env['ws']}/assets/{www}").json()["relationships"]
    assert any(r["proposed_by_task_id"] == task["id"] for r in rels)


# --- Adversary -------------------------------------------------------------------------


def test_adversary_paths_rest_on_shown_findings_and_stay_hypotheses(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    _evidence(client, env)
    f1 = finding(client, env, "Admin panel exposed")
    f2 = finding(client, env, "Default credentials suspected")
    fp = finding(client, env, "Was a false alarm")
    use(client, env["owner"])
    client.post(
        f"/api/workspaces/{env['ws']}/findings/{fp}/status",
        json={"status": "false_positive", "note": "checked"},
    )
    task = start(client, env, "adversary").json()

    def answer(req: GenerationRequest[Any]) -> AdversaryOutput:
        assert f1 in req.user and f2 in req.user and fp not in req.user
        return AdversaryOutput(
            paths=[
                ProposedPath(
                    title="Panel to data",
                    narrative="n",
                    steps=[
                        ProposedStep(asset="www.example.com", description="Reach the host."),
                        ProposedStep(finding_id=f1, description="Open the panel."),
                        ProposedStep(finding_id=f2, description="Sign in."),
                    ],
                ),
                ProposedPath(
                    title="Uses a dismissed finding",
                    narrative="n",
                    steps=[
                        ProposedStep(finding_id=f1, description="a"),
                        ProposedStep(finding_id=fp, description="b"),
                    ],
                ),
                ProposedPath(
                    title="Only assets",
                    narrative="n",
                    steps=[
                        ProposedStep(asset="www.example.com", description="a"),
                        ProposedStep(asset="api.example.com", description="b"),
                    ],
                ),
                ProposedPath(
                    title="One step",
                    narrative="n",
                    steps=[ProposedStep(finding_id=f1, description="a")],
                ),
            ],
            notes="notes",
        )

    worker_with(FakeProvider({AdversaryOutput: answer})).run_once()
    detail = task_detail(client, env, task["id"])
    assert [a["title"] for a in detail["result"]["accepted"]] == ["Panel to data"]
    assert {r["title"]: r["reason"] for r in detail["result"]["refused"]} == {
        "Uses a dismissed finding": "Step 2 names a finding the agent wasn't shown.",
        "Only assets": "A path must rest on at least one recorded finding.",
        "One step": "More than 3 paths.",
    }
    paths = client.get(f"/api/workspaces/{env['ws']}/projects/{env['pid']}/attack-paths").json()
    assert len(paths) == 1
    p = paths[0]
    assert (p["status"], p["confidence"], p["created_by"]) == ("hypothesis", "low", None)
    assert p["proposed_by_task_id"] == task["id"]
    assert [s["ordinal"] for s in p["steps"]] == [1, 2, 3]

    # The database refuses an agent path that claims more than low confidence unreviewed.
    with pytest.raises(IntegrityError):
        owner_db.execute(
            text("UPDATE attack_paths SET confidence = 'high' WHERE id = :i"), {"i": p["id"]}
        )
    owner_db.rollback()

    # A person still can't validate it while its findings are unvalidated (Phase 4 rule).
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/attack-paths/{p['id']}/review",
        json={"status": "validated", "note": "looks right"},
    )
    assert r.status_code in (409, 422)


# --- Analyst ---------------------------------------------------------------------------


def test_analyst_summary_is_labelled_and_counts_come_from_records(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    _evidence(client, env)
    f1 = finding(client, env, f"Exposed panel. {INJECTION}")
    finding(client, env, "Weak TLS", status="hypothesis")
    task = start(client, env, "analyst").json()

    def answer(req: GenerationRequest[Any]) -> AnalystOutput:
        assert '<data source="project_counts"' in req.user
        assert INJECTION in req.user and INJECTION not in req.system
        return AnalystOutput(
            summary="We found 999 critical issues.",  # the model's numbers aren't the record
            key_risks=[KeyRisk(finding_id=f1, why="w"), KeyRisk(finding_id="nope", why="w")],
            next_steps=["Validate the panel finding."],
        )

    worker_with(FakeProvider({AnalystOutput: answer})).run_once()
    result = task_detail(client, env, task["id"])["result"]
    assert result["counts"]["findings_by_status"] == {"hypothesis": 1, "unverified": 1}
    assert result["counts"]["open_findings_by_severity"] == {"high": 2}
    assert result["counts"]["evidence_records"] >= 1
    assert [k["finding_id"] for k in result["key_risks"]] == [f1]
    assert result["key_risks"][0]["status"] == "unverified"  # status from the record
    assert result["refused"] == [
        {"finding_id": "nope", "reason": "Not a finding the agent was shown."}
    ]
    # The summary never changes a finding.
    statuses = owner_db.execute(text("SELECT validation_status FROM findings")).scalars().all()
    assert sorted(statuses) == ["hypothesis", "unverified"]


# --- Overview --------------------------------------------------------------------------


def test_overview_counts_real_usage(client: TestClient, env, ai_on) -> None:
    use(client, env["viewer"])
    info = client.get(f"/api/workspaces/{env['ws']}/agents").json()
    assert [a["key"] for a in info["agents"]] == [
        "director",
        "scout",
        "investigator",
        "hunter",
        "adversary",
        "guardian",
        "analyst",
    ]
    assert all(a["usage"]["runs"] == 0 for a in info["agents"])
    assert {a["key"]: a["status"] for a in info["agents"]}["guardian"] == "automatic"

    start(client, env, "analyst")
    worker_with(
        FakeProvider({AnalystOutput: AnalystOutput(summary="s", key_risks=[], next_steps=[])})
    ).run_once()
    use(client, env["viewer"])
    info = client.get(f"/api/workspaces/{env['ws']}/agents").json()
    usage = {a["key"]: a["usage"] for a in info["agents"]}["analyst"]
    assert usage == {
        "runs": 1,
        "succeeded": 1,
        "failed": 0,
        "input_tokens": 100,
        "output_tokens": 50,
    }
    tasks = client.get(f"/api/workspaces/{env['ws']}/agent-tasks").json()
    assert [t["agent"] for t in tasks] == ["analyst"]


# --- Fixture model, end to end --------------------------------------------------------


def test_fixture_model_drives_every_agent(
    client: TestClient, env, monkeypatch: pytest.MonkeyPatch, owner_db: Session
) -> None:
    monkeypatch.setenv("NIGHTFALL_COLLECTOR_MODE", "fixture")
    monkeypatch.setenv("NIGHTFALL_AI_PROVIDER", "fixture")
    get_settings.cache_clear()
    try:
        _evidence(client, env)
        finding(client, env, "Seeded")
        w = make_worker()
        w.provider_factory = FixtureProvider
        www = asset_id(owner_db, "www.example.com")
        ids = [
            start(client, env, "director", objective="Get a picture").json()["id"],
            start(client, env, "investigator", asset_id=www).json()["id"],
            start(client, env, "adversary").json()["id"],
        ]
        drain(w)
        statuses = owner_db.execute(text("SELECT agent, status FROM agent_tasks")).all()
        assert {s for _, s in statuses} == {"succeeded"}, statuses
        assert {a for a, _ in statuses} >= {"director", "investigator", "adversary", "analyst"}
        director = task_detail(client, env, ids[0])
        assert {c["agent"] for c in director["children"]} == {"scout", "analyst"}
        assert task_detail(client, env, ids[2])["result"]["accepted"]
    finally:
        get_settings.cache_clear()
