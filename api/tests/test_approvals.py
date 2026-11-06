import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.recon.collectors import HttpFingerprint, collectors
from nightfall.recon.safe_http import SafeHttp
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import authorize_scope, make_worker, org_project


@pytest.fixture
def env(client: TestClient, factory: Factory, owner_db: Session):
    ws = factory.workspace()
    oid, pid = org_project(owner_db, ws)
    owner = factory.sign_in(factory.member(ws, Role.OWNER))
    use(client, owner)
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    analyst = factory.sign_in(factory.member(ws, Role.ANALYST))
    operator = factory.sign_in(factory.member(ws, Role.OPERATOR))
    return {"ws": ws, "pid": pid, "owner": owner, "analyst": analyst, "operator": operator}


def request_http(client, env, who="analyst", target="www.example.com"):
    use(client, env[who])
    return client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": target},
    )


def act(client, env, who, op_id, action, reason=""):
    use(client, env[who])
    return client.post(
        f"/api/workspaces/{env['ws']}/operations/{op_id}/{action}", json={"reason": reason}
    )


def test_low_risk_waits_for_a_second_person(client: TestClient, env, owner_db: Session) -> None:
    r = request_http(client, env)
    assert r.status_code == 202 and r.json()["status"] == "awaiting_approval"
    op_id = r.json()["id"]
    assert make_worker().run_once() is False  # nothing runs before approval

    assert act(client, env, "analyst", op_id, "approve").status_code == 403  # role can't approve
    ok = act(client, env, "operator", op_id, "approve", "Client confirmed window")
    assert ok.status_code == 200
    body = ok.json()
    assert body["status"] == "queued"
    assert (
        body["approval"]["decision"] == "approved" and body["approval"]["decided_by"] == "Operator"
    )

    make_worker().run_once()
    use(client, env["analyst"])
    done = client.get(f"/api/workspaces/{env['ws']}/operations/{op_id}").json()
    assert done["status"] == "succeeded"
    techs = {t["name"] for t in done["result_summary"]["technologies"]}
    assert {"nginx", "PHP", "WordPress"} <= techs
    assert {"operation.requested", "operation.approved", "operation.completed"} <= set(
        audit_actions(owner_db)
    )


def test_single_operator_owner_approves_their_own(client: TestClient, env, owner_db) -> None:
    """D1: one operator. The owner explicitly approves their own request, recorded as theirs."""
    op_id = request_http(client, env, who="owner").json()["id"]
    r = act(client, env, "owner", op_id, "approve", "Owner approval")
    assert r.status_code == 200 and r.json()["status"] == "queued"
    approver = owner_db.execute(
        text("SELECT approver_user_id FROM approvals WHERE operation_id = :o"), {"o": op_id}
    ).scalar_one()
    assert approver == env["owner"].user.id


def test_only_the_owner_may_approve_their_own(client: TestClient, env) -> None:
    op_id = request_http(client, env, who="operator").json()["id"]
    r = act(client, env, "operator", op_id, "approve")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "self_approval"


def test_two_person_policy_still_available(client: TestClient, env, owner_db) -> None:
    owner_db.execute(
        text("UPDATE workspaces SET approval_policy = 'two_person' WHERE id = :w"),
        {"w": env["ws"]},
    )
    owner_db.commit()
    op_id = request_http(client, env, who="owner").json()["id"]
    r = act(client, env, "owner", op_id, "approve")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "self_approval"
    assert act(client, env, "operator", op_id, "approve").status_code == 200


def test_approval_needs_fresh_two_factor(client: TestClient, env, owner_db) -> None:
    op_id = request_http(client, env, who="owner").json()["id"]
    owner_db.execute(text("UPDATE sessions SET mfa_verified_at = now() - interval '16 minutes'"))
    owner_db.commit()
    r = act(client, env, "owner", op_id, "approve")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "step_up_required"
    reasons = (
        owner_db.execute(
            text("SELECT data->>'reason' FROM audit_events WHERE action = 'authz.denied'")
        )
        .scalars()
        .all()
    )
    assert "mfa_stale" in reasons


@pytest.mark.parametrize("policy", ["single_operator", "two_person"])
def test_database_also_blocks_self_approval(
    client: TestClient, env, owner_db: Session, policy: str
) -> None:
    """The trigger enforces the policy too: a non-owner never approves their own request,
    and under two_person nobody does."""
    owner_db.execute(
        text("UPDATE workspaces SET approval_policy = :p WHERE id = :w"),
        {"p": policy, "w": env["ws"]},
    )
    owner_db.commit()
    who = "operator" if policy == "single_operator" else "owner"
    op_id = request_http(client, env, who=who).json()["id"]
    with pytest.raises(DBAPIError, match="cannot be approved by the person who requested it"):
        owner_db.execute(
            text(
                "INSERT INTO approvals (workspace_id, operation_id, approver_user_id, decision, "
                "scope_id_at_decision) SELECT workspace_id, id, requested_by_user_id, 'approved', "
                "scope_id FROM operations WHERE id = :i"
            ),
            {"i": op_id},
        )
    owner_db.rollback()


def test_rejection_is_final(client: TestClient, env) -> None:
    op_id = request_http(client, env).json()["id"]
    r = act(client, env, "operator", op_id, "reject", "Outside the agreed test window")
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert r.json()["approval"]["reason"] == "Outside the agreed test window"
    assert act(client, env, "owner", op_id, "approve").status_code == 409
    assert make_worker().run_once() is False


def test_scope_change_before_approval_denies(client: TestClient, env) -> None:
    op_id = request_http(client, env).json()["id"]
    use(client, env["owner"])
    authorize_scope(client, env["ws"], env["pid"], [("host", "only.example.com")], reference="v2")
    r = act(client, env, "operator", op_id, "approve")
    assert r.json()["status"] == "denied" and "scope changed" in r.json()["denial_reason"]


def test_worker_refuses_low_risk_without_approval(
    client: TestClient, env, owner_db: Session
) -> None:
    op_id = request_http(client, env).json()["id"]
    owner_db.execute(text("UPDATE operations SET status = 'queued' WHERE id = :i"), {"i": op_id})
    owner_db.commit()
    make_worker().run_once()
    use(client, env["analyst"])
    op = client.get(f"/api/workspaces/{env['ws']}/operations/{op_id}").json()
    assert op["status"] == "denied" and "No valid approval" in op["denial_reason"]


def test_private_resolution_is_denied_at_run_time(client: TestClient, env) -> None:
    op_id = request_http(client, env).json()["id"]
    act(client, env, "operator", op_id, "approve")
    rebinding = HttpFingerprint(
        make_client=lambda nets: SafeHttp(resolver=lambda h: ["10.1.2.3"], excluded_networks=nets)
    )
    make_worker({**collectors("fixture"), "http": rebinding}).run_once()
    use(client, env["analyst"])
    op = client.get(f"/api/workspaces/{env['ws']}/operations/{op_id}").json()
    assert op["status"] == "denied" and "10.1.2.3" in op["denial_reason"]


def test_requester_can_cancel_while_waiting(client: TestClient, env) -> None:
    op_id = request_http(client, env).json()["id"]
    use(client, env["analyst"])
    assert client.post(f"/api/workspaces/{env['ws']}/operations/{op_id}/cancel").status_code == 200
    assert act(client, env, "operator", op_id, "approve").status_code == 409
