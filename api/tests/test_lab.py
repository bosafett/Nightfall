# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""Isolated lab (Phase 6b): lab and real-world work never mix.

Each rule is checked at more than one layer: API validation, database policy (the lab
worker's role and the normal worker's role), and the lab worker's address check.
"""

import ipaddress
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from nightfall.config import _sqlalchemy_url
from nightfall.core.evidence_store import EvidenceStore
from nightfall.recon.collectors import HttpFingerprint, lab_collectors
from nightfall.recon.safe_http import Refused, SafeHttp
from nightfall.recon.worker import Worker
from tests.conftest import EVIDENCE_DIR, WORKER_URL, use
from tests.phase3_helpers import make_worker
from tests.test_agents import ai_on, env  # noqa: F401 - fixtures

LAB = ipaddress.ip_network("172.30.99.0/24")
APP = "172.30.99.10"
LAB_URL = os.environ.get(
    "NIGHTFALL_TEST_LAB_WORKER_DATABASE_URL",
    WORKER_URL.replace(
        "nightfall_worker:worker_dev_only", "nightfall_lab_worker:lab_worker_dev_only"
    ),
)
_lab_engine = create_engine(_sqlalchemy_url(LAB_URL))


def lab_worker(tools: dict[str, Any] | None = None) -> Worker:
    return Worker(
        sessionmaker(bind=_lab_engine, expire_on_commit=False),
        EvidenceStore(Path(EVIDENCE_DIR)),
        tools or lab_collectors((LAB,)),
        lab=True,
    )


def fake_app() -> HttpFingerprint:
    """The lab's practice app, served by a mock transport (no network in tests)."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == APP  # pinned to the checked address
        return httpx.Response(200, headers={"Server": "Juice"}, text="<title>Lab app</title>")

    def client(excluded: list[Any]) -> SafeHttp:
        return SafeHttp(
            excluded_networks=excluded, only_networks=[LAB], transport=httpx.MockTransport(handler)
        )

    return HttpFingerprint(make_client=client)


def add_target(client: TestClient, env, sid: str, kind: str, value: str) -> httpx.Response:
    return client.post(
        f"/api/workspaces/{env['ws']}/scopes/{sid}/targets", json={"kind": kind, "value": value}
    )


def test_scope_rules_for_lab_and_normal_scopes(client: TestClient, env) -> None:
    base = f"/api/workspaces/{env['ws']}"
    use(client, env["owner"])
    # A normal scope can't reach into the lab network.
    sid = client.post(f"{base}/projects/{env['pid']}/scopes").json()["id"]
    bad = add_target(client, env, sid, "ip", "172.30.99.5")
    assert bad.status_code == 422 and "lab network" in bad.json()["detail"]["message"]
    client.delete(f"{base}/scopes/{sid}")

    # A lab scope can't name anything outside it, or any hostname.
    pid = env["pid"]
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    for t in client.get(f"{base}/projects/{pid}/scopes").json()[0]["targets"]:
        client.delete(f"{base}/scopes/{sid}/targets/{t['id']}")
    assert client.patch(f"{base}/scopes/{sid}", json={"is_lab": True}).json()["is_lab"] is True
    for kind, value in [
        ("domain_tree", "example.com"),
        ("host", "juice.lab"),
        ("ip", "8.8.8.8"),
        ("ip", "10.0.0.5"),
        ("cidr", "172.30.0.0/16"),
    ]:
        r = add_target(client, env, sid, kind, value)
        assert r.status_code == 422, (kind, value)
    assert add_target(client, env, sid, "ip", APP).status_code == 201
    assert add_target(client, env, sid, "cidr", "172.30.99.0/28").status_code == 201
    # Switching back to normal while it names lab addresses is refused.
    r = client.patch(f"{base}/scopes/{sid}", json={"is_lab": False})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "lab_mismatch"
    client.patch(f"{base}/scopes/{sid}", json={"authorization_reference": "Lab"})
    out = client.post(f"{base}/scopes/{sid}/authorize")
    assert out.status_code == 200 and out.json()["is_lab"] is True


def _active_lab_scope(client: TestClient, env) -> None:
    base = f"/api/workspaces/{env['ws']}"
    use(client, env["owner"])
    pid = env["pid"]
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    for t in client.get(f"{base}/projects/{pid}/scopes").json()[0]["targets"]:
        client.delete(f"{base}/scopes/{sid}/targets/{t['id']}")
    client.patch(f"{base}/scopes/{sid}", json={"is_lab": True, "authorization_reference": "Lab"})
    assert add_target(client, env, sid, "ip", APP).status_code == 201
    assert client.post(f"{base}/scopes/{sid}/authorize").status_code == 200


def _request(bs: TestClient, env, tool: str, target: str = APP) -> httpx.Response:
    """Lab work is requested through BLACKSITE (D3), by the owner (single operator, D1)."""
    use(bs, env["owner"])
    return bs.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": tool, "target": target},
    )


def test_lab_run_end_to_end_and_kept_apart(
    client: TestClient, blacksite: TestClient, env, owner_db: Session
) -> None:
    _active_lab_scope(client, env)
    # The hosted app can't request lab work (D3); BLACKSITE can.
    use(client, env["owner"])
    hosted = client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": APP},
    )
    assert hosted.status_code == 403 and hosted.json()["detail"]["code"] == "lab_from_blacksite"
    assert _request(blacksite, env, "ct").json()["detail"]["code"] == "not_in_lab"
    op = _request(blacksite, env, "http").json()
    assert op["status"] == "awaiting_approval"
    # The hosted app can't approve it either; the owner approves it in BLACKSITE (D1).
    use(client, env["owner"])
    r = client.post(f"/api/workspaces/{env['ws']}/operations/{op['id']}/approve", json={})
    assert r.status_code == 403
    ok = blacksite.post(
        f"/api/workspaces/{env['ws']}/operations/{op['id']}/approve", json={"reason": "lab"}
    )
    assert ok.status_code == 200 and ok.json()["status"] == "queued"

    # The normal worker never sees it (claim filter and database policy).
    assert make_worker().run_once() is False
    with make_worker().sessions() as db:
        assert db.execute(text("SELECT count(*) FROM operations")).scalar() == 0
    # The lab worker runs it; results are marked as lab (simulation) evidence.
    assert lab_worker({"http": fake_app()}).run_once() is True
    detail = client.get(f"/api/workspaces/{env['ws']}/operations/{op['id']}").json()
    assert detail["status"] == "succeeded", detail
    sim = owner_db.execute(
        text("SELECT is_simulation FROM evidence WHERE operation_id = :o"), {"o": op["id"]}
    ).scalar_one()
    assert sim is True


def test_lab_worker_role_is_confined(client: TestClient, env, owner_db: Session) -> None:
    # A normal (example.com) operation exists; the lab worker can't see or claim it.
    use(client, env["owner"])
    client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "ct", "target": "example.com"},
    )
    lab = lab_worker()
    assert lab.run_once() is False
    with lab.sessions() as db:
        db.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])})
        assert db.execute(text("SELECT count(*) FROM operations")).scalar() == 0
        for table in ("agent_tasks", "attack_paths", "users", "sessions", "evidence_blobs"):
            with pytest.raises(DBAPIError):
                db.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))  # noqa: S608 - fixed names
            db.rollback()
    assert make_worker().run_once() is True  # the normal worker still does


def test_moderate_risk_needs_a_lab_scope(owner_db: Session, client: TestClient, env) -> None:
    sid = owner_db.execute(
        text("SELECT id FROM scopes WHERE project_id = :p AND status = 'active'"),
        {"p": env["pid"]},
    ).scalar_one()
    with pytest.raises(IntegrityError):
        owner_db.execute(
            text(
                "INSERT INTO operations (workspace_id, project_id, scope_id, tool, risk_class, "
                "target_value) VALUES (:w, :p, :s, 'x', 'moderate', 'example.com')"
            ),
            {"w": env["ws"], "p": env["pid"], "s": sid},
        )
    owner_db.rollback()


def test_lab_address_check_refuses_everything_outside() -> None:
    pin = SafeHttp(only_networks=[LAB], resolver=lambda h: [h])
    assert pin.pin(APP) == APP
    for outside in ("8.8.8.8", "10.0.0.1", "127.0.0.1", "169.254.169.254", "172.30.100.1"):
        with pytest.raises(Refused, match="outside the lab network"):
            pin.pin(outside)


def test_agents_cannot_propose_lab_operations(
    client: TestClient, env, ai_on, owner_db: Session
) -> None:
    from nightfall.agents.registry import ProposedCollection, ScoutOutput
    from tests.test_agents import FakeProvider, run_agent, worker_with

    _active_lab_scope(client, env)
    task = run_agent(client, env, "analyst", "scout").json()
    answer = ScoutOutput(
        proposals=[ProposedCollection(tool="http", target=APP, purpose="p")], notes=""
    )
    worker_with(FakeProvider({ScoutOutput: answer})).run_once()
    result = client.get(f"/api/workspaces/{env['ws']}/agent-tasks/{task['id']}").json()["result"]
    assert result["refused"][0]["reason"] == "Agents can't propose operations in the lab."
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar() == 0


def test_lab_role_sees_and_writes_only_lab_data(
    client: TestClient, blacksite: TestClient, env, owner_db: Session
) -> None:
    """Review finding F1: the lab credential can't reach real-world data, even in the same
    workspace, and can't plant data anywhere else."""
    from tests.phase3_helpers import org_project

    # Real-world data: env's project has a normal scope; collect so assets/evidence exist.
    use(client, env["owner"])
    client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "ct", "target": "example.com"},
    )
    assert make_worker().run_once() is True
    # A separate lab project in the same workspace, with an approved lab run.
    lab_org, lab_pid = org_project(owner_db, env["ws"], "Lab org")
    base = f"/api/workspaces/{env['ws']}"
    sid = client.post(f"{base}/projects/{lab_pid}/scopes").json()["id"]
    client.patch(f"{base}/scopes/{sid}", json={"is_lab": True, "authorization_reference": "Lab"})
    assert add_target(client, env, sid, "ip", APP).status_code == 201
    assert client.post(f"{base}/scopes/{sid}/authorize").status_code == 200
    use(blacksite, env["owner"])
    op = blacksite.post(
        f"{base}/projects/{lab_pid}/collections", json={"tool": "http", "target": APP}
    ).json()
    blacksite.post(f"{base}/operations/{op['id']}/approve", json={"reason": "lab"})
    assert lab_worker({"http": fake_app()}).run_once() is True

    real_org = owner_db.execute(
        text("SELECT organization_id FROM projects WHERE id = :p"), {"p": env["pid"]}
    ).scalar_one()
    with lab_worker().sessions() as db:
        db.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])})

        def ids(sql: str) -> set[str]:
            return {str(r[0]) for r in db.execute(text(sql))}

        assert ids("SELECT id FROM projects") == {str(lab_pid)}
        assert ids("SELECT id FROM organizations") == {str(lab_org)}
        assert ids("SELECT id FROM scopes") == {sid}
        assert ids("SELECT value FROM assets") == {APP}
        assert ids("SELECT project_id FROM evidence") == {str(lab_pid)}
        assert ids("SELECT project_id FROM findings") <= {str(lab_pid)}
        assert ids("SELECT count(*) FROM scope_targets WHERE value = 'example.com'") == {"0"}

        # Writes outside lab work are refused.
        for sql, params in [
            (
                "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
                "VALUES (:w, :o, 'hostname', 'planted.example.com', 'x')",
                {"w": env["ws"], "o": real_org},
            ),
            (
                "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
                "VALUES (:w, :o, 'ip_address', '172.30.99.66', 'x')",
                {"w": env["ws"], "o": real_org},
            ),
            (
                "INSERT INTO findings (workspace_id, project_id, title, severity, confidence, "
                "validation_status, origin, check_id) VALUES (:w, :p, 'planted', 'high', "
                "'high', 'unverified', 'deterministic_check', 'x')",
                {"w": env["ws"], "p": env["pid"]},
            ),
        ]:
            with pytest.raises(DBAPIError):
                db.execute(text(sql), params)
            db.rollback()
            db.execute(
                text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(env["ws"])}
            )

        # Another workspace entirely: nothing visible at all.
        other = owner_db.execute(
            text("INSERT INTO workspaces (name, slug) VALUES ('Other', 'other-f1') RETURNING id")
        ).scalar_one()
        owner_db.commit()
        db.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(other)})
        for table in ("projects", "organizations", "assets", "findings", "evidence", "scopes"):
            assert db.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 0  # noqa: S608


# Routing table shaped like the lab-worker container: lab-net on eth0 (internal, no
# gateway), the uplink on eth1 with the default route.
ROUTES = """Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth1\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00631EAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth1\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""


@pytest.mark.parametrize(
    ("configured", "problem"),
    [
        ("172.30.99.0/24", None),
        ("192.168.1.0/24", "isn't a network this lab worker is attached to"),  # home LAN
        ("172.30.0.0/16", "isn't a network this lab worker is attached to"),  # widened
        ("172.30.99.0/25", "isn't a network this lab worker is attached to"),  # narrowed
        ("172.18.0.0/16", "leads out"),  # the uplink
    ],
)
def test_lab_worker_refuses_a_lab_network_it_isnt_attached_to(
    configured: str, problem: str | None
) -> None:
    """Review finding F4."""
    from nightfall.scope.lab import lab_network_problem

    got = lab_network_problem((ipaddress.ip_network(configured),), ROUTES)
    assert (got is None) if problem is None else (got is not None and problem in got)


@pytest.mark.parametrize(("age_hours", "status"), [(23, "succeeded"), (25, "denied")])
def test_lab_approvals_expire(
    client: TestClient,
    blacksite: TestClient,
    env,
    owner_db: Session,
    age_hours: int,
    status: str,
) -> None:
    """Review finding F5: a lab job that waited too long after approval doesn't run."""
    _active_lab_scope(client, env)
    op = _request(blacksite, env, "http").json()
    blacksite.post(f"/api/workspaces/{env['ws']}/operations/{op['id']}/approve", json={})
    owner_db.execute(
        text(
            "UPDATE approvals SET decided_at = now() - make_interval(hours => :h) "
            "WHERE operation_id = :o"
        ),
        {"h": age_hours, "o": op["id"]},
    )
    owner_db.commit()
    assert lab_worker({"http": fake_app()}).run_once() is True
    detail = client.get(f"/api/workspaces/{env['ws']}/operations/{op['id']}").json()
    assert detail["status"] == status
    if status == "denied":
        assert "lab approvals expire" in detail["denial_reason"]
