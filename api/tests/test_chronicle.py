# ruff: noqa: F811  (pytest fixtures imported from test_ownership)
"""CHRONICLE v1: a project's history, assembled from the audit log."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, use
from tests.phase3_helpers import authorize_scope, org_project
from tests.test_ownership import FakeProbes, env, probes  # noqa: F401 - fixtures


def _get(client: TestClient, env: dict, **params) -> dict:  # type: ignore[no-untyped-def]
    r = client.get(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/chronicle",
        params={k: str(v) for k, v in params.items()},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _collect(client: TestClient, ws, pid, target: str):  # type: ignore[no-untyped-def]
    return client.post(
        f"/api/workspaces/{ws}/projects/{pid}/collections", json={"tool": "dns", "target": target}
    )


def test_project_history_from_the_audit_log(
    client: TestClient, env: dict, probes: FakeProbes, factory: Factory, owner_db: Session
) -> None:
    ws, pid = env["ws"], env["pid"]
    op = _collect(client, ws, pid, "app.example.com")
    assert op.status_code == 202, op.text
    assert _collect(client, ws, pid, "evil.test").status_code in (403, 422)  # refused, no record
    claim = client.post(
        f"/api/workspaces/{ws}/ownership/claims", json={"name": "example.com", "method": "dns"}
    ).json()
    client.post(f"/api/workspaces/{ws}/scopes/{env['scope']['id']}/ownership/{claim['id']}/check")

    # Another project's history stays out.
    _, other_pid = org_project(owner_db, ws, "Other Org")
    authorize_scope(client, ws, other_pid, [("domain_tree", "other.test")])

    out = _get(client, env)
    actions = [e["action"] for e in out["entries"]]
    assert out["organization_id"] and actions[0] == "ownership.checked"  # newest first
    for a in (
        "scope.authorized",
        "scope.target_added",
        "operation.requested",
        "operation.denied",
        "ownership.checked",
    ):
        assert a in actions, a
    # Claims are workspace-wide: creating one isn't part of a project's history.
    assert "ownership.claim_created" not in actions
    other = {e["details"].get("target") for e in out["entries"]}
    assert "other.test" not in other

    requested = next(e for e in out["entries"] if e["action"] == "operation.requested")
    assert requested["summary"] == "Owner requested an operation"
    assert requested["entity_id"] == op.json()["id"] and requested["details"]["tool"] == "dns"
    denied = next(e for e in out["entries"] if e["action"] == "operation.denied")
    assert denied["summary"] == "Operation refused by CONTROL"
    assert denied["details"]["target"] == "evil.test"
    # Safe fields only.
    assert all("ip" not in e and "user_agent" not in e for e in out["entries"])

    # Filtered to one operation.
    only = _get(client, env, operation_id=op.json()["id"])["entries"]
    assert only and {e["entity_id"] for e in only} == {op.json()["id"]}


def test_paging_and_access(
    client: TestClient, env: dict, factory: Factory, owner_db: Session
) -> None:
    ws = env["ws"]
    full = _get(client, env)["entries"]
    assert len(full) >= 5
    seen, before = [], None
    while True:
        page = _get(client, env, limit=2, **({"before": before} if before else {}))
        seen += [e["id"] for e in page["entries"]]
        before = page["next_before"]
        if before is None:
            break
    assert seen == [e["id"] for e in full]

    viewer = factory.sign_in(factory.member(ws, Role.VIEWER))
    use(client, viewer)
    assert _get(client, env)["entries"] == full  # any member may read it
    outsider_ws = factory.workspace("Elsewhere")
    use(client, factory.sign_in(factory.member(outsider_ws, Role.OWNER)))
    url = f"/api/workspaces/{outsider_ws}/projects/{env['pid']}/chronicle"
    assert client.get(url).status_code == 404
    use(client, env["owner"])
    url = f"/api/workspaces/{ws}/projects/{env['pid']}/chronicle"
    bad = client.get(url, params={"before": str(uuid.uuid4())})
    assert bad.status_code == 404


def test_asset_filter(client: TestClient, env: dict, owner_db: Session) -> None:
    ws, pid = env["ws"], env["pid"]
    org = owner_db.execute(
        text("SELECT organization_id FROM projects WHERE id = :p"), {"p": pid}
    ).scalar_one()
    asset = owner_db.execute(
        text(
            "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
            "VALUES (:w, :o, 'hostname', 'app.example.com', 'manual') RETURNING id"
        ),
        {"w": ws, "o": org},
    ).scalar_one()
    owner_db.execute(
        text(
            "INSERT INTO audit_events (workspace_id, actor_type, action, entity_type, entity_id, "
            "data) VALUES (:w, 'system', 'asset.updated', 'asset', :a, '{\"name\": \"x\"}')"
        ),
        {"w": ws, "a": asset},
    )
    owner_db.commit()
    entries = _get(client, env, asset_id=asset)["entries"]
    assert [e["action"] for e in entries] == ["asset.updated"]
    assert entries[0]["summary"] == "System: updated an asset"
    # Asset events aren't project events unless asked for (assets belong to the organization).
    assert "asset.updated" not in [e["action"] for e in _get(client, env)["entries"]]
