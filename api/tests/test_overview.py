import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, use


def _org(db: Session, ws: uuid.UUID, name: str) -> uuid.UUID:
    oid = db.execute(
        text("INSERT INTO organizations (workspace_id, name) VALUES (:w, :n) RETURNING id"),
        {"w": ws, "n": name},
    ).scalar_one()
    db.commit()
    return oid


def _project(
    db: Session, ws: uuid.UUID, org: uuid.UUID, name: str, status: str, started: str | None
) -> uuid.UUID:
    pid = db.execute(
        text(
            "INSERT INTO projects (workspace_id, organization_id, name, assessment_type, status, "
            "started_at) VALUES (:w, :o, :n, 'reconnaissance', :s, "
            "now() - CAST(:st AS interval)) RETURNING id"
        ),
        {"w": ws, "o": org, "n": name, "s": status, "st": started},
    ).scalar_one()
    db.commit()
    return pid


def test_empty_workspace_reports_zeros_and_unavailable_modules(
    client: TestClient, factory: Factory
) -> None:
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.VIEWER)))
    body = client.get(f"/api/workspaces/{ws}/overview").json()
    assert body["window"] == "24h"
    assert body["projects"] == {"available": True, "active": 0, "open": 0, "started_in_window": 0}
    assert body["assets"] == {"available": True, "total": 0, "new_in_window": 0}
    assert body["operations"] == {
        "available": True,
        "in_window": 0,
        "pending": 0,
        "failed_in_window": 0,
    }
    for key, phase in [
        ("critical_findings", 4),
        ("recent_findings", 4),
        ("agent_activity", 5),
        ("risk", 4),
    ]:
        assert body[key] == {"available": False, "phase": phase}
    assert body["assessments"] == []
    assert body["graph"] == {"nodes": [], "edges": [], "truncated": False}


def test_counts_window_and_graph_come_from_records(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    acme = _org(owner_db, ws, "Acme")
    _org(owner_db, ws, "Empty Org")
    a = _project(owner_db, ws, acme, "Recent", "active", "2 hours")
    _project(owner_db, ws, acme, "Older", "active", "3 days")
    _project(owner_db, ws, acme, "Queued", "planning", None)
    _project(owner_db, ws, acme, "Finished", "completed", "20 days")
    _project(owner_db, ws, acme, "Shelved", "archived", None)
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    base = f"/api/workspaces/{ws}/overview"

    day = client.get(base).json()
    assert day["projects"] == {"available": True, "active": 2, "open": 3, "started_in_window": 1}
    assert client.get(base, params={"window": "7d"}).json()["projects"]["started_in_window"] == 2
    assert client.get(base, params={"window": "30d"}).json()["projects"]["started_in_window"] == 3
    assert client.get(base, params={"window": "1h"}).json()["projects"]["started_in_window"] == 0
    assert client.get(base, params={"window": "1y"}).status_code == 422

    assert {x["name"] for x in day["assessments"]} == {"Recent", "Older", "Queued"}
    assert all(x["organization_name"] == "Acme" for x in day["assessments"])

    g = day["graph"]
    labels = {n["label"]: n for n in g["nodes"]}
    assert set(labels) == {"Acme", "Empty Org", "Recent", "Older", "Queued", "Finished"}
    assert labels["Recent"]["record_id"] == str(a) and labels["Recent"]["kind"] == "project"
    assert len(g["edges"]) == 4
    assert all(e["source"] == f"org:{acme}" and e["status"] == "observed" for e in g["edges"])
    node_ids = {n["id"] for n in g["nodes"]}
    assert all(e["target"] in node_ids for e in g["edges"])


def test_overview_is_tenant_isolated(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    mine, theirs = factory.workspace("Mine"), factory.workspace("Theirs")
    other = _org(owner_db, theirs, "Their Org")
    _project(owner_db, theirs, other, "Their project", "active", "1 hour")
    use(client, factory.sign_in(factory.member(mine, Role.ANALYST)))
    body = client.get(f"/api/workspaces/{mine}/overview").json()
    assert body["projects"]["active"] == 0 and body["graph"]["nodes"] == []
    assert client.get(f"/api/workspaces/{theirs}/overview").status_code == 404
