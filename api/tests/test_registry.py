from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use


def test_organization_and_project_lifecycle(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    base = f"/api/workspaces/{ws}"

    org = client.post(f"{base}/organizations", json={"name": "  Acme Corp ", "notes": "Client"})
    assert org.status_code == 201
    org_id = org.json()["id"]
    assert org.json()["name"] == "Acme Corp" and org.json()["project_count"] == 0
    dup = client.post(f"{base}/organizations", json={"name": "acme corp"})
    assert dup.status_code == 409

    p = client.post(
        f"{base}/projects",
        json={
            "organization_id": org_id,
            "name": "External recon",
            "assessment_type": "reconnaissance",
        },
    )
    assert p.status_code == 201
    project = p.json()
    assert project["status"] == "planning" and project["started_at"] is None
    assert project["organization_name"] == "Acme Corp"

    # Persisted: visible to a fresh request.
    assert client.get(f"{base}/organizations/{org_id}").json()["project_count"] == 1
    listed = client.get(f"{base}/projects", params={"organization_id": org_id}).json()
    assert [x["id"] for x in listed] == [project["id"]]

    upd = client.patch(f"{base}/projects/{project['id']}", json={"status": "active"}).json()
    assert upd["status"] == "active" and upd["started_at"] is not None
    renamed = client.patch(f"{base}/organizations/{org_id}", json={"name": "Acme Corporation"})
    assert renamed.json()["name"] == "Acme Corporation"

    actions = audit_actions(owner_db)
    for expected in (
        "organization.created",
        "project.created",
        "project.updated",
        "organization.updated",
    ):
        assert expected in actions


def test_validation_errors(client: TestClient, factory: Factory) -> None:
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    base = f"/api/workspaces/{ws}"
    assert client.post(f"{base}/organizations", json={"name": "   "}).status_code == 422
    assert client.post(f"{base}/organizations", json={"name": "x" * 201}).status_code == 422
    assert client.post(f"{base}/organizations", json={"name": "ok", "extra": 1}).status_code == 422
    org_id = client.post(f"{base}/organizations", json={"name": "Org"}).json()["id"]
    bad_type = client.post(
        f"{base}/projects",
        json={"organization_id": org_id, "name": "p", "assessment_type": "exploit_everything"},
    )
    assert bad_type.status_code == 422
