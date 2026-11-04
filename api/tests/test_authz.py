import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use


def test_non_member_gets_404_and_is_audited(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    mine, theirs = factory.workspace("Mine"), factory.workspace("Theirs")
    m = factory.sign_in(factory.member(mine, Role.ANALYST))
    use(client, m)
    for path in ("", "/organizations", "/projects", "/members"):
        assert client.get(f"/api/workspaces/{theirs}{path}").status_code == 404
    assert client.get(f"/api/workspaces/{uuid.uuid4()}").status_code == 404
    assert "authz.denied" in audit_actions(owner_db)


def test_viewer_cannot_mutate(client: TestClient, factory: Factory, owner_db: Session) -> None:
    ws = factory.workspace()
    v = factory.sign_in(factory.member(ws, Role.VIEWER))
    use(client, v)
    assert client.get(f"/api/workspaces/{ws}/organizations").status_code == 200
    r = client.post(f"/api/workspaces/{ws}/organizations", json={"name": "Nope"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden"
    row = owner_db.execute(
        text("SELECT workspace_id, data->>'reason' FROM audit_events WHERE action = 'authz.denied'")
    ).one()
    assert row == (ws, "permission")


def test_analyst_cannot_manage_members(client: TestClient, factory: Factory) -> None:
    ws = factory.workspace()
    a = factory.sign_in(factory.member(ws, Role.ANALYST))
    use(client, a)
    assert client.get(f"/api/workspaces/{ws}/invites").status_code == 403
    assert (
        client.post(
            f"/api/workspaces/{ws}/invites", json={"email": "x@example.test", "role": "viewer"}
        ).status_code
        == 403
    )
    assert client.patch(f"/api/workspaces/{ws}", json={"name": "Renamed"}).status_code == 403


def test_privileged_roles_need_mfa(client: TestClient, factory: Factory) -> None:
    ws = factory.workspace()
    no_mfa = factory.sign_in(factory.member(ws, Role.OPERATOR, mfa=False))
    use(client, no_mfa)
    r = client.get(f"/api/workspaces/{ws}/organizations")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "mfa_required"
    # Enrolled but this session never passed the second factor.
    unverified = factory.sign_in(factory.member(ws, Role.ADMIN), mfa_verified=False)
    use(client, unverified)
    assert client.get(f"/api/workspaces/{ws}/organizations").status_code == 403
    # /me still works so the UI can send them to enrollment.
    assert client.get("/api/auth/me").status_code == 200


def test_cross_workspace_ids_are_not_found(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    a, b = factory.workspace("A"), factory.workspace("B")
    org_b = owner_db.execute(
        text("INSERT INTO organizations (workspace_id, name) VALUES (:b, 'B org') RETURNING id"),
        {"b": b},
    ).scalar_one()
    owner_db.commit()
    m = factory.sign_in(factory.member(a, Role.ANALYST))
    use(client, m)
    assert client.get(f"/api/workspaces/{a}/organizations/{org_b}").status_code == 404
    assert (
        client.patch(
            f"/api/workspaces/{a}/organizations/{org_b}", json={"name": "hijack"}
        ).status_code
        == 404
    )
    r = client.post(
        f"/api/workspaces/{a}/projects",
        json={"organization_id": str(org_b), "name": "p", "assessment_type": "reconnaissance"},
    )
    assert r.status_code == 404
    assert (
        client.get(f"/api/workspaces/{a}/projects", params={"organization_id": str(org_b)}).json()
        == []
    )


def test_member_in_two_workspaces_sees_each_separately(
    client: TestClient, factory: Factory
) -> None:
    a, b = factory.workspace("A"), factory.workspace("B")
    m = factory.member(a, Role.ANALYST, email="both@example.test")
    factory.member(b, Role.ANALYST, email="both@example.test")
    use(client, factory.sign_in(m))
    client.post(f"/api/workspaces/{a}/organizations", json={"name": "Only in A"})
    assert [o["name"] for o in client.get(f"/api/workspaces/{a}/organizations").json()] == [
        "Only in A"
    ]
    assert client.get(f"/api/workspaces/{b}/organizations").json() == []
    assert len(client.get("/api/auth/me").json()["workspaces"]) == 2


def test_role_management_rules(client: TestClient, factory: Factory) -> None:
    ws = factory.workspace()
    owner = factory.sign_in(factory.member(ws, Role.OWNER))
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    viewer = factory.member(ws, Role.VIEWER)

    use(client, admin)
    assert (
        client.post(
            f"/api/workspaces/{ws}/invites", json={"email": "o@example.test", "role": "owner"}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/api/workspaces/{ws}/members/{owner.member_id}", json={"role": "viewer"}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/api/workspaces/{ws}/members/{viewer.member_id}", json={"role": "admin"}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"/api/workspaces/{ws}/members/{viewer.member_id}", json={"role": "operator"}
        ).status_code
        == 200
    )

    use(client, owner)
    r = client.patch(f"/api/workspaces/{ws}/members/{owner.member_id}", json={"role": "admin"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "last_owner"
    assert client.delete(f"/api/workspaces/{ws}/members/{owner.member_id}").status_code == 409
    assert client.delete(f"/api/workspaces/{ws}/members/{admin.member_id}").status_code == 200
    members = client.get(f"/api/workspaces/{ws}/members").json()
    assert {m["role"] for m in members} == {"owner", "operator"}


def test_reset_link_refused_for_multi_workspace_user(client: TestClient, factory: Factory) -> None:
    a, b = factory.workspace("A"), factory.workspace("B")
    owner = factory.sign_in(factory.member(a, Role.OWNER))
    target = factory.member(a, Role.VIEWER, email="shared@example.test")
    factory.member(b, Role.OWNER, email="shared@example.test")
    use(client, owner)
    r = client.post(f"/api/workspaces/{a}/members/{target.member_id}/password-reset")
    assert r.status_code == 409 and r.json()["detail"]["code"] == "multiple_workspaces"
