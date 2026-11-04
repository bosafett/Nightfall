from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import authorize_scope, org_project


def test_scope_lifecycle_versions_and_supersedes(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ADMIN)))
    base = f"/api/workspaces/{ws}"

    v1 = authorize_scope(
        client, ws, pid, [("domain_tree", "Example.COM.")], [("host", "mail.example.com")]
    )
    assert v1["status"] == "active" and v1["version"] == 1
    assert v1["targets"][0]["value"] == "example.com"  # normalized on entry
    assert v1["authorized_by"] == "Admin"

    # Authorized versions can't be edited through the API...
    sid = v1["id"]
    r = client.post(f"{base}/scopes/{sid}/targets", json={"kind": "host", "value": "x.test.com"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "scope_locked"
    # ...and new drafts copy the active entries.
    v2 = client.post(f"{base}/projects/{pid}/scopes").json()
    assert v2["version"] == 2 and v2["status"] == "draft"
    assert [t["value"] for t in v2["targets"]] == ["example.com"]
    assert client.post(f"{base}/projects/{pid}/scopes").status_code == 409  # one draft
    client.post(f"{base}/scopes/{v2['id']}/targets", json={"kind": "cidr", "value": "192.0.2.0/24"})
    assert client.post(f"{base}/scopes/{v2['id']}/authorize").json()["status"] == "active"

    versions = client.get(f"{base}/projects/{pid}/scopes").json()
    assert [(s["version"], s["status"]) for s in versions] == [(2, "active"), (1, "superseded")]
    assert "scope.authorized" in audit_actions(owner_db)


def test_database_refuses_changes_to_authorized_scopes(
    client: TestClient, factory: Factory, owner_db: Session, app_engine
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    v1 = authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    for stmt in (
        "INSERT INTO scope_targets (workspace_id, scope_id, kind, value) "
        "VALUES (:w, :s, 'domain_tree', 'evil.com')",
        "UPDATE scope_targets SET value = 'evil.com' WHERE scope_id = :s",
        "DELETE FROM scope_targets WHERE scope_id = :s",
        "UPDATE scopes SET authorization_reference = 'forged' WHERE id = :s",
        "DELETE FROM scopes WHERE id = :s",
    ):
        try:
            with app_engine.begin() as conn:
                conn.execute(
                    text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(ws)}
                )
                conn.execute(text(stmt), {"w": ws, "s": v1["id"]})
            raise AssertionError(f"allowed: {stmt}")
        except DBAPIError as exc:
            assert "immutable" in str(exc) or "draft" in str(exc), stmt


def test_who_can_edit_and_authorize(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    base = f"/api/workspaces/{ws}"
    use(client, factory.sign_in(factory.member(ws, Role.VIEWER)))
    assert client.post(f"{base}/projects/{pid}/scopes").status_code == 403

    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    client.post(f"{base}/scopes/{sid}/targets", json={"kind": "host", "value": "a.example.com"})
    client.patch(f"{base}/scopes/{sid}", json={"authorization_reference": "SOW"})
    assert client.post(f"{base}/scopes/{sid}/authorize").status_code == 403  # analyst can't

    use(client, factory.sign_in(factory.member(ws, Role.OPERATOR)))
    assert client.post(f"{base}/scopes/{sid}/authorize").status_code == 403  # nor operator


def test_authorization_requires_reference_targets_and_open_window(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ADMIN)))
    base = f"/api/workspaces/{ws}"
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    assert (
        client.post(f"{base}/scopes/{sid}/authorize").json()["detail"]["code"]
        == "reference_required"
    )
    client.patch(f"{base}/scopes/{sid}", json={"authorization_reference": "SOW"})
    assert client.post(f"{base}/scopes/{sid}/authorize").json()["detail"]["code"] == "no_targets"
    client.post(f"{base}/scopes/{sid}/targets", json={"kind": "host", "value": "a.example.com"})
    client.patch(f"{base}/scopes/{sid}", json={"valid_until": "2020-01-01T00:00:00Z"})
    assert client.post(f"{base}/scopes/{sid}/authorize").json()["detail"]["code"] == "window_ended"
    bad = client.patch(
        f"{base}/scopes/{sid}",
        json={"valid_from": "2030-01-02T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z"},
    )
    assert bad.status_code == 422


def test_invalid_entries_rejected(client: TestClient, factory: Factory, owner_db: Session) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    base = f"/api/workspaces/{ws}"
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    for kind, value in [
        ("host", "*.example.com"),
        ("ip", "0177.0.0.1"),
        ("cidr", "10.0.0.1/8"),
        ("domain_tree", "http://example.com"),
        ("host", "localhost"),
    ]:
        r = client.post(f"{base}/scopes/{sid}/targets", json={"kind": kind, "value": value})
        assert r.status_code == 422, (kind, value)


def test_scope_check_preview(client: TestClient, factory: Factory, owner_db: Session) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ADMIN)))
    base = f"/api/workspaces/{ws}"
    r = client.post(f"{base}/projects/{pid}/scope-check", json={"value": "a.example.com"}).json()
    assert r["allowed"] is False and r["scope_version"] is None
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    r = client.post(f"{base}/projects/{pid}/scope-check", json={"value": "A.Example.com."}).json()
    assert r == {
        "allowed": True,
        "reason": "In scope.",
        "normalized": "a.example.com",
        "scope_version": 1,
    }
