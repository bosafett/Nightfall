import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.config import _sqlalchemy_url
from nightfall.core.db.models import Role
from tests import phase3_helpers
from tests.conftest import APP_URL, Factory, use
from tests.phase3_helpers import org_project


def test_register_categorize_and_edit_assets(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    oid, _ = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    base = f"/api/workspaces/{ws}/assets"
    cases = [
        ("domain", "Example.COM.", "example.com"),
        ("ip_address", "2001:0DB8::1", "2001:db8::1"),
        ("ip_range", "192.0.2.0/24", "192.0.2.0/24"),
        ("api", " Payments API v2 ", "Payments API v2"),
    ]
    for kind, value, stored in cases:
        r = client.post(
            base,
            json={
                "organization_id": str(oid),
                "kind": kind,
                "value": value,
                "ownership": "organization",
            },
        )
        assert r.status_code == 201, r.text
        assert r.json()["value"] == stored and r.json()["source"] == "manual"
    dup = client.post(
        base, json={"organization_id": str(oid), "kind": "domain", "value": "example.com"}
    )
    assert dup.status_code == 409
    for kind, value in [
        ("domain", "not a domain"),
        ("ip_address", "300.1.1.1"),
        ("ip_range", "10.0.0.1/8"),
    ]:
        assert (
            client.post(
                base, json={"organization_id": str(oid), "kind": kind, "value": value}
            ).status_code
            == 422
        )
    listed = client.get(base, params={"kind": "domain"}).json()
    assert [a["value"] for a in listed] == ["example.com"]
    patched = client.patch(
        f"{base}/{listed[0]['id']}", json={"ownership": "third_party", "notes": "CDN"}
    ).json()
    assert patched["ownership"] == "third_party" and patched["notes"] == "CDN"


def test_viewer_cannot_register_assets(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    oid, _ = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.VIEWER)))
    r = client.post(
        f"/api/workspaces/{ws}/assets",
        json={"organization_id": str(oid), "kind": "domain", "value": "example.com"},
    )
    assert r.status_code == 403


def _asset(client: TestClient, ws: object, oid: object, value: str = "example.com") -> str:
    r = client.post(
        f"/api/workspaces/{ws}/assets",
        json={"organization_id": str(oid), "kind": "domain", "value": value},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "unverified"
    return str(r.json()["id"])


def test_status_changes_are_recorded_in_history(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    oid, _ = org_project(owner_db, ws)
    analyst = factory.sign_in(factory.member(ws, Role.ANALYST))
    use(client, analyst)
    aid = _asset(client, ws, oid)
    base = f"/api/workspaces/{ws}/assets"
    assert client.patch(f"{base}/{aid}", json={"status": "verified"}).json()["status"] == "verified"
    client.patch(f"{base}/{aid}", json={"status": "verified", "ownership": "organization"})
    detail = client.get(f"{base}/{aid}").json()
    changes = [(h["change"], h["old_value"], h["new_value"]) for h in detail["history"]]
    assert changes == [
        ("ownership", "unknown", "organization"),
        ("status", "unverified", "verified"),
        ("created", None, "manual"),
    ]
    assert {h["actor_user_id"] for h in detail["history"]} == {str(analyst.user.id)}
    assert all(h["recorded_by"] == "nightfall_app" for h in detail["history"])
    assert [a["value"] for a in client.get(base, params={"status": "verified"}).json()] == [
        "example.com"
    ]
    assert client.get(base, params={"status": "retired"}).json() == []
    # A no-op patch records nothing.
    client.patch(f"{base}/{aid}", json={"status": "verified"})
    assert len(client.get(f"{base}/{aid}").json()["history"]) == 3


def test_only_a_person_changes_status_and_history_is_insert_only(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    oid, _ = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    aid = _asset(client, ws, oid)
    with phase3_helpers._worker_engine.connect() as c:
        c.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(ws)})
        # Collectors re-observe assets freely ...
        c.execute(text("UPDATE assets SET last_seen_at = now() WHERE id = :a"), {"a": aid})
        c.commit()
        # ... but cannot verify one, even claiming to be a user.
        c.execute(text("SELECT set_config('app.user_id', gen_random_uuid()::text, false)"))
        with pytest.raises(DBAPIError, match="only a person"):
            c.execute(text("UPDATE assets SET status = 'verified' WHERE id = :a"), {"a": aid})
        c.rollback()
    with phase3_helpers._worker_engine.connect() as c:
        c.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(ws)})
        with pytest.raises(DBAPIError, match="only a person"):
            c.execute(
                text(
                    "INSERT INTO assets (workspace_id, organization_id, kind, value, source, "
                    "status) VALUES (:w, :o, 'domain', 'x.example.com', 'ct', 'verified')"
                ),
                {"w": ws, "o": oid},
            )
        c.rollback()
    app = create_engine(_sqlalchemy_url(APP_URL))
    with app.connect() as c:
        c.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(ws)})
        for stmt in (
            "UPDATE asset_history SET new_value = 'x'",
            "DELETE FROM asset_history",
            "INSERT INTO asset_history (workspace_id, asset_id, change, recorded_by) "
            "VALUES (:w, :a, 'notes', 'forged')",
        ):
            with pytest.raises(DBAPIError, match="permission denied"):
                c.execute(text(stmt), {"w": ws, "a": aid})
            c.rollback()
    app.dispose()
    assert len(client.get(f"/api/workspaces/{ws}/assets/{aid}").json()["history"]) == 1
