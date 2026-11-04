from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from tests.conftest import Factory, use
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
