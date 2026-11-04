import hashlib
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.recon.collectors import FixtureCertificateTransparency, collectors
from tests.conftest import EVIDENCE_DIR, Factory, audit_actions, use
from tests.phase3_helpers import authorize_scope, make_worker, org_project


@pytest.fixture
def setup(client: TestClient, factory: Factory, owner_db: Session):
    ws = factory.workspace()
    oid, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    authorize_scope(
        client,
        ws,
        pid,
        [("domain_tree", "example.com")],
        [("host", "mail.example.com"), ("domain_tree", "legacy.example.com")],
    )
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    return ws, oid, pid


def collect(client: TestClient, ws, pid, tool: str, target: str):
    return client.post(
        f"/api/workspaces/{ws}/projects/{pid}/collections", json={"tool": tool, "target": target}
    )


def test_out_of_scope_requests_are_refused_and_audited(
    client: TestClient, setup, owner_db: Session
) -> None:
    ws, _, pid = setup
    for target in (
        "evil.com",
        "badexample.com",
        "mail.example.com",
        "x.legacy.example.com",
        "192.0.2.1",
        "example.com.evil.com",
    ):
        r = collect(client, ws, pid, "ct", target)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "out_of_scope", target
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar() == 0
    assert audit_actions(owner_db).count("operation.denied") == 6


def test_no_scope_means_no_collection(client: TestClient, factory: Factory, owner_db: Session):
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    r = collect(client, ws, pid, "dns", "example.com")
    assert r.status_code == 422 and "no authorized scope" in r.json()["detail"]["message"]


def test_viewer_cannot_request(client: TestClient, factory: Factory, setup) -> None:
    ws, _, pid = setup
    use(client, factory.sign_in(factory.member(ws, Role.VIEWER)))
    assert collect(client, ws, pid, "ct", "example.com").status_code == 403


def test_ct_collection_end_to_end(client: TestClient, setup, owner_db: Session) -> None:
    ws, oid, pid = setup
    r = collect(client, ws, pid, "ct", "Example.com.")
    assert r.status_code == 202
    op = r.json()
    assert (
        op["status"] == "queued" and op["target"] == "example.com" and op["risk_class"] == "passive"
    )
    again = collect(client, ws, pid, "ct", "example.com")
    assert again.status_code == 200 and again.json()["id"] == op["id"]  # deduplicated

    worker = make_worker()
    assert worker.run_once() is True
    assert worker.run_once() is False

    done = client.get(f"/api/workspaces/{ws}/operations/{op['id']}").json()
    assert done["status"] == "succeeded", done
    s = done["result_summary"]
    # Fixture names: www, api, mail (excluded), old.legacy (excluded tree),
    # cdn.third-party.example (out of scope), wildcard folded into apex, one malformed.
    assert s["out_of_scope"] == 3 and s["rejected"] == 1
    assets = client.get(f"/api/workspaces/{ws}/assets", params={"organization_id": str(oid)}).json()
    values = {a["value"] for a in assets}
    assert values == {"example.com", "www.example.com", "api.example.com"}
    assert all(a["source"] == "fixture" for a in assets)

    # Evidence: stored once, hash verified on download, provenance recorded.
    ev = done["evidence"][0]
    assert ev["tool_name"] == "fixture-ct" and ev["confidence"] == "high"
    content = client.get(f"/api/workspaces/{ws}/evidence/{ev['id']}/content")
    assert content.status_code == 200
    assert hashlib.sha256(content.content).hexdigest() == ev["sha256"]
    assert content.headers["content-disposition"].startswith("attachment")
    assert content.headers["content-type"] == "application/octet-stream"

    www = next(a for a in assets if a["value"] == "www.example.com")
    detail = client.get(f"/api/workspaces/{ws}/assets/{www['id']}").json()
    assert detail["relationships"][0]["rel_type"] == "subdomain_of"
    assert detail["relationships"][0]["other_value"] == "example.com"
    # A discovered asset traces back to the evidence that found it.
    assert [e["id"] for e in detail["evidence"]] == [ev["id"]]
    assert "operation.completed" in audit_actions(owner_db)


def test_rerunning_a_job_never_duplicates(client: TestClient, setup, owner_db: Session) -> None:
    ws, _, pid = setup
    op_id = collect(client, ws, pid, "ct", "example.com").json()["id"]
    worker = make_worker()
    worker.run_once()

    def counts():
        return owner_db.execute(
            text(
                "SELECT (SELECT count(*) FROM assets), (SELECT count(*) FROM evidence), "
                "(SELECT count(*) FROM asset_relationships)"
            )
        ).one()

    before = counts()
    # Simulate a crash after ingest but before the status update: force it to run again.
    owner_db.execute(text("UPDATE operations SET status = 'queued' WHERE id = :i"), {"i": op_id})
    owner_db.commit()
    worker.run_once()
    owner_db.expire_all()
    assert counts() == before
    # A *new* request for the same target is a new observation: new evidence row, same assets.
    collect(client, ws, pid, "ct", "example.com")
    worker.run_once()
    after = counts()
    assert after[0] == before[0] and after[2] == before[2]


def test_scope_change_after_request_denies_the_job(
    client: TestClient, factory: Factory, setup, owner_db: Session
) -> None:
    ws, _, pid = setup
    op_id = collect(client, ws, pid, "dns", "www.example.com").json()["id"]
    use(client, factory.sign_in(factory.member(ws, Role.ADMIN)))
    authorize_scope(client, ws, pid, [("host", "only.example.com")], reference="SOW-43")
    make_worker().run_once()
    op = client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()
    assert op["status"] == "denied" and "scope changed" in op["denial_reason"]
    assert owner_db.execute(text("SELECT count(*) FROM evidence")).scalar() == 0


def test_dns_records_ip_and_cname_relationships(client: TestClient, setup) -> None:
    ws, oid, pid = setup
    collect(client, ws, pid, "dns", "www.example.com")
    make_worker().run_once()
    assets = {a["value"]: a for a in client.get(f"/api/workspaces/{ws}/assets").json()}
    assert assets["192.0.2.10"]["kind"] == "ip_address"
    assert assets["2001:db8::10"]["kind"] == "ip_address"
    assert "edge.third-party.example" not in assets  # out-of-scope CNAME target not registered
    rels = client.get(f"/api/workspaces/{ws}/assets/{assets['www.example.com']['id']}").json()
    assert {r["rel_type"] for r in rels["relationships"]} == {"resolves_to"}


def test_collector_failure_is_recorded(client: TestClient, setup) -> None:
    ws, _, pid = setup

    class Broken(FixtureCertificateTransparency):
        def run(self, target: str):
            raise TimeoutError("crt.sh did not answer")

    op_id = collect(client, ws, pid, "ct", "example.com").json()["id"]
    make_worker({**collectors("fixture"), "ct": Broken()}).run_once()
    op = client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()
    assert op["status"] == "failed" and "crt.sh did not answer" in op["error"]


def test_stale_running_jobs_are_retried_then_failed(
    client: TestClient, setup, owner_db: Session
) -> None:
    ws, _, pid = setup
    op_id = collect(client, ws, pid, "ct", "example.com").json()["id"]
    owner_db.execute(
        text(
            "UPDATE operations SET status='running', attempts=1, "
            "started_at = now() - interval '11 minutes' WHERE id = :i"
        ),
        {"i": op_id},
    )
    owner_db.commit()
    make_worker().run_once()
    assert client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()["status"] == "succeeded"

    op2 = collect(client, ws, pid, "dns", "example.com").json()["id"]
    owner_db.execute(
        text(
            "UPDATE operations SET status='running', attempts=3, "
            "started_at = now() - interval '11 minutes' WHERE id = :i"
        ),
        {"i": op2},
    )
    owner_db.commit()
    make_worker().run_once()
    op = client.get(f"/api/workspaces/{ws}/operations/{op2}").json()
    assert op["status"] == "failed" and "3 attempts" in op["error"]


def test_tampered_evidence_is_detected(client: TestClient, setup, owner_db: Session) -> None:
    ws, _, pid = setup
    op_id = collect(client, ws, pid, "ct", "example.com").json()["id"]
    make_worker().run_once()
    ev = client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()["evidence"][0]
    path = Path(EVIDENCE_DIR) / ev["sha256"][:2] / ev["sha256"]
    path.chmod(0o640)
    path.write_bytes(b"forged")
    r = client.get(f"/api/workspaces/{ws}/evidence/{ev['id']}/content")
    assert r.status_code == 500 and r.json()["detail"]["code"] == "integrity_failed"
    assert "evidence.integrity_failed" in audit_actions(owner_db)


def test_worker_role_cannot_read_identity_tables(owner_db: Session) -> None:
    from tests.phase3_helpers import _worker_engine

    for table in ("users", "sessions", "auth_tokens", "workspace_members"):
        with pytest.raises(Exception, match="permission denied"), _worker_engine.connect() as c:
            c.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))  # noqa: S608


def test_operations_and_evidence_are_tenant_isolated(
    client: TestClient, factory: Factory, setup
) -> None:
    ws, _, pid = setup
    op_id = collect(client, ws, pid, "ct", "example.com").json()["id"]
    make_worker().run_once()
    ev_id = client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()["evidence"][0]["id"]
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.ANALYST)))
    for path in (f"operations/{op_id}", f"evidence/{ev_id}", f"evidence/{ev_id}/content"):
        assert client.get(f"/api/workspaces/{other}/{path}").status_code == 404
    assert client.get(f"/api/workspaces/{other}/assets").json() == []
    assert (
        client.post(
            f"/api/workspaces/{other}/projects/{pid}/collections",
            json={"tool": "ct", "target": "example.com"},
        ).status_code
        == 404
    )
    _ = uuid
