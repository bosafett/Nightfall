"""Evidence content stored in Postgres (NIGHTFALL_EVIDENCE_BACKEND=postgres)."""

import dataclasses
import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

import nightfall.recon.routes as recon_routes
from nightfall.config import _sqlalchemy_url, get_settings
from nightfall.core.db.models import Role
from nightfall.core.db.session import set_workspace_context
from nightfall.core.evidence_store import IntegrityError, PostgresEvidenceStore, read_from
from nightfall.recon.collectors import collectors
from nightfall.recon.worker import Worker
from tests.conftest import WORKER_URL, Factory, use
from tests.phase3_helpers import authorize_scope, org_project

_worker_engine = create_engine(_sqlalchemy_url(WORKER_URL))


@pytest.fixture
def pg_backend(monkeypatch: pytest.MonkeyPatch) -> PostgresEvidenceStore:
    settings = dataclasses.replace(get_settings(), evidence_backend="postgres")
    monkeypatch.setattr(recon_routes, "get_settings", lambda: settings)
    return PostgresEvidenceStore(sessionmaker(bind=_worker_engine, expire_on_commit=False))


def run_ct(client: TestClient, factory: Factory, owner_db: Session, store) -> tuple:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    op = client.post(
        f"/api/workspaces/{ws}/projects/{pid}/collections",
        json={"tool": "ct", "target": "example.com"},
    ).json()
    worker = Worker(
        sessionmaker(bind=_worker_engine, expire_on_commit=False), store, collectors("fixture")
    )
    assert worker.run_once() is True
    ev = client.get(f"/api/workspaces/{ws}/operations/{op['id']}").json()["evidence"][0]
    return ws, ev


def test_content_round_trips_through_postgres(
    client: TestClient, factory: Factory, owner_db: Session, pg_backend
) -> None:
    ws, ev = run_ct(client, factory, owner_db, pg_backend)
    r = client.get(f"/api/workspaces/{ws}/evidence/{ev['id']}/content")
    assert r.status_code == 200
    assert hashlib.sha256(r.content).hexdigest() == ev["sha256"]
    assert owner_db.execute(text("SELECT count(*) FROM evidence_blobs")).scalar() == 1


def test_other_workspaces_cannot_read_the_blob_even_by_hash(
    client: TestClient, factory: Factory, owner_db: Session, app_engine: Engine, pg_backend
) -> None:
    ws, ev = run_ct(client, factory, owner_db, pg_backend)
    digest = bytes.fromhex(ev["sha256"])
    with Session(app_engine) as db:
        set_workspace_context(db, ws)
        assert read_from(db, digest)  # visible to the owning workspace
    with Session(app_engine) as db:
        set_workspace_context(db, uuid.uuid4())
        with pytest.raises(IntegrityError, match="missing"):
            read_from(db, digest)
    with Session(app_engine) as db:  # no workspace context at all
        assert db.execute(text("SELECT count(*) FROM evidence_blobs")).scalar() == 0


def test_blobs_are_immutable_and_api_cannot_write(owner_db: Session, app_engine: Engine) -> None:
    store = PostgresEvidenceStore(sessionmaker(bind=_worker_engine))
    digest = store.put(b"evidence")
    assert store.put(b"evidence") == digest  # idempotent
    with Session(_worker_engine) as db, pytest.raises(DBAPIError):
        db.execute(text("UPDATE evidence_blobs SET content = 'x'"))
    with Session(_worker_engine) as db, pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM evidence_blobs"))
    with Session(app_engine) as db, pytest.raises(DBAPIError):
        db.execute(text("INSERT INTO evidence_blobs VALUES (:d, 'x', 1)"), {"d": b"\x00" * 32})


def test_tampered_blob_is_detected(owner_db: Session) -> None:
    store = PostgresEvidenceStore(sessionmaker(bind=_worker_engine))
    digest = store.put(b"original")
    owner_db.execute(
        text("UPDATE evidence_blobs SET content = 'altered', size_bytes = 7 WHERE sha256 = :d"),
        {"d": digest},
    )
    owner_db.commit()
    with pytest.raises(IntegrityError, match="integrity"):
        store.get(digest)
