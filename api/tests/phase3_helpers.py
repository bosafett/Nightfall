import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from nightfall.config import _sqlalchemy_url
from nightfall.core.evidence_store import EvidenceStore
from nightfall.recon.collectors import Collector, collectors
from nightfall.recon.worker import Worker
from tests.conftest import EVIDENCE_DIR, WORKER_URL

_worker_engine = create_engine(_sqlalchemy_url(WORKER_URL))


def make_worker(tools: dict[str, Collector] | None = None, *, profile_b: bool = False) -> Worker:
    return Worker(
        sessionmaker(bind=_worker_engine, expire_on_commit=False),
        EvidenceStore(Path(EVIDENCE_DIR)),
        tools or collectors("fixture"),
        profile_b=profile_b,
    )


def org_project(db: Session, ws: uuid.UUID, org: str = "Acme") -> tuple[uuid.UUID, uuid.UUID]:
    oid = db.execute(
        text("INSERT INTO organizations (workspace_id, name) VALUES (:w, :n) RETURNING id"),
        {"w": ws, "n": org},
    ).scalar_one()
    pid = db.execute(
        text(
            "INSERT INTO projects (workspace_id, organization_id, name, "
            "assessment_type) VALUES (:w, :o, 'Recon', 'reconnaissance') "
            "RETURNING id"
        ),
        {"w": ws, "o": oid},
    ).scalar_one()
    db.commit()
    return oid, pid


def authorize_scope(
    client: TestClient,
    ws: uuid.UUID,
    pid: uuid.UUID,
    targets: list[tuple[str, str]],
    exclusions: list[tuple[str, str]] = (),
    reference: str = "SOW-42",
) -> dict:
    """client must be signed in as an admin/owner."""
    base = f"/api/workspaces/{ws}"
    draft = client.post(f"{base}/projects/{pid}/scopes")
    assert draft.status_code == 201, draft.text
    sid = draft.json()["id"]
    for kind, value in targets:
        assert (
            client.post(
                f"{base}/scopes/{sid}/targets", json={"kind": kind, "value": value}
            ).status_code
            == 201
        )
    for kind, value in exclusions:
        assert (
            client.post(
                f"{base}/scopes/{sid}/exclusions", json={"kind": kind, "value": value}
            ).status_code
            == 201
        )
    assert (
        client.patch(
            f"{base}/scopes/{sid}", json={"authorization_reference": reference}
        ).status_code
        == 200
    )
    r = client.post(f"{base}/scopes/{sid}/authorize")
    assert r.status_code == 200, r.text
    return r.json()
