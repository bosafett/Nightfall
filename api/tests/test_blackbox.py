"""BLACK BOX: evidence inventory and on-demand integrity verification."""

import dataclasses
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import nightfall.blackbox.routes as blackbox
from nightfall.config import get_settings
from nightfall.core.db.models import Role
from nightfall.core.evidence_store import PostgresEvidenceStore
from tests.conftest import EVIDENCE_DIR, Factory, audit_actions, use
from tests.phase3_helpers import make_worker
from tests.test_evidence_pg import _worker_engine, run_ct


def _blob(sha_hex: str) -> Path:
    return Path(EVIDENCE_DIR) / sha_hex[:2] / sha_hex


def _duplicate_evidence(owner_db: Session, evidence_id: str, copies: int) -> None:
    for _ in range(copies):
        owner_db.execute(
            text(
                "INSERT INTO evidence (workspace_id, project_id, asset_id, operation_id, kind, "
                "source, collection_method, collected_at, confidence, tool_name, tool_version, "
                "content_sha256, content_type, size_bytes) "
                "SELECT workspace_id, project_id, asset_id, NULL, kind, source, "
                "collection_method, collected_at, confidence, tool_name, tool_version, "
                "content_sha256, content_type, size_bytes FROM evidence WHERE id = :e"
            ),
            {"e": evidence_id},
        )
    owner_db.commit()


def test_inventory_and_verification_detect_tampering(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws, ev = run_ct(client, factory, owner_db, make_worker().store)
    base = f"/api/workspaces/{ws}/blackbox"
    inv = client.get(base).json()
    assert inv["total"] == 1 and inv["total_bytes"] == ev["size_bytes"]
    assert inv["retention_policy"] == "keep_indefinitely"
    assert inv["last_verification"] is None

    ok = client.post(f"{base}/verify").json()
    assert (ok["checked"], ok["ok"], ok["failures"], ok["next_after"]) == (1, 1, [], None)
    last = client.get(base).json()["last_verification"]
    assert (last["checked"], last["failed"], last["complete"]) == (1, 0, True)

    path = _blob(ev["sha256"])
    original = path.read_bytes()
    os.chmod(path, 0o640)
    try:
        path.write_bytes(original + b"tampered")
        bad = client.post(f"{base}/verify").json()
        assert bad["failures"] == [{"evidence_id": ev["id"], "problem": "hash_mismatch"}]
        path.unlink()
        gone = client.post(f"{base}/verify").json()
        assert gone["failures"] == [{"evidence_id": ev["id"], "problem": "missing"}]
    finally:
        path.write_bytes(original)
        os.chmod(path, 0o440)
    assert client.get(base).json()["last_verification"]["failed"] == 1
    actions = audit_actions(owner_db)
    assert actions.count("blackbox.verified") == 3
    assert actions.count("evidence.integrity_failed") == 2


def test_verification_runs_in_batches_with_running_totals(
    client: TestClient, factory: Factory, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, ev = run_ct(client, factory, owner_db, make_worker().store)
    _duplicate_evidence(owner_db, ev["id"], 2)
    monkeypatch.setattr(blackbox, "VERIFY_BATCH", 2)
    base = f"/api/workspaces/{ws}/blackbox"
    first = client.post(f"{base}/verify").json()
    assert first["checked"] == 2 and first["next_after"] is not None
    assert client.get(base).json()["last_verification"]["complete"] is False
    assert client.post(f"{base}/verify", params={"after": first["next_after"]}).status_code == 422
    second = client.post(
        f"{base}/verify", params={"after": first["next_after"], "run_id": first["run_id"]}
    ).json()
    assert (second["checked"], second["total_checked"], second["next_after"]) == (1, 3, None)
    last = client.get(base).json()["last_verification"]
    assert (last["checked"], last["complete"]) == (3, True)


def test_postgres_backend_and_access(
    client: TestClient, factory: Factory, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = dataclasses.replace(get_settings(), evidence_backend="postgres")
    monkeypatch.setattr(blackbox, "get_settings", lambda: settings)

    store = PostgresEvidenceStore(sessionmaker(bind=_worker_engine, expire_on_commit=False))
    ws, _ = run_ct(client, factory, owner_db, store)
    assert client.post(f"/api/workspaces/{ws}/blackbox/verify").json()["ok"] == 1
    # Another workspace's owner sees none of it.
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    assert client.get(f"/api/workspaces/{other}/blackbox").json()["total"] == 0
    assert client.post(f"/api/workspaces/{other}/blackbox/verify").json()["checked"] == 0
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    assert client.get(f"/api/workspaces/{ws}/blackbox").status_code == 403
    assert client.post(f"/api/workspaces/{ws}/blackbox/verify").status_code == 403
