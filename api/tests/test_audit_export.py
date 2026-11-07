# ruff: noqa: F811  (pytest fixtures imported from test_watchtower)
"""Audit export with a hash chain (review F7)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.audit import export as export_mod
from nightfall.core.audit.export import genesis, link
from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.test_watchtower import _events, env  # noqa: F401 - fixture


def _export(client: TestClient, ws) -> list[dict]:
    records, cursor = [], None
    while True:
        r = client.post(f"/api/workspaces/{ws}/audit/export", json=cursor)
        assert r.status_code == 200, r.text
        page = r.json()
        assert page["genesis"] == genesis(ws)
        records += page["records"]
        if page["next"] is None:
            return records
        cursor = page["next"]


def _check(client: TestClient, ws, last: dict) -> dict:
    body = {"through_id": last["record"]["id"], "position": last["position"], "hash": last["hash"]}
    r = client.post(f"/api/workspaces/{ws}/audit/export/check", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_export_chains_pages_and_detects_tampering(
    client: TestClient, env, factory: Factory, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(export_mod, "EXPORT_PAGE", 7)
    ws = env["ws"]
    _events(owner_db, ws, [f"operation.step_{i}" for i in range(20)], password="hunter2")
    _events(owner_db, factory.workspace("Other"), ["operation.elsewhere"])
    use(client, env["owner"])
    records = _export(client, ws)

    # Every record links to the one before it, from the workspace's genesis value.
    prev = genesis(ws)
    for i, r in enumerate(records, start=1):
        assert r["position"] == i and r["hash"] == link(prev, r["record"])
        prev = r["hash"]
    actions = [r["record"]["action"] for r in records]
    assert "operation.elsewhere" not in actions and len(records) >= 20
    assert all(r["record"]["data"].get("password") in (None, "<redacted>") for r in records)
    assert "audit.exported" in audit_actions(owner_db)

    last = records[-1]
    res = _check(client, ws, last)
    assert res["match"] is True, res
    # Later events don't affect an earlier export (_events would backdate it: that's an
    # insertion into the exported range, which the position check catches below).
    owner_db.execute(
        text(
            "INSERT INTO audit_events (workspace_id, actor_type, action) "
            "VALUES (:w, 'system', 'operation.later')"
        ),
        {"w": ws},
    )
    owner_db.commit()
    assert _check(client, ws, last)["match"] is True

    # Changing an exported event (as the database owner could) is detected...
    victim = records[3]["record"]["id"]
    owner_db.execute(
        text("UPDATE audit_events SET action = 'operation.edited' WHERE id = :i"), {"i": victim}
    )
    owner_db.commit()
    res = _check(client, ws, last)
    assert (res["match"], res["problem"]) == (False, "hash")
    # ...and so is removing one.
    owner_db.execute(text("DELETE FROM audit_events WHERE id = :i"), {"i": victim})
    owner_db.commit()
    assert _check(client, ws, last)["problem"] == "position"
    owner_db.execute(text("DELETE FROM audit_events WHERE id = :i"), {"i": last["record"]["id"]})
    owner_db.commit()
    assert _check(client, ws, last)["problem"] == "missing"
    assert "audit.export_checked" in audit_actions(owner_db)


def test_export_is_owner_and_admin_only_and_workspace_confined(
    client: TestClient, env, factory: Factory, owner_db: Session
) -> None:
    ws = env["ws"]
    _events(owner_db, ws, ["operation.one"])
    use(client, env["operator"])
    assert client.post(f"/api/workspaces/{ws}/audit/export").status_code == 403
    use(client, env["admin"])
    records = _export(client, ws)
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    assert _export(client, other) == []
    res = _check(client, other, records[-1])
    assert res["problem"] == "missing"
    cursor = {
        "after": records[-1]["record"]["id"],
        "position": 1,
        "prev": "0" * 64,
        "cutoff": "2026-01-01T00:00:00Z",
    }
    assert client.post(f"/api/workspaces/{other}/audit/export", json=cursor).status_code == 404
