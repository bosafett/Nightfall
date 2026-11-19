"""SENTINEL step 3a (migration 0028): extraction from the detectors, confidence, assessment with
history, suppression, expiry, retention, isolation. Test addresses are public ones, because
documentation, private and CGNAT ranges never become indicators."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.sentinel import extract
from tests.conftest import Factory, audit_actions, use
from tests.test_shield_guard import _alert, _authorize, _register, _send, _sensor, _ws
from tests.test_shield_host import _at, _post, _snap

ATTACKER = "45.33.32.156"
OTHER = "45.33.32.157"


def _sentinel(base: str) -> str:
    return base.replace("/shield", "/sentinel")


def _indicators(client: TestClient, base: str, **params: str) -> list[dict[str, Any]]:
    r = client.get(f"{_sentinel(base)}/indicators", params=params)
    assert r.status_code == 200, r.text
    return list(r.json())


def test_mapping_is_in_the_pinned_catalogue() -> None:
    extract.check_mapping()


def test_intrusion_alerts_and_blocks_become_sightings(client: TestClient, factory: Factory) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    client.post(f"{base}/allowlist", json={"cidr": OTHER})
    with _sensor(key) as s:
        _send(s, _alert(ATTACKER), _alert("203.0.113.9"), _alert(OTHER), _alert("100.64.1.1"),
              _alert("45.33.0.0/16"))  # fmt: skip
    (ind,) = _indicators(client, base)  # only the public, non-allow-listed single address
    assert (ind["type"], ind["value"], ind["sighting_count"]) == ("ip", ATTACKER, 1)
    assert ind["computed_confidence"] == ind["confidence"] == "low"
    assert ind["status"] == "active" and ind["assessment"] == "unreviewed"
    # A repeat sighting, and a GUARD block of the same address, raise it to medium (never high).
    _authorize(client, base, [sid])
    with _sensor(key) as s:
        (res,) = _send(s, _alert(ATTACKER, scenario="crowdsecurity/http-cve-2021-41773"))
        assert res["outcome"] == "blocked"
    (ind,) = _indicators(client, base)
    assert ind["sighting_count"] == 3 and ind["computed_confidence"] == "medium"
    detail = client.get(f"{_sentinel(base)}/indicators/{ind['id']}").json()
    kinds = sorted(x["source_kind"] for x in detail["sightings"])
    assert kinds == ["block", "intrusion_alert", "intrusion_alert"]
    assert {t["id"] for t in detail["techniques"]} == {"T1110", "T1021.004", "T1190"}
    assert {t["name"] for t in detail["techniques"]} >= {"Brute Force"}
    assert detail["machines"] == ["lab"]


def test_host_alerts_and_file_hashes(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    _, base = _ws(client, factory)
    _, key = _register(client, base)
    with _sensor(key) as s:
        _post(s, _snap("admins", []), _snap("files", [{"path": "/etc/passwd", "sha256": "a" * 64}]))
        _post(
            s,
            _snap("admins", [{"username": "eve", "groupname": "sudo"}], _at(30)),
            _snap("files", [{"path": "/etc/passwd", "sha256": "b" * 64}], _at(30)),
        )
    (ind,) = _indicators(client, base, type="sha256")
    assert ind["value"] == "b" * 64
    tech = (
        owner_db.execute(
            text("SELECT techniques FROM sentinel_sightings WHERE indicator_id IS NULL")
        )
        .scalars()
        .all()
    )
    assert tech == [["T1098"]]  # the new-admin alert: a technique-only sighting


def test_assessment_history_suppression_and_permissions(
    client: TestClient, factory: Factory, owner_db: Session, app_engine: Engine
) -> None:
    owner, base = _ws(client, factory)
    _, key = _register(client, base)
    with _sensor(key) as s:
        _send(s, _alert(ATTACKER))
    (ind,) = _indicators(client, base)
    url = f"{_sentinel(base)}/indicators/{ind['id']}/assess"
    viewer = factory.sign_in(factory.member(owner.workspace_id, Role.VIEWER))
    use(client, viewer)
    assert client.post(url, json={"assessment": "malicious", "reason": "x"}).status_code == 403
    analyst = factory.sign_in(factory.member(owner.workspace_id, Role.ANALYST))
    use(client, analyst)
    assert client.post(url, json={"assessment": "malicious", "reason": " "}).status_code == 422
    r = client.post(url, json={"assessment": "malicious", "reason": "Repeated SSH brute force"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["confidence"] == "high" and d["computed_confidence"] == "low"
    assert d["assessed_by"] == analyst.user.email
    r = client.post(url, json={"assessment": "false_positive", "reason": "Our scanner"})
    d = r.json()
    assert d["status"] == "suppressed" and d["confidence"] == "low"
    assert [(h["from_assessment"], h["to_assessment"]) for h in d["history"]] == [
        ("malicious", "false_positive"), ("unreviewed", "malicious"),
    ]  # fmt: skip
    assert _indicators(client, base) == []  # suppressed: not in the active list
    assert len(_indicators(client, base, status="all")) == 1
    assert audit_actions(owner_db).count("sentinel.assessed") == 2
    # A new sighting is still recorded while suppressed.
    with _sensor(key) as s:
        _send(s, _alert(ATTACKER))
    assert _indicators(client, base, status="all")[0]["sighting_count"] == 2
    # The app role can't write an assessment directly, only through the function.
    with app_engine.connect() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, false)"),
                     {"w": str(owner.workspace_id)})  # fmt: skip
        with pytest.raises(DBAPIError):
            conn.execute(text("UPDATE sentinel_indicators SET assessment = 'benign'"))
        conn.rollback()


def test_expiry_retention_and_isolation(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    _, base = _ws(client, factory)
    _, key = _register(client, base)
    with _sensor(key) as s:
        _send(s, _alert(ATTACKER), _alert(OTHER))
    owner_db.execute(text(
        "UPDATE sentinel_indicators SET expires_at = now() - interval '1 day' WHERE value = :v"
    ), {"v": ATTACKER})  # fmt: skip
    owner_db.commit()
    assert [i["value"] for i in _indicators(client, base)] == [OTHER]
    expired = next(i for i in _indicators(client, base, status="all") if i["value"] == ATTACKER)
    assert expired["status"] == "expired"
    # One year without a sighting: removed on the next ingest (with its history).
    owner_db.execute(text(
        "UPDATE sentinel_indicators SET first_seen = now() - interval '400 days', "
        "last_seen = now() - interval '400 days' WHERE value = :v"
    ), {"v": OTHER})  # fmt: skip
    owner_db.execute(
        text("UPDATE sentinel_sightings SET ingested_at = now() - interval '400 days'")
    )
    owner_db.commit()
    with _sensor(key) as s:
        _send(s, _alert("45.33.32.158"))
    values = {i["value"] for i in _indicators(client, base, status="all")}
    assert OTHER not in values and "45.33.32.158" in values
    ind_id = _indicators(client, base, status="all")[0]["id"]
    _, base2 = _ws(client, factory)
    assert client.get(f"{_sentinel(base2)}/indicators/{ind_id}").status_code == 404
    assert _indicators(client, base2, status="all") == []
