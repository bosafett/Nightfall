"""SHIELD v3 phase 2, safeguard 21 (migration 0030): GUARD's trial week. During the trial it records
what it would have blocked and blocks nothing; the database refuses an automatic block too."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.shield import guard
from tests.conftest import Factory, audit_actions
from tests.test_sentinel import ATTACKER, OTHER
from tests.test_shield_guard import _alert, _register, _send, _sensor, _ws


def _authorize(client: TestClient, base: str, sid: str, **kw: Any) -> dict[str, Any]:
    r = client.post(f"{base}/response-authorization", json={"sensor_ids": [sid], "days": 30, **kw})
    assert r.status_code == 201, r.text
    return dict(r.json())


def _age(owner_db: Session, days: int) -> None:
    sql = (
        "UPDATE shield_response_authorizations "
        "SET authorized_at = authorized_at - :d * interval '1 day'"
    )
    owner_db.execute(text(sql), {"d": days})
    owner_db.commit()


def test_first_week_records_what_it_would_have_blocked(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    a = _authorize(client, base, sid)  # no trial_days given: the recommended 7
    assert a["trial_days"] == 7
    with _sensor(key) as s:
        (res,) = _send(s, _alert(ATTACKER))
        assert res["outcome"] == "alert_only" and res["block_id"] is None
        assert res["reason"].startswith(f"Trial week: GUARD would have blocked {ATTACKER}/32")
        assert s.get("/api/sensor/decisions").json()["apply"] == []
    view = client.get(f"{base}/intrusion").json()
    assert view["trial_active"] and view["automatic_active"] and view["blocks"] == []
    assert view["alerts"][0]["would_have_blocked"] is True
    assert "shield.guard.trial" in audit_actions(owner_db)
    # A week later the same authorization blocks on its own.
    _age(owner_db, 8)
    with _sensor(key) as s:
        (res,) = _send(s, _alert(OTHER))
        assert res["outcome"] == "blocked", res
    view = client.get(f"{base}/intrusion").json()
    assert not view["trial_active"]
    assert {x["source"]: x["would_have_blocked"] for x in view["alerts"]} == {
        OTHER: False,
        ATTACKER: True,
    }


def test_the_owner_may_skip_it_but_not_edit_it_later(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    assert client.post(f"{base}/response-authorization",
                       json={"sensor_ids": [sid], "trial_days": 8}).status_code == 422  # fmt: skip
    _authorize(client, base, sid, trial_days=0)
    with _sensor(key) as s:
        assert _send(s, _alert(ATTACKER))[0]["outcome"] == "blocked"
    with pytest.raises(DBAPIError, match="only be ended"):
        owner_db.execute(text("UPDATE shield_response_authorizations SET trial_days = 7"))
    owner_db.rollback()


def test_database_refuses_automatic_blocks_during_the_trial(
    client: TestClient, factory: Factory, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _authorize(client, base, sid)
    # Pretend the API's own check is wrong: the database still says no.
    monkeypatch.setattr(guard, "trial_ends", lambda auth, category: utcnow() - timedelta(days=1))
    with _sensor(key) as s:
        (res,) = _send(s, _alert(ATTACKER))
    assert res["outcome"] == "refused" and res["block_id"] is None
    assert owner_db.execute(text("SELECT count(*) FROM shield_blocks")).scalar_one() == 0


def test_a_new_rule_is_alert_only_for_its_first_week(
    client: TestClient, factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, base = _ws(client, factory)
    sid, key = _register(client, base)
    _authorize(client, base, sid, trial_days=0)
    monkeypatch.setattr(guard, "NEW_RULES", {"ssh_bruteforce": utcnow() - timedelta(days=2)})
    with _sensor(key) as s:
        ssh, scan = _send(s, _alert(ATTACKER), _alert(OTHER, scenario="crowdsecurity/http-probing"))
    assert ssh["outcome"] == "alert_only" and ssh["reason"].startswith("Trial week")
    assert scan["outcome"] == "blocked"
