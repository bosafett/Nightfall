# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""Temporary self-review mode (owner decision 2026-11-08): explicit, labelled, time-limited."""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from nightfall.blackops import profile_b
from nightfall.config import ConfigError, get_settings, load_settings
from nightfall.control.reviews import review
from nightfall.tools.nuclei import pack1
from tests.conftest import use
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_lab import _active_lab_scope

NOW = datetime(2026, 11, 8, tzinfo=UTC)


def test_the_rule() -> None:
    s = get_settings()
    assert review(None, s, NOW, "X").kind == "none" and not review("", s, NOW, "X").ok
    r = review("REV-2026-12-01 Jane Doe", s, NOW, "X")
    assert (r.kind, r.ok) == ("independent", True)
    off = review("SELF:owner", dataclasses.replace(s, self_review_until=None), NOW, "X")
    assert (off.kind, off.ok) == ("self", False) and "self-review mode is off" in (
        off.problem or ""
    )
    on = review(
        "self:owner", dataclasses.replace(s, self_review_until=NOW + timedelta(days=5)), NOW, "X"
    )
    assert on.ok and "NOT independent" in on.label
    ended = review("SELF:owner", dataclasses.replace(s, self_review_until=NOW), NOW, "X")
    assert not ended.ok and "ended" in (ended.problem or "")


def test_window_is_at_most_90_days(monkeypatch: pytest.MonkeyPatch) -> None:
    far = (datetime.now(UTC) + timedelta(days=91)).date().isoformat()
    monkeypatch.setenv("NIGHTFALL_SELF_REVIEW_UNTIL", far)
    with pytest.raises(ConfigError, match="90 days"):
        load_settings()
    monkeypatch.setenv("NIGHTFALL_SELF_REVIEW_UNTIL", "next week")
    with pytest.raises(ConfigError, match="must be a date"):
        load_settings()
    soon = (datetime.now(UTC) + timedelta(days=30)).date().isoformat()
    monkeypatch.setenv("NIGHTFALL_SELF_REVIEW_UNTIL", soon)
    assert load_settings().self_review_until is not None


def test_features_unlock_only_inside_the_window() -> None:
    s = dataclasses.replace(
        get_settings(),
        blacksite_enabled=True,
        lab_pack1_review_ref="SELF:owner 2026-11-08",
        profile_b_enabled=True,
        profile_b_review_ref="SELF:owner 2026-11-08",
        profile_b_public_key="x",
        on_demand_worker=False,
    )
    assert pack1.unavailable_reason(s) and profile_b.unavailable_reason(s)  # no window
    inside = dataclasses.replace(s, self_review_until=datetime.now(UTC) + timedelta(days=1))
    assert pack1.unavailable_reason(inside) is None
    assert profile_b.unavailable_reason(inside) is None
    past = dataclasses.replace(s, self_review_until=datetime.now(UTC) - timedelta(minutes=1))
    assert "ended" in (profile_b.unavailable_reason(past) or "")


def test_lab_runs_under_self_review_are_labelled_everywhere(
    client: TestClient, blacksite: TestClient, env, monkeypatch: pytest.MonkeyPatch, owner_db
) -> None:
    from sqlalchemy import text

    from tests.test_blackops import launch, preflight

    monkeypatch.setenv("NIGHTFALL_BLACKSITE_REVIEW_REF", "SELF:owner 2026-11-08")
    get_settings.cache_clear()
    _active_lab_scope(client, env)
    pre = preflight(blacksite, env, "owner", "http-security-assessment", "172.30.99.10")
    check = {c["key"]: c for c in pre["checks"]}["review"]
    assert check["status"] == "fail" and "self-review mode is off" in check["detail"]

    until = (datetime.now(UTC) + timedelta(days=30)).date().isoformat()
    monkeypatch.setenv("NIGHTFALL_SELF_REVIEW_UNTIL", until)
    get_settings.cache_clear()
    pre = preflight(blacksite, env, "owner", "http-security-assessment", "172.30.99.10")
    check = {c["key"]: c for c in pre["checks"]}["review"]
    assert check["status"] == "pass" and "NOT independent" in check["detail"]
    assert (
        launch(blacksite, env, "owner", "http-security-assessment", "172.30.99.10").status_code
        == 201
    )
    data = owner_db.execute(
        text("SELECT data FROM audit_events WHERE action = 'playbook.requested'")
    ).scalar_one()
    assert data["review_kind"] == "self" and "NOT independent" in data["review"]
    use(client, env["owner"])
    lib = client.get(f"/api/workspaces/{env['ws']}/blackops/playbooks").json()
    assert any("BLACKSITE" in n and "NOT independent" in n for n in lib["self_review_notices"])
    status = blacksite.get(f"/api/workspaces/{env['ws']}/blacksite/status").json()
    assert status["review_kind"] == "self" and status["review_recorded"] is True
    get_settings.cache_clear()
