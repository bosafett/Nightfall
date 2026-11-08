# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""BLACK ICE: source freshness and report replay (review §14)."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blackice import replay as replay_mod
from nightfall.blackice.finding_rules import Draft
from nightfall.config import get_settings
from nightfall.core.db.models import Confidence, Severity
from nightfall.recon.collectors import FixtureCertificateTransparency, collectors
from tests.conftest import use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture


def sources(client: TestClient, env) -> dict[str, dict[str, Any]]:
    use(client, env["viewer"])
    body = client.get(f"/api/workspaces/{env['ws']}/sources").json()
    assert body["stale_after_days"] == 7
    return {s["key"]: s for s in body["sources"]}


def collect(client: TestClient, env, tool: str = "ct", target: str = "example.com") -> str:
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": tool, "target": target},
    )
    assert r.status_code in (200, 202), r.text
    return r.json()["id"]


class Down(FixtureCertificateTransparency):
    def run(self, target, ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("crt.sh (the public certificate-log search) is unavailable right now")


def test_freshness_follows_the_operations(
    client: TestClient, env, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert {k: s["state"] for k, s in sources(client, env).items()} == {
        "ct": "never_run",
        "dns": "never_run",
        "http": "never_run",
        "nuclei": "never_run",
        "tls": "never_run",
        "headers": "never_run",
        # Lab tool pack 1: no BLACKSITE and no pack review on this deployment.
        "nuclei-pack1-cve": "unavailable",
        "nuclei-pack1-config": "unavailable",
        "nuclei-pack1-tech": "unavailable",
        "auth-audit": "unavailable",  # Profile B: off on this deployment
        "access-audit": "unavailable",
        "input-audit": "unavailable",
    }
    collect(client, env)
    make_worker().run_once()
    ct = sources(client, env)["ct"]
    assert ct["state"] == "fresh" and ct["last_success_at"] and ct["last_error"] is None

    # The source goes down: the latest run failed, so it's failing, with the reason.
    collect(client, env, target="www.example.com")
    make_worker({**collectors("fixture"), "ct": Down()}).run_once()
    ct = sources(client, env)["ct"]
    assert ct["state"] == "failing" and "unavailable right now" in ct["last_error"]

    # It recovers.
    collect(client, env, target="api.example.com")
    make_worker().run_once()
    assert sources(client, env)["ct"]["state"] == "fresh"

    # No success for over a week: stale.
    owner_db.execute(text("UPDATE operations SET finished_at = finished_at - interval '8 days'"))
    owner_db.commit()
    assert sources(client, env)["ct"]["state"] == "stale"

    # Serverless hosting without the tool sandbox can't run Nuclei at all.
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    get_settings.cache_clear()
    try:
        assert sources(client, env)["nuclei"]["state"] == "unavailable"
    finally:
        monkeypatch.delenv("NIGHTFALL_ON_DEMAND_WORKER")
        get_settings.cache_clear()


def _report_with_rule_findings(client: TestClient, env) -> str:
    op = collect(client, env, tool="http", target="www.example.com")
    use(client, env["operator"])
    approved = client.post(
        f"/api/workspaces/{env['ws']}/operations/{op}/approve", json={"reason": "test"}
    )
    assert approved.status_code == 200, approved.text
    make_worker().run_once()
    use(client, env["owner"])
    r = client.post(f"/api/workspaces/{env['ws']}/projects/{env['pid']}/reports")
    assert r.status_code == 201, r.text
    return r.json()["id"]


def replayed(client: TestClient, env, report: str) -> dict[str, Any]:
    use(client, env["viewer"])
    r = client.get(f"/api/workspaces/{env['ws']}/reports/{report}/replay")
    assert r.status_code == 200, r.text
    return r.json()


def test_replay_matches_when_rules_are_unchanged(
    client: TestClient, env, owner_db: Session
) -> None:
    report = _report_with_rule_findings(client, env)
    d = replayed(client, env, report)
    assert d["evidence_considered"] >= 1
    assert d["current_ruleset"] in d["snapshot_ruleset"]
    titles = {i["title"] for i in d["unchanged"]}
    assert "nginx version disclosed in HTTP headers" in titles
    assert d["changed"] == d["new"] == d["gone"] == []

    # Evidence collected after the report doesn't count: the replay is "as of" the report.
    later = collect(client, env, tool="http", target="api.example.com")
    use(client, env["operator"])
    client.post(f"/api/workspaces/{env['ws']}/operations/{later}/approve", json={})
    make_worker().run_once()
    assert replayed(client, env, report)["new"] == []


def test_replay_shows_what_a_rule_change_would_do_without_changing_anything(
    client: TestClient, env, owner_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _report_with_rule_findings(client, env)
    before = owner_db.execute(
        text("SELECT content_sha256 FROM assessment_snapshots WHERE id = :i"), {"i": report}
    ).scalar_one()
    findings_before = owner_db.execute(
        text("SELECT id, severity, title, validation_status FROM findings ORDER BY id")
    ).all()

    original = replay_mod.drafts_for

    def new_rules(summary, now):  # type: ignore[no-untyped-def]
        out = []
        for d in original(summary, now):
            if "PHP" in d.title:
                continue  # rule retired
            if "nginx" in d.title:
                d = Draft(**{**d.__dict__, "severity": Severity.MEDIUM})  # re-rated
            out.append(d)
        if summary.get("http"):
            out.append(
                Draft(
                    check_id="http.new-rule",
                    rule_id="R7-new",
                    title="A new rule's finding",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description="",
                    impact="",
                    remediation="",
                )
            )
        return out

    monkeypatch.setattr(replay_mod, "drafts_for", new_rules)
    d = replayed(client, env, report)
    assert [(c["then"]["severity"], c["now"]["severity"]) for c in d["changed"]] == [
        ("low", "medium")
    ]
    assert [g["title"] for g in d["gone"]] == ["PHP version disclosed in HTTP headers"]
    assert [n["title"] for n in d["new"]] == ["A new rule's finding"]

    # Read-only: the snapshot and the findings are untouched, and the report still verifies.
    after = owner_db.execute(
        text("SELECT content_sha256 FROM assessment_snapshots WHERE id = :i"), {"i": report}
    ).scalar_one()
    assert after == before
    assert (
        owner_db.execute(
            text("SELECT id, severity, title, validation_status FROM findings ORDER BY id")
        ).all()
        == findings_before
    )
    use(client, env["viewer"])
    assert client.get(f"/api/workspaces/{env['ws']}/reports/{report}").json()["integrity_ok"]


def test_replay_is_tenant_scoped(client: TestClient, env, factory) -> None:  # type: ignore[no-untyped-def]
    from nightfall.core.db.models import Role

    report = _report_with_rule_findings(client, env)
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    assert client.get(f"/api/workspaces/{other}/reports/{report}/replay").status_code == 404
    assert client.get(f"/api/workspaces/{env['ws']}/reports/{report}/replay").status_code in (
        403,
        404,
    )


def test_old_snapshots_without_check_ids_still_compare(
    client: TestClient, env, owner_db: Session
) -> None:
    report = _report_with_rule_findings(client, env)
    owner_db.execute(
        text(
            "UPDATE assessment_snapshots SET content = jsonb_set(content, '{findings}', "
            "(SELECT jsonb_agg(f - 'check_id') FROM jsonb_array_elements(content->'findings') f))"
            " WHERE id = :i"
        ),
        {"i": report},
    )
    owner_db.commit()
    d = replayed(client, env, report)
    assert d["changed"] == d["new"] == d["gone"] == [] and d["unchanged"]
