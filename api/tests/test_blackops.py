# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""BLACK OPS (Addendum 4): playbooks are bundles of ordinary, scope-checked operations.

Covers the playbook framework itself: catalog integrity, preflight, server-side
authorization, two-person approval, scope re-checks, live/lab separation, BLACK ICE
capture, history, and that every refusal leaves an audit event.
"""

import ast
import ipaddress
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.orm import Session

from nightfall.blackops.catalog import PLAYBOOKS, Playbook, Profile, Step, check_catalog
from nightfall.recon.posture import HeaderAudit
from nightfall.recon.safe_http import SafeHttp
from tests.conftest import audit_actions, use
from tests.phase3_helpers import authorize_scope, make_worker
from tests.test_agents import ai_on, env  # noqa: F401 - fixtures
from tests.test_lab import APP, LAB, _active_lab_scope, lab_worker

GOLDEN = Path(__file__).parent / "golden" / "playbooks.json"


def base(env) -> str:
    return f"/api/workspaces/{env['ws']}/blackops"


def preflight(client: TestClient, env, who: str, playbook: str, target: str) -> dict:
    use(client, env[who])
    r = client.post(
        f"{base(env)}/projects/{env['pid']}/preflight",
        json={"playbook_id": playbook, "target": target},
    )
    assert r.status_code == 200, r.text
    return r.json()


def launch(client: TestClient, env, who: str, playbook: str, target: str) -> httpx.Response:
    p = PLAYBOOKS[playbook]
    use(client, env[who])
    return client.post(
        f"{base(env)}/projects/{env['pid']}/runs",
        json={
            "playbook_id": playbook,
            "target": target,
            "version": p.version,
            "definition_sha256": p.sha256,
        },
    )


def drain(worker: Any) -> None:
    while worker.run_once():
        pass


def failed(pre: dict) -> set[str]:
    return {c["key"] for c in pre["checks"] if c["status"] == "fail"}


# --- Catalog -------------------------------------------------------------------------


def test_catalog_fingerprints_are_pinned() -> None:
    """A definition can't change without a version bump (and a reviewed golden update)."""
    pinned = json.loads(GOLDEN.read_text())
    assert pinned == {f"{p.id}@{p.version}": p.sha256 for p in PLAYBOOKS.values()}


def test_catalog_starts_with_the_five_low_risk_playbooks() -> None:
    assert list(PLAYBOOKS) == [
        "surface-mapper",
        "service-fingerprinter",
        "web-exposure-audit",
        "tls-configuration-audit",
        "http-security-assessment",
    ]
    for p in PLAYBOOKS.values():
        assert p.risk_class.value in ("passive", "low")
        assert Profile.VALIDATION not in p.profiles


def test_listed_tests_exist() -> None:
    for p in PLAYBOOKS.values():
        for ref in p.tests:
            path, name = ref.split("::")
            tree = ast.parse((Path(__file__).parent.parent / path).read_text())
            names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
            assert name in names, f"{p.id} lists missing test {ref}"


@pytest.mark.parametrize(
    "steps,profiles,message",
    [
        ((Step("shell", "x"),), (Profile.LIVE,), "unknown tool"),
        ((Step("ct", "x"),), (Profile.LAB,), "can't run in the lab"),
        ((Step("http", "x"),), (Profile.VALIDATION,), "profile B"),
        ((), (Profile.LIVE,), "1 to 20 steps"),
    ],
)
def test_catalog_check_refuses_unreviewable_definitions(
    monkeypatch: pytest.MonkeyPatch, steps: tuple, profiles: tuple, message: str
) -> None:
    bad = Playbook(
        **{
            **PLAYBOOKS["surface-mapper"].__dict__,
            "id": "bad",
            "steps": steps,
            "profiles": profiles,
        }
    )
    monkeypatch.setitem(PLAYBOOKS, "bad", bad)
    with pytest.raises(ValueError, match=message):
        check_catalog()


# --- Library and settings ------------------------------------------------------------


def test_library_shows_availability_and_who_may_run(client: TestClient, env) -> None:
    use(client, env["viewer"])
    lib = client.get(f"{base(env)}/playbooks").json()
    assert [p["id"] for p in lib["playbooks"]] == list(PLAYBOOKS)
    assert lib["can_run"] is False and lib["can_manage"] is False
    assert {p["key"]: p["available"] for p in lib["profiles"]} == {
        "live": True,
        "validation": False,
        "lab": True,
    }
    use(client, env["owner"])
    lib = client.get(f"{base(env)}/playbooks").json()
    assert lib["can_run"] is True and lib["can_manage"] is True
    assert all(p["availability"] == "available" for p in lib["playbooks"])
    detail = client.get(f"{base(env)}/playbooks/tls-configuration-audit").json()
    assert detail["definition_sha256"] == PLAYBOOKS["tls-configuration-audit"].sha256
    assert detail["dependencies"] and detail["changelog"][0]["version"] == "1.0.0"
    assert client.get(f"{base(env)}/playbooks/rm-rf").status_code == 404


def test_disabling_a_playbook_blocks_launch_and_is_recorded(
    client: TestClient, env, owner_db: Session
) -> None:
    use(client, env["operator"])  # operators can't manage the library
    r = client.put(f"{base(env)}/playbooks/surface-mapper/setting", json={"enabled": False})
    assert r.status_code == 403
    use(client, env["owner"])
    r = client.put(f"{base(env)}/playbooks/surface-mapper/setting", json={"enabled": False})
    assert r.status_code == 200 and r.json()["availability"] == "disabled"
    assert r.json()["setting_history"][0]["enabled"] is False
    assert "enabled" in failed(preflight(client, env, "owner", "surface-mapper", "example.com"))
    assert launch(client, env, "owner", "surface-mapper", "example.com").status_code == 422
    assert "playbook.setting_changed" in audit_actions(owner_db)
    assert "playbook.denied" in audit_actions(owner_db)


# --- Preflight and server-side authorization -----------------------------------------


def test_preflight_checks(client: TestClient, env) -> None:
    ok = preflight(client, env, "owner", "surface-mapper", "Example.COM.")
    assert ok["allowed"] is True and ok["target"] == "example.com" and ok["profile"] == "live"
    assert ok["needs_approval"] is False and ok["scope_version"] == 1
    assert [s["tool"] for s in ok["steps"]] == ["ct", "dns"]

    assert failed(preflight(client, env, "owner", "surface-mapper", "evil.test")) == {"scope"}
    assert failed(
        preflight(client, env, "owner", "tls-configuration-audit", "mail.example.com")
    ) == {"scope"}  # excluded
    low = preflight(client, env, "owner", "tls-configuration-audit", "www.example.com")
    assert low["allowed"] is True and low["needs_approval"] is True
    # The viewer can read the checklist but isn't authorized to launch.
    assert failed(preflight(client, env, "viewer", "surface-mapper", "example.com")) == {
        "permission"
    }


@pytest.mark.parametrize(
    "target,check",
    [("evil.test", "scope"), ("mail.example.com", "scope"), ("169.254.169.254", "scope")],
)
def test_out_of_scope_launch_is_refused_and_audited(
    client: TestClient, env, owner_db: Session, target: str, check: str
) -> None:
    r = launch(client, env, "owner", "service-fingerprinter", target)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "preflight_failed"
    row = owner_db.execute(
        text("SELECT data FROM audit_events WHERE action = 'playbook.denied'")
    ).scalar_one()
    assert check in row["failed_checks"] and row["target"] == target
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0


def test_only_owners_launch(client: TestClient, env, owner_db: Session) -> None:
    for who in ("operator", "analyst", "viewer"):
        assert launch(client, env, who, "surface-mapper", "example.com").status_code == 403
    assert audit_actions(owner_db).count("authz.denied") == 3


def test_stale_definition_is_refused(client: TestClient, env, owner_db: Session) -> None:
    use(client, env["owner"])
    r = client.post(
        f"{base(env)}/projects/{env['pid']}/runs",
        json={
            "playbook_id": "surface-mapper",
            "target": "example.com",
            "version": "0.9.0",
            "definition_sha256": "0" * 64,
        },
    )
    assert r.status_code == 422 and r.json()["detail"]["code"] == "definition_changed"
    assert "playbook.denied" in audit_actions(owner_db)


# --- Execution -----------------------------------------------------------------------


def test_passive_playbook_runs_without_approval(client: TestClient, env, owner_db: Session) -> None:
    r = launch(client, env, "owner", "surface-mapper", "example.com")
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "running" and run["profile"] == "live"
    assert [s["status"] for s in run["steps"]] == ["queued", "queued"]
    drain(make_worker())
    run = client.get(f"{base(env)}/runs/{run['id']}").json()
    assert run["status"] == "succeeded" and run["definition_current"] is True
    assert len(run["evidence"]) == 2
    # BLACK ICE registered in-scope names only.
    names = set(owner_db.execute(text("SELECT value FROM assets")).scalars())
    assert "www.example.com" in names and "cdn.third-party.example" not in names
    history = client.get(f"{base(env)}/runs", params={"project_id": str(env["pid"])}).json()
    assert [h["id"] for h in history] == [run["id"]]
    assert "playbook.requested" in audit_actions(owner_db)


def test_low_risk_run_needs_a_second_person(client: TestClient, env, owner_db: Session) -> None:
    run = launch(client, env, "owner", "tls-configuration-audit", "www.example.com").json()
    assert run["status"] == "awaiting_approval"
    worker = make_worker()
    assert worker.run_once() is False  # nothing claimable before approval

    use(client, env["owner"])
    r = client.post(f"{base(env)}/runs/{run['id']}/approve", json={})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "self_approval"
    use(client, env["analyst"])  # can't approve at all
    assert client.post(f"{base(env)}/runs/{run['id']}/approve", json={}).status_code == 403

    use(client, env["operator"])
    r = client.post(f"{base(env)}/runs/{run['id']}/approve", json={"reason": "Ticket 7"})
    assert r.status_code == 200 and r.json()["status"] == "running"
    drain(worker)
    run = client.get(f"{base(env)}/runs/{run['id']}").json()
    assert run["status"] == "succeeded"
    assert {f["check_id"] for f in run["findings"]} == {"tls.legacy-protocol"}
    assert all(f["validation_status"] == "unverified" for f in run["findings"])
    actions = audit_actions(owner_db)
    assert {"playbook.denied", "playbook.approved", "operation.approved"} <= set(actions)


def test_approved_run_executes_and_reaches_black_ice(client: TestClient, env) -> None:
    run = launch(client, env, "owner", "http-security-assessment", "www.example.com").json()
    use(client, env["operator"])
    client.post(f"{base(env)}/runs/{run['id']}/approve", json={})
    drain(make_worker())
    use(client, env["owner"])
    run = client.get(f"{base(env)}/runs/{run['id']}").json()
    assert {f["check_id"] for f in run["findings"]} == {
        "http.hsts-short-max-age",
        "http.missing-csp",
        "http.no-framing-protection",
        "http.cookie-not-secure.session",
    }
    ev = run["evidence"][0]
    raw = client.get(f"/api/workspaces/{env['ws']}/evidence/{ev['id']}/content").content
    assert b"secret-value" not in raw and b"session=<redacted>" in raw  # cookie values dropped
    # Re-running correlates with the same findings instead of duplicating them.
    again = launch(client, env, "owner", "http-security-assessment", "www.example.com").json()
    use(client, env["operator"])
    client.post(f"{base(env)}/runs/{again['id']}/approve", json={})
    drain(make_worker())
    use(client, env["owner"])
    again = client.get(f"{base(env)}/runs/{again['id']}").json()
    assert {f["id"] for f in again["findings"]} == {f["id"] for f in run["findings"]}
    assert {f["change"] for f in again["findings"]} == {"seen_again"}


def test_scope_change_before_approval_denies_the_steps(client: TestClient, env) -> None:
    run = launch(client, env, "owner", "service-fingerprinter", "www.example.com").json()
    use(client, env["owner"])
    authorize_scope(client, env["ws"], env["pid"], [("host", "other.example.org")])
    use(client, env["operator"])
    out = client.post(f"{base(env)}/runs/{run['id']}/approve", json={}).json()
    assert out["status"] == "denied"
    assert all("scope changed" in s["denial_reason"] for s in out["steps"])


def test_overlapping_run_is_blocked_and_cancel_releases_it(client: TestClient, env) -> None:
    first = launch(client, env, "owner", "tls-configuration-audit", "www.example.com").json()
    pre = preflight(client, env, "owner", "tls-configuration-audit", "www.example.com")
    assert failed(pre) == {"conflicts"}
    use(client, env["owner"])
    out = client.post(f"{base(env)}/runs/{first['id']}/cancel").json()
    assert out["status"] == "cancelled"
    assert preflight(client, env, "owner", "tls-configuration-audit", "www.example.com")["allowed"]


def test_budget_is_checked(client: TestClient, env, owner_db: Session) -> None:
    owner_db.execute(
        text(
            "INSERT INTO operations (workspace_id, project_id, scope_id, tool, risk_class, "
            "target_value, status) SELECT workspace_id, project_id, id, 'dns', 'passive', "
            "'n' || g || '.example.com', 'succeeded' FROM scopes, generate_series(1, 119) g"
        )
    )
    owner_db.commit()
    pre = preflight(client, env, "owner", "surface-mapper", "example.com")
    assert failed(pre) == {"budget"}


# --- Profiles: live and lab stay apart -----------------------------------------------


def lab_headers() -> HeaderAudit:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == APP
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<p>lab</p>")

    def make(excluded: list[Any]) -> SafeHttp:
        return SafeHttp(
            excluded_networks=excluded, only_networks=[LAB], transport=httpx.MockTransport(handler)
        )

    return HeaderAudit(make_client=make)


def test_lab_profile_routes_to_the_lab_worker(client: TestClient, env, owner_db: Session) -> None:
    _active_lab_scope(client, env)
    pre = preflight(client, env, "owner", "surface-mapper", APP)
    assert pre["profile"] == "lab" and "profile" in failed(pre)  # live-only playbook
    pre = preflight(client, env, "owner", "web-exposure-audit", APP)
    assert pre["allowed"] and pre["profile"] == "lab" and pre["needs_approval"]

    run = launch(client, env, "owner", "http-security-assessment", APP).json()
    assert run["profile"] == "lab" and run["status"] == "awaiting_approval"
    use(client, env["operator"])
    client.post(f"{base(env)}/runs/{run['id']}/approve", json={})
    assert make_worker().run_once() is False  # the normal worker never sees lab work
    drain(lab_worker({"headers": lab_headers()}))
    use(client, env["owner"])
    run = client.get(f"{base(env)}/runs/{run['id']}").json()
    assert run["status"] == "succeeded"
    assert owner_db.execute(text("SELECT bool_and(is_simulation) FROM evidence")).scalar_one()
    assert ipaddress.ip_address(APP) in LAB


# --- Database guards -----------------------------------------------------------------


def test_runs_are_insert_only_and_operations_cant_be_moved(
    client: TestClient, env, owner_db: Session, app_engine: Engine
) -> None:
    run = launch(client, env, "owner", "tls-configuration-audit", "www.example.com").json()
    with app_engine.connect() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(env["ws"])})
        with pytest.raises(ProgrammingError, match="permission denied"):
            conn.execute(text("UPDATE playbook_runs SET target_value = 'evil.test'"))
    with pytest.raises(DBAPIError, match="playbook run cannot change"):
        owner_db.execute(text("UPDATE operations SET playbook_step = 2"))
    owner_db.rollback()
    with pytest.raises(DBAPIError, match="does not match its playbook run"):
        owner_db.execute(
            text(
                "INSERT INTO operations (workspace_id, project_id, scope_id, tool, risk_class, "
                "target_value, requested_by_user_id, playbook_run_id, playbook_step) "
                "SELECT workspace_id, project_id, scope_id, 'http', 'low', 'evil.test', "
                "requested_by_user_id, id, 2 FROM playbook_runs WHERE id = :r"
            ),
            {"r": run["id"]},
        )
    owner_db.rollback()
