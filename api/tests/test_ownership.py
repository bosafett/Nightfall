"""Proof of control over a target (Profile B G1). No real DNS or web server is contacted."""

from collections.abc import Sequence
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.scope import ownership
from nightfall.scope.ownership import Observed
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import authorize_scope, org_project


class FakeProbes:
    def __init__(self) -> None:
        self.txt_records: dict[str, list[str]] = {}
        self.files: dict[str, tuple[int, str]] = {}
        self.calls: list[tuple[str, str]] = []

    def txt(self, name: str) -> Observed:
        self.calls.append(("txt", name))
        answers = self.txt_records.get(name, [])
        obs = {"method": "dns", "query": name, "answers": answers}
        return Observed(answers, obs, None if answers else f"{name} has no TXT record.")

    def file(self, host: str, excluded: Sequence) -> Observed:  # type: ignore[type-arg]
        self.calls.append(("file", host))
        status, body = self.files.get(host, (404, ""))
        obs = {"method": "file", "status": status, "body": body}
        if status != 200:
            return Observed([], obs, f"The file returned HTTP {status}, not 200.")
        return Observed([ln.strip() for ln in body.splitlines() if ln.strip()], obs)


@pytest.fixture
def probes(monkeypatch: pytest.MonkeyPatch) -> FakeProbes:
    p = FakeProbes()
    monkeypatch.setattr(ownership, "PROBES", p)
    return p


@pytest.fixture
def env(client: TestClient, factory: Factory, owner_db: Session) -> dict:
    ws = factory.workspace()
    owner = factory.sign_in(factory.member(ws, Role.OWNER))
    admin = factory.sign_in(factory.member(ws, Role.ADMIN))
    analyst = factory.sign_in(factory.member(ws, Role.ANALYST))
    _, pid = org_project(owner_db, ws)
    use(client, owner)
    scope = authorize_scope(
        client,
        ws,
        pid,
        [
            ("domain_tree", "example.com"),
            ("host", "app.example.com"),
            ("host", "other.test"),
            ("ip", "203.0.113.5"),
        ],
    )
    return {
        "ws": ws,
        "pid": pid,
        "owner": owner,
        "admin": admin,
        "analyst": analyst,
        "scope": scope,
    }


def _claim(client: TestClient, ws, name: str, method: str) -> dict:
    r = client.post(f"/api/workspaces/{ws}/ownership/claims", json={"name": name, "method": method})
    assert r.status_code == 201, r.text
    return r.json()


def _check(client: TestClient, ws, scope_id, claim_id):  # type: ignore[no-untyped-def]
    return client.post(f"/api/workspaces/{ws}/scopes/{scope_id}/ownership/{claim_id}/check")


def _controls(client: TestClient, env: dict) -> dict[str, dict | None]:
    scopes = client.get(f"/api/workspaces/{env['ws']}/projects/{env['pid']}/scopes").json()
    return {t["value"]: t["control"] for t in scopes[0]["targets"]}


def test_dns_proof_covers_the_domain_and_names_under_it(
    client: TestClient, env: dict, probes: FakeProbes, owner_db: Session
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    claim = _claim(client, ws, "Example.COM.", "dns")
    assert claim["name"] == "example.com" and claim["token"].startswith("janus-verify=")
    assert claim["where"] == "TXT record _janus-verify.example.com"
    # Only the hash is stored, never the token.
    stored = owner_db.execute(text("SELECT token_sha256 FROM ownership_claims")).scalar_one()
    assert claim["token"].encode() not in bytes(stored)
    assert "token" not in client.get(f"/api/workspaces/{ws}/ownership/claims").json()[0]

    # Nothing published yet: the check fails and is recorded.
    r = _check(client, ws, sid, claim["id"])
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "no TXT record" in r.json()["detail"]
    assert not any(c and c["proven"] for c in _controls(client, env).values())

    # A wrong token doesn't count; the right one among others does.
    probes.txt_records["_janus-verify.example.com"] = ["janus-verify=wrong", "v=spf1 -all"]
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is False
    probes.txt_records["_janus-verify.example.com"].append(claim["token"])
    r = _check(client, ws, sid, claim["id"])
    body = r.json()
    assert body["ok"] is True and len(body["observation_sha256"]) == 64
    assert body["observation"]["query"] == "_janus-verify.example.com"

    controls = _controls(client, env)
    assert controls["example.com"]["proven"] and controls["app.example.com"]["proven"]
    assert controls["example.com"]["method"] == "dns"
    assert controls["other.test"] == {
        "proven": False,
        "claim_id": None,
        "claim_name": None,
        "method": None,
        "checked_at": None,
    }
    assert controls["203.0.113.5"]["proven"] is False  # addresses are never eligible
    actions = audit_actions(owner_db)
    assert "ownership.claim_created" in actions and actions.count("ownership.checked") == 3


def test_file_proof_covers_only_that_host(
    client: TestClient, env: dict, probes: FakeProbes
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    claim = _claim(client, ws, "app.example.com", "file")
    assert claim["where"] == "https://app.example.com/.well-known/janus-verify.txt"
    probes.files["app.example.com"] = (200, f"\n{claim['token']}\n")
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is True
    assert probes.calls == [("file", "app.example.com")]
    controls = _controls(client, env)
    assert controls["app.example.com"]["proven"] is True
    assert controls["example.com"]["proven"] is False  # a file can't prove a whole domain


def test_freshness_latest_result_and_retirement(
    client: TestClient, env: dict, probes: FakeProbes, owner_db: Session
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    claim = _claim(client, ws, "example.com", "dns")
    probes.txt_records["_janus-verify.example.com"] = [claim["token"]]
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is True
    assert _controls(client, env)["example.com"]["proven"] is True

    # Older than 24 hours no longer counts (backdated as the database owner).
    owner_db.execute(
        text("UPDATE ownership_checks SET checked_at = checked_at - :d"),
        {"d": ownership.FRESH + timedelta(minutes=1)},
    )
    owner_db.commit()
    assert _controls(client, env)["example.com"]["proven"] is False

    # A pass followed by a failure is not proven.
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is True
    probes.txt_records.clear()
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is False
    assert _controls(client, env)["example.com"]["proven"] is False

    # A retired claim proves nothing and can't be checked; a new token can be issued.
    probes.txt_records["_janus-verify.example.com"] = [claim["token"]]
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is True
    r = client.post(f"/api/workspaces/{ws}/ownership/claims/{claim['id']}/retire")
    assert r.status_code == 200 and r.json()["retired_at"]
    assert _controls(client, env)["example.com"]["proven"] is False
    assert _check(client, ws, sid, claim["id"]).status_code == 409
    again = _claim(client, ws, "example.com", "dns")
    assert again["token"] != claim["token"]
    assert "ownership.claim_retired" in audit_actions(owner_db)


def test_new_scope_version_needs_new_proof(
    client: TestClient, env: dict, probes: FakeProbes
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    claim = _claim(client, ws, "example.com", "dns")
    probes.txt_records["_janus-verify.example.com"] = [claim["token"]]
    assert _check(client, ws, sid, claim["id"]).json()["ok"] is True
    base = f"/api/workspaces/{ws}"
    draft = client.post(f"{base}/projects/{env['pid']}/scopes").json()  # copies the targets
    assert client.post(f"{base}/scopes/{draft['id']}/authorize").status_code == 200
    assert _controls(client, env)["example.com"]["proven"] is False
    # The old version is superseded: checks against it are refused.
    assert _check(client, ws, sid, claim["id"]).status_code == 409


def test_who_may_do_what(client: TestClient, env: dict, probes: FakeProbes) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    body = {"name": "example.com", "method": "dns"}
    for who in ("admin", "analyst"):
        use(client, env[who])
        assert client.post(f"/api/workspaces/{ws}/ownership/claims", json=body).status_code == 403
    use(client, env["owner"])
    claim = _claim(client, ws, "example.com", "dns")
    assert client.post(f"/api/workspaces/{ws}/ownership/claims", json=body).status_code == 409
    use(client, env["admin"])
    assert _check(client, ws, sid, claim["id"]).status_code == 200  # admins may run checks
    assert (
        client.post(f"/api/workspaces/{ws}/ownership/claims/{claim['id']}/retire").status_code
        == 403
    )
    use(client, env["analyst"])
    assert _check(client, ws, sid, claim["id"]).status_code == 403
    assert len(client.get(f"/api/workspaces/{ws}/ownership/claims").json()) == 1


def test_bad_names_and_uncovered_scopes_are_refused(
    client: TestClient, env: dict, probes: FakeProbes, factory: Factory
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    for name in ("203.0.113.5", "*.example.com", "localhost", "https://example.com/"):
        r = client.post(
            f"/api/workspaces/{ws}/ownership/claims", json={"name": name, "method": "dns"}
        )
        assert r.status_code == 422, name
    elsewhere = _claim(client, ws, "unrelated.org", "dns")
    r = _check(client, ws, sid, elsewhere["id"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "not_in_scope"
    assert probes.calls == []  # nothing was looked up
    # Another workspace can't see or use the claim.
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    assert client.get(f"/api/workspaces/{other}/ownership/claims").json() == []
    assert _check(client, other, sid, elsewhere["id"]).status_code == 404


def test_fixture_mode_refuses_checks(client: TestClient, env: dict) -> None:
    claim = _claim(client, env["ws"], "example.com", "dns")
    r = _check(client, env["ws"], env["scope"]["id"], claim["id"])
    assert r.status_code == 409 and r.json()["detail"]["code"] == "fixture_mode"


def test_database_keeps_checks_insert_only_and_retirement_final(
    app_engine, env: dict, probes: FakeProbes, client: TestClient
) -> None:
    ws, sid = env["ws"], env["scope"]["id"]
    claim = _claim(client, ws, "example.com", "dns")
    _check(client, ws, sid, claim["id"])
    client.post(f"/api/workspaces/{ws}/ownership/claims/{claim['id']}/retire")
    with app_engine.connect() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(ws)})
        conn.commit()
        for stmt in (
            "UPDATE ownership_checks SET ok = true",
            "DELETE FROM ownership_checks",
            "UPDATE ownership_claims SET name = 'evil.example'",
            "UPDATE ownership_claims SET retired_at = NULL, retired_by_user_id = NULL",
            "DELETE FROM ownership_claims",
        ):
            with pytest.raises(DBAPIError):
                with conn.begin():
                    conn.execute(text(stmt))
