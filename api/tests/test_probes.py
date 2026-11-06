# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""BLACKSITE probe deck (JANUS Phase 2): bounded probes against registered lab assets."""

import socket
import uuid
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blacksite.probes import Probe, ProbeSpec, diff
from nightfall.recon.safe_http import SafeHttp
from tests.conftest import use
from tests.phase3_helpers import make_worker, org_project
from tests.test_agents import ai_on, env  # noqa: F401 - fixtures
from tests.test_lab import APP, LAB, lab_worker

SEEN: list[httpx.Request] = []


def lab_scope(client: TestClient, env, **bounds: Any) -> None:
    base = f"/api/workspaces/{env['ws']}"
    use(client, env["owner"])
    pid = env["pid"]
    sid = client.post(f"{base}/projects/{pid}/scopes").json()["id"]
    for t in client.get(f"{base}/projects/{pid}/scopes").json()[0]["targets"]:
        client.delete(f"{base}/scopes/{sid}/targets/{t['id']}")
    client.patch(f"{base}/scopes/{sid}", json={"is_lab": True, "authorization_reference": "Lab"})
    r = client.post(f"{base}/scopes/{sid}/targets", json={"kind": "ip", "value": APP, **bounds})
    assert r.status_code == 201, r.text
    assert client.post(f"{base}/scopes/{sid}/authorize").status_code == 200


def lab_asset(owner_db: Session, env, value: str = APP, org: Any = None) -> str:
    org = (
        org
        or owner_db.execute(
            text("SELECT organization_id FROM projects WHERE id = :p"), {"p": env["pid"]}
        ).scalar_one()
    )
    aid = owner_db.execute(
        text(
            "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
            "VALUES (:w, :o, 'ip_address', :v, 'manual') RETURNING id"
        ),
        {"w": env["ws"], "o": org, "v": value},
    ).scalar_one()
    owner_db.commit()
    return str(aid)


def probe(bs: TestClient, env, asset: str, spec: dict, **extra: Any) -> httpx.Response:
    use(bs, env["owner"])
    return bs.post(
        f"/api/workspaces/{env['ws']}/blacksite/probes",
        json={"project_id": str(env["pid"]), "asset_id": asset, "spec": spec, **extra},
    )


def fake_lab(status: int = 200, body: str = "<p>lab</p>") -> Probe:
    def handler(request: httpx.Request) -> httpx.Response:
        SEEN.append(request)
        assert request.url.host == APP  # pinned to the checked address
        return httpx.Response(
            status,
            headers={"Set-Cookie": "sid=s3cret-cookie", "Location": "http://169.254.169.254/"},
            text=body,
        )

    def make(excluded: list[Any]) -> SafeHttp:
        return SafeHttp(
            excluded_networks=excluded, only_networks=[LAB], transport=httpx.MockTransport(handler)
        )

    return Probe(make_client=make)


def drain(worker: Any) -> None:
    while worker.run_once():
        pass


def denied_codes(db: Session) -> list[str]:
    db.expire_all()
    return list(
        db.execute(
            text("SELECT data->>'code' FROM audit_events WHERE action = 'probe.denied'")
        ).scalars()
    )


@pytest.fixture
def lab(client: TestClient, env, owner_db: Session) -> str:
    lab_scope(client, env)
    return lab_asset(owner_db, env)


def test_http_probe_end_to_end_redacts_and_never_follows(
    blacksite: TestClient, env, lab: str, owner_db: Session
) -> None:
    SEEN.clear()
    r = probe(
        blacksite,
        env,
        lab,
        {
            "type": "http",
            "scheme": "http",
            "path": "/rest/admin?x=1",
            "headers": {"Authorization": "Bearer t0ken-secret", "X-Test": "1"},
        },  # fmt: skip
        approve=True,
        reason="Lab check",
    )
    assert r.status_code == 201, r.text
    op = r.json()
    assert op["status"] == "queued" and op["is_lab"] and op["risk_class"] == "low"
    assert make_worker().run_once() is False  # the normal worker never sees it
    drain(lab_worker({"probe": fake_lab(status=302)}))
    detail = blacksite.get(f"/api/workspaces/{env['ws']}/operations/{op['id']}").json()
    assert detail["status"] == "succeeded", detail
    assert len(SEEN) == 1 and SEEN[0].method == "GET"  # the redirect was not followed
    assert (
        SEEN[0].headers["host"] == APP and SEEN[0].headers["authorization"] == "Bearer t0ken-secret"
    )
    raw = owner_db.execute(
        text("SELECT summary FROM evidence WHERE operation_id = :o"), {"o": op["id"]}
    ).scalar_one()["probe"]
    blob = str(raw)
    assert "t0ken-secret" not in blob and "s3cret-cookie" not in blob and "<redacted>" in blob
    assert raw["result"]["location"] == "http://169.254.169.254/"
    approver = owner_db.execute(
        text("SELECT approver_user_id FROM approvals WHERE operation_id = :o"), {"o": op["id"]}
    ).scalar_one()
    assert approver == env["owner"].user.id


@pytest.mark.parametrize(
    ("spec", "extra", "status", "code"),
    [
        ({"type": "http", "port": 8080}, {}, 422, "probe_rejected"),
        ({"type": "tcp", "ports": [22, 80]}, {}, 422, "probe_rejected"),
        ({"type": "http", "method": "POST", "body": "{}"}, {}, 422, "confirm_required"),
    ],
)
def test_bounds_are_enforced_and_audited(
    blacksite: TestClient, env, lab: str, owner_db: Session, spec: dict, extra: dict, status: int,
    code: str,
) -> None:  # fmt: skip
    r = probe(blacksite, env, lab, spec, **extra)
    assert r.status_code == status and r.json()["detail"]["code"] == code, r.text
    assert code in denied_codes(owner_db)
    assert owner_db.execute(text("SELECT count(*) FROM operations")).scalar_one() == 0


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "http", "headers": {"Host": "evil.test"}},
        {"type": "http", "headers": {"Connection": "upgrade"}},
        {"type": "http", "headers": {"X-Forwarded-For": "1.2.3.4"}},
        {"type": "http", "headers": {"X-A": "a\r\nInjected: 1"}},
        {"type": "http", "path": "http://evil.test/"},
        {"type": "http", "path": "/a b"},
        {"type": "http", "body": "x"},
        {"type": "http", "method": "CONNECT"},
        {"type": "tcp", "ports": list(range(1, 12))},
        {"type": "dns"},
    ],
)
def test_malformed_specs_are_refused(blacksite: TestClient, env, lab: str, spec: dict) -> None:
    r = probe(blacksite, env, lab, spec)
    assert r.status_code == 422, spec


def test_targets_only_by_registered_in_scope_asset(
    blacksite: TestClient, client: TestClient, env, lab: str, owner_db: Session
) -> None:
    assert (
        probe(blacksite, env, str(uuid.uuid4()), {"type": "tcp", "ports": [80]}).status_code == 404
    )
    # A registered lab address outside the authorized scope.
    other = lab_asset(owner_db, env, "172.30.99.20")
    r = probe(blacksite, env, other, {"type": "tcp", "ports": [80]})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "out_of_scope"
    # A real-world (public) asset is invisible to BLACKSITE.
    public = owner_db.execute(
        text(
            "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
            "SELECT workspace_id, organization_id, 'ip_address', '8.8.8.8', 'manual' "
            "FROM assets LIMIT 1 RETURNING id"
        )
    ).scalar_one()
    owner_db.commit()
    assert probe(blacksite, env, str(public), {"type": "tcp", "ports": [80]}).status_code == 404
    assert set(denied_codes(owner_db)) >= {"unregistered_target", "out_of_scope"}


def test_probe_routes_exist_only_in_blacksite(client: TestClient, env, lab: str) -> None:
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{env['ws']}/blacksite/probes",
        json={
            "project_id": str(env["pid"]),
            "asset_id": lab,
            "spec": {"type": "tcp", "ports": [80]},
        },
    )
    assert r.status_code == 404


def test_one_pending_rate_and_budget(
    client: TestClient, blacksite: TestClient, env, owner_db: Session
) -> None:
    lab_scope(client, env, allowed_ports=[80], max_rps=10, daily_budget=2)
    asset = lab_asset(owner_db, env)
    first = probe(blacksite, env, asset, {"type": "tcp", "ports": [80]}).json()
    r = probe(blacksite, env, asset, {"type": "tcp", "ports": [80]})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "probe_pending"
    blacksite.post(f"/api/workspaces/{env['ws']}/operations/{first['id']}/cancel")
    assert probe(blacksite, env, asset, {"type": "tcp", "ports": [80]}).status_code == 201
    owner_db.execute(text("UPDATE operations SET status = 'cancelled'"))
    owner_db.commit()
    r = probe(blacksite, env, asset, {"type": "tcp", "ports": [80]})
    assert r.status_code == 429 and r.json()["detail"]["code"] == "budget_exhausted"
    assert {"probe_pending", "budget_exhausted"} <= set(denied_codes(owner_db))


def test_rate_limit(client: TestClient, blacksite: TestClient, env, owner_db: Session) -> None:
    lab_scope(client, env, allowed_ports=[80], max_rps=1, daily_budget=50)
    asset = lab_asset(owner_db, env)
    first = probe(blacksite, env, asset, {"type": "tcp", "ports": [80]}).json()
    owner_db.execute(
        text("UPDATE operations SET status = 'cancelled' WHERE id = :o"), {"o": first["id"]}
    )
    owner_db.commit()
    r = probe(blacksite, env, asset, {"type": "tcp", "ports": [80]})
    assert r.status_code == 429 and r.json()["detail"]["code"] == "rate_limited"


def test_worker_rechecks_bounds_from_the_pinned_scope(
    blacksite: TestClient, env, lab: str, owner_db: Session
) -> None:
    op = probe(blacksite, env, lab, {"type": "tcp", "ports": [80]}, approve=True).json()
    owner_db.execute(
        text("UPDATE operations SET params = jsonb_set(params, '{probe,ports}', '[8080]')")
    )
    owner_db.commit()
    drain(lab_worker({"probe": fake_lab()}))
    detail = blacksite.get(f"/api/workspaces/{env['ws']}/operations/{op['id']}").json()
    assert detail["status"] == "denied" and "8080" in detail["denial_reason"]


def test_tcp_probe_connects_and_closes(
    blacksite: TestClient, env, lab: str, owner_db: Session
) -> None:
    calls: list[tuple[str, int]] = []

    class Conn:
        def close(self) -> None:
            pass

    def connect(ip: str, port: int) -> Any:
        calls.append((ip, port))
        if port == 443:
            raise ConnectionRefusedError
        return Conn()

    tool = fake_lab()
    tool.connect = connect
    op = probe(blacksite, env, lab, {"type": "tcp", "ports": [80, 443]}, approve=True).json()
    drain(lab_worker({"probe": tool}))
    result = owner_db.execute(
        text("SELECT summary FROM evidence WHERE operation_id = :o"), {"o": op["id"]}
    ).scalar_one()["probe"]["result"]
    assert result["ports"] == {"80": "open", "443": "closed"}
    assert calls == [(APP, 80), (APP, 443)]
    assert isinstance(socket.AF_INET, int)


def test_replay_is_a_new_operation_with_a_new_approval(
    blacksite: TestClient, env, lab: str, owner_db: Session
) -> None:
    op = probe(blacksite, env, lab, {"type": "http", "scheme": "http"}, approve=True).json()
    drain(lab_worker({"probe": fake_lab(status=200, body="one")}))
    owner_db.execute(text("UPDATE operations SET created_at = now() - interval '2 seconds'"))
    owner_db.commit()  # outside the one-per-second rate window
    r = blacksite.post(f"/api/workspaces/{env['ws']}/blacksite/probes/{op['id']}/replay", json={})
    assert r.status_code == 201, r.text
    again = r.json()
    assert again["id"] != op["id"] and again["status"] == "awaiting_approval"
    blacksite.post(f"/api/workspaces/{env['ws']}/operations/{again['id']}/approve", json={})
    drain(lab_worker({"probe": fake_lab(status=404, body="two")}))
    cmp = blacksite.get(
        f"/api/workspaces/{env['ws']}/blacksite/probes/compare",
        params={"a": op["id"], "b": again["id"]},
    ).json()
    assert cmp["differences"]["status"] == {"a": 200, "b": 404}
    assert "body_sha256" in cmp["differences"]
    listed = blacksite.get(f"/api/workspaces/{env['ws']}/blacksite/probes").json()
    assert {p["id"] for p in listed} == {op["id"], again["id"]}


def test_state_changing_probe_is_moderate_and_lab_only(
    blacksite: TestClient, env, lab: str
) -> None:
    r = probe(
        blacksite, env, lab, {"type": "http", "scheme": "http", "method": "POST", "body": "{}"},
        confirm_state_change=True,
    )  # fmt: skip
    assert r.status_code == 201 and r.json()["risk_class"] == "moderate"


def test_spec_and_diff_units() -> None:
    assert ProbeSpec(type="tls").target_ports() == [443]
    assert ProbeSpec(type="http", scheme="http").target_ports() == [80]
    assert ProbeSpec(type="http", method="delete").state_changing
    a = {"result": {"status": 200, "headers": [["Server", "a"]]}}
    b = {"result": {"status": 200, "headers": [["Server", "b"]]}}
    assert diff(a, b) == {"headers": {"server": {"a": "a", "b": "b"}}}


def page_probe() -> Probe:
    """A lab web page with typical weaknesses, served over HTTPS (mock transport)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Server": "nginx/1.25.3",
                "Set-Cookie": "sid=v4lue-secret; Path=/",
            },
            text="<html><title>Lab</title></html>",
        )

    def make(excluded: list[Any]) -> SafeHttp:
        return SafeHttp(
            excluded_networks=excluded, only_networks=[LAB], transport=httpx.MockTransport(handler)
        )

    return Probe(make_client=make)


def test_submit_to_black_ice(blacksite: TestClient, env, lab: str, owner_db: Session) -> None:
    # A finding already exists elsewhere in the workspace: numbering must continue from it
    # even though BLACKSITE's role can't see it (migration 0015).
    owner_db.execute(
        text(
            "INSERT INTO findings (workspace_id, project_id, title, severity, confidence, "
            "validation_status, origin, discovery_source) SELECT p.workspace_id, p.id, "
            "'Elsewhere', 'low', 'high', 'unverified', 'human', 'test' FROM projects p "
            "WHERE p.id = :p"
        ),
        {"p": org_project(owner_db, env["ws"], "Real-world client")[1]},
    )
    owner_db.commit()
    op = probe(blacksite, env, lab, {"type": "http", "scheme": "https"}, approve=True).json()
    drain(lab_worker({"probe": page_probe()}))
    url = f"/api/workspaces/{env['ws']}/blacksite/probes/{op['id']}/submit"
    r = blacksite.post(url)
    assert r.status_code == 200, r.text
    got = {f["check_id"]: f for f in r.json()["findings"]}
    assert set(got) == {
        "http.version-disclosure.nginx",
        "http.missing-hsts",
        "http.missing-csp",
        "http.no-framing-protection",
        "http.cookie-not-secure.sid",
        "http.cookie-not-httponly.sid",
    }
    assert {f["validation_status"] for f in got.values()} == {"unverified"}
    assert {f["change"] for f in got.values()} == {"new"}
    numbers = owner_db.execute(text("SELECT number FROM findings ORDER BY number")).scalars().all()
    assert numbers == list(range(1, 8))
    # The cookie's attributes were kept for the rules; its value was not.
    stored = str(
        owner_db.execute(
            text("SELECT summary FROM evidence WHERE operation_id = :o"), {"o": op["id"]}
        ).scalar_one()
    )
    assert "v4lue-secret" not in stored and "sid=<redacted>; Path=/" in stored
    again = blacksite.post(url).json()["findings"]
    assert {f["change"] for f in again} == {"seen_again"}
    assert owner_db.execute(text("SELECT count(*) FROM findings")).scalar_one() == 7
    actions = owner_db.execute(
        text("SELECT count(*) FROM audit_events WHERE action = 'probe.submitted'")
    ).scalar_one()
    assert actions == 2


def test_submit_refusals(client: TestClient, blacksite: TestClient, env, lab: str) -> None:
    pending = probe(blacksite, env, lab, {"type": "tcp", "ports": [80]}).json()
    url = f"/api/workspaces/{env['ws']}/blacksite/probes/{pending['id']}/submit"
    assert blacksite.post(url).json()["detail"]["code"] == "not_finished"
    blacksite.post(f"/api/workspaces/{env['ws']}/operations/{pending['id']}/approve", json={})

    class Conn:
        def close(self) -> None:
            pass

    tool = fake_lab()
    tool.connect = lambda ip, port: Conn()
    drain(lab_worker({"probe": tool}))
    r = blacksite.post(url)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "nothing_to_submit"
    use(client, env["owner"])
    assert client.post(url).status_code == 404  # not on the hosted app
