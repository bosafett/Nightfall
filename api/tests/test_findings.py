from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import from_http
from nightfall.core.db.models import Role
from tests.conftest import Factory, audit_actions, use
from tests.phase3_helpers import authorize_scope, make_worker, org_project

NOW = datetime(2026, 11, 5, tzinfo=UTC)


# --- Rules (pure) ------------------------------------------------------------------


def test_rules_version_disclosure_only_for_server_stated_versions() -> None:
    techs = [
        {
            "name": "nginx",
            "version": "1.25.3",
            "confidence": "high",
            "evidence": "server: nginx/1.25.3",
        },
        {"name": "WordPress", "version": "6.4.2", "confidence": "medium", "evidence": "meta"},
    ]
    checks = {d.check_id for d in from_http([{"attempts": []}], techs, NOW)}
    assert checks == {"http.version-disclosure.nginx"}


def test_rules_tls_and_https() -> None:
    https_bad = [
        {
            "attempts": [
                {
                    "url": "https://a.example/",
                    "verified_tls": True,
                    "error": "SSLError: certificate verify failed",
                },
                {"url": "https://a.example/", "verified_tls": False, "status": 200},
            ],
            "tls": {"not_after": (NOW + timedelta(days=10)).isoformat()},
        }
    ]
    checks = {d.check_id for d in from_http(https_bad, [], NOW)}
    assert checks == {"tls.certificate-not-trusted", "tls.certificate-expiring"}

    expired = [
        {
            "attempts": [{"url": "https://a.example/", "verified_tls": True, "status": 200}],
            "tls": {"not_after": (NOW - timedelta(days=1)).isoformat()},
        }
    ]
    assert {d.check_id for d in from_http(expired, [], NOW)} == {"tls.certificate-expired"}

    plain = [
        {
            "attempts": [
                {
                    "url": "https://a.example/",
                    "verified_tls": True,
                    "error": "ConnectError: refused",
                },
                {"url": "http://a.example/", "verified_tls": False, "status": 200},
            ]
        }
    ]
    assert {d.check_id for d in from_http(plain, [], NOW)} == {"http.no-https"}
    assert from_http([], [], NOW) == []


# --- Rule-made findings via the worker ----------------------------------------------


@pytest.fixture
def env(client: TestClient, factory: Factory, owner_db: Session):
    ws = factory.workspace()
    oid, pid = org_project(owner_db, ws)
    owner = factory.sign_in(factory.member(ws, Role.OWNER))
    use(client, owner)
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    return {
        "ws": ws,
        "pid": pid,
        "oid": oid,
        "owner": owner,
        "analyst": factory.sign_in(factory.member(ws, Role.ANALYST)),
        "viewer": factory.sign_in(factory.member(ws, Role.VIEWER)),
        "operator": factory.sign_in(factory.member(ws, Role.OPERATOR)),
    }


def run_http(client, env) -> str:
    use(client, env["analyst"])
    op = client.post(
        f"/api/workspaces/{env['ws']}/projects/{env['pid']}/collections",
        json={"tool": "http", "target": "www.example.com"},
    ).json()["id"]
    use(client, env["operator"])
    client.post(f"/api/workspaces/{env['ws']}/operations/{op}/approve", json={"reason": "ok"})
    make_worker().run_once()
    return op


def test_worker_creates_unverified_findings_linked_to_evidence(client, env, owner_db) -> None:
    op = run_http(client, env)
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    findings = client.get(f"{base}/findings").json()
    titles = {f["title"] for f in findings}
    # Fixture: nginx/1.25.3 and PHP/8.2.12 stated in headers.
    assert titles == {
        "nginx version disclosed in HTTP headers",
        "PHP version disclosed in HTTP headers",
    }
    assert all(
        f["validation_status"] == "unverified" and f["origin"] == "deterministic_check"
        for f in findings
    )
    assert [f["ref"] for f in sorted(findings, key=lambda f: f["number"])] == ["NF-0001", "NF-0002"]
    detail = client.get(f"{base}/findings/{findings[0]['id']}").json()
    assert len(detail["evidence"]) == 1 and detail["evidence"][0]["linked_by"].startswith("rule:R1")
    assert detail["rule_id"].startswith("R1-version-disclosure@findings/")
    op_detail = client.get(f"{base}/operations/{op}").json()
    assert {c["change"] for c in op_detail["result_summary"]["findings"]} == {"new"}


def test_reobservation_updates_not_duplicates_and_reopens_remediated(client, env, owner_db) -> None:
    run_http(client, env)
    base = f"/api/workspaces/{env['ws']}"
    use(client, env["analyst"])
    first = client.get(f"{base}/findings").json()
    nginx = next(f for f in first if f["title"].startswith("nginx"))
    php = next(f for f in first if f["title"].startswith("PHP"))
    client.post(
        f"{base}/findings/{nginx['id']}/status",
        json={"status": "remediated", "note": "Header removed"},
    )
    client.post(
        f"{base}/findings/{php['id']}/status",
        json={"status": "false_positive", "note": "Proxy header"},
    )

    run_http(client, env)
    use(client, env["analyst"])
    again = client.get(f"{base}/findings").json()
    assert len(again) == 2
    n = client.get(f"{base}/findings/{nginx['id']}").json()
    assert n["validation_status"] == "unverified" and "Observed again" in n["status_note"]
    assert len(n["evidence"]) == 2  # both observations linked
    p = client.get(f"{base}/findings/{php['id']}").json()
    assert p["validation_status"] == "false_positive"  # a person's dismissal sticks


# --- Manual findings, status decisions, permissions -----------------------------------


def make_finding(client, env, **kw):
    body = {
        "project_id": str(env["pid"]),
        "title": "Admin panel exposed",
        "severity": "high",
        "confidence": "medium",
        **kw,
    }
    return client.post(f"/api/workspaces/{env['ws']}/findings", json=body)


def test_status_rules(client, env, owner_db) -> None:
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    assert make_finding(client, env, validation_status="validated").status_code == 422
    f = make_finding(client, env, validation_status="hypothesis").json()
    assert f["validation_status"] == "hypothesis" and f["origin"] == "human"
    r = client.post(f"{base}/findings/{f['id']}/status", json={"status": "validated", "note": ""})
    assert r.json()["detail"]["code"] == "note_required"
    r = client.post(
        f"{base}/findings/{f['id']}/status", json={"status": "validated", "note": "Confirmed"}
    )
    assert r.json()["detail"]["code"] == "evidence_required"
    r = client.post(
        f"{base}/findings/{f['id']}/status", json={"status": "false_positive", "note": "Lab copy"}
    )
    assert r.status_code == 200
    assert r.json()["validated_by"] == "Analyst" and r.json()["validated_at"]
    back = client.post(f"{base}/findings/{f['id']}/status", json={"status": "unverified"}).json()
    assert back["validated_by"] is None
    assert "finding.status_changed" in audit_actions(owner_db)


def test_database_refuses_unattributed_verification(env, owner_db) -> None:
    with pytest.raises(IntegrityError):
        owner_db.execute(
            text(
                "INSERT INTO findings (workspace_id, project_id, title, severity, confidence, "
                "validation_status, origin) VALUES (:w, :p, 'x', 'low', 'low', 'validated', "
                "'deterministic_check')"
            ),
            {"w": env["ws"], "p": env["pid"]},
        )
    owner_db.rollback()


def test_viewer_cannot_edit_or_decide(client, env) -> None:
    use(client, env["analyst"])
    f = make_finding(client, env).json()
    use(client, env["viewer"])
    base = f"/api/workspaces/{env['ws']}"
    assert make_finding(client, env).status_code == 403
    assert client.patch(f"{base}/findings/{f['id']}", json={"severity": "low"}).status_code == 403
    assert (
        client.post(
            f"{base}/findings/{f['id']}/status", json={"status": "false_positive", "note": "x"}
        ).status_code
        == 403
    )
    assert client.get(f"{base}/findings/{f['id']}").status_code == 200


def test_filters_and_sorting(client, env) -> None:
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    for sev in ("low", "critical", "medium"):
        make_finding(client, env, title=f"{sev} thing", severity=sev)
    by_sev = [f["severity"] for f in client.get(f"{base}/findings").json()]
    assert by_sev == ["critical", "medium", "low"]
    only = client.get(f"{base}/findings", params={"severity": ["critical", "low"]}).json()
    assert {f["severity"] for f in only} == {"critical", "low"}
    assert client.get(f"{base}/findings", params={"status": ["validated"]}).json() == []
    assert (
        len(client.get(f"{base}/findings", params={"organization_id": str(env["oid"])}).json()) == 3
    )


def test_asset_must_belong_to_project_org(client, env, factory, owner_db) -> None:
    other_org, _ = org_project(owner_db, env["ws"], org="Other")
    aid = owner_db.execute(
        text(
            "INSERT INTO assets (workspace_id, organization_id, kind, value, source) "
            "VALUES (:w, :o, 'domain', 'other.example', 'manual') RETURNING id"
        ),
        {"w": env["ws"], "o": other_org},
    ).scalar_one()
    owner_db.commit()
    use(client, env["analyst"])
    r = make_finding(client, env, asset_id=str(aid))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "asset_mismatch"


def test_manual_evidence_links_and_validation(client, env) -> None:
    run_http(client, env)
    use(client, env["analyst"])
    base = f"/api/workspaces/{env['ws']}"
    f = make_finding(client, env).json()
    ev = client.get(f"{base}/projects/{env['pid']}/evidence").json()[0]
    linked = client.post(
        f"{base}/findings/{f['id']}/evidence", json={"evidence_id": ev["id"], "note": "see headers"}
    )
    assert linked.status_code == 200 and linked.json()["evidence"][0]["linked_by"].startswith(
        "user:"
    )
    assert (
        client.post(
            f"{base}/findings/{f['id']}/evidence", json={"evidence_id": ev["id"]}
        ).status_code
        == 409
    )
    v = client.post(
        f"{base}/findings/{f['id']}/status", json={"status": "validated", "note": "Reproduced"}
    )
    assert v.json()["validation_status"] == "validated"
    assert (
        client.delete(f"{base}/findings/{f['id']}/evidence/{ev['id']}").json()["detail"]["code"]
        == "validated"
    )
    rule_made = next(
        x for x in client.get(f"{base}/findings").json() if x["origin"] == "deterministic_check"
    )
    rule_ev = client.get(f"{base}/findings/{rule_made['id']}").json()["evidence"][0]["id"]
    assert (
        client.delete(f"{base}/findings/{rule_made['id']}/evidence/{rule_ev}").json()["detail"][
            "code"
        ]
        == "rule_link"
    )


def test_findings_are_tenant_isolated(client, env, factory) -> None:
    use(client, env["analyst"])
    f = make_finding(client, env).json()
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.ANALYST)))
    assert client.get(f"/api/workspaces/{other}/findings/{f['id']}").status_code == 404
    assert client.get(f"/api/workspaces/{other}/findings").json() == []
    r = client.post(
        f"/api/workspaces/{other}/findings",
        json={"project_id": str(env["pid"]), "title": "x", "severity": "low", "confidence": "low"},
    )
    assert r.status_code == 404
