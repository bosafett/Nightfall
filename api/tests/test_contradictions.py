# ruff: noqa: F811  (pytest fixtures imported from test_agents)
# mypy: disable-error-code="no-untyped-def"
"""BLACK ICE contradiction flags: a finding's status disagrees with newer evidence."""

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blackice.contradictions import retests
from nightfall.core.db.models import Role
from tests.conftest import use
from tests.phase3_helpers import make_worker
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_blackice import collect


def _run_http(client: TestClient, env) -> None:
    op = collect(client, env, tool="http", target="www.example.com")
    use(client, env["operator"])
    r = client.post(f"/api/workspaces/{env['ws']}/operations/{op}/approve", json={"reason": "t"})
    assert r.status_code == 200, r.text
    make_worker().run_once()


def _newer_copy(owner_db: Session, finding_id: str, summary: str, simulated: bool) -> None:
    """Re-check of the finding's asset, an hour after its latest evidence, with `summary`."""
    owner_db.execute(
        text(
            "INSERT INTO evidence (workspace_id, project_id, asset_id, kind, source, "
            "collection_method, collected_at, confidence, tool_name, tool_version, "
            "content_sha256, content_type, size_bytes, summary, is_simulation) "
            "SELECT e.workspace_id, e.project_id, e.asset_id, e.kind, e.source, "
            "e.collection_method, e.collected_at + interval '1 hour', e.confidence, e.tool_name, "
            "e.tool_version, sha256(e.content_sha256), e.content_type, e.size_bytes, "
            "CAST(:s AS jsonb), :sim FROM evidence e JOIN finding_evidence fe "
            "ON fe.evidence_id = e.id WHERE fe.finding_id = :f "
            "ORDER BY e.collected_at DESC LIMIT 1"
        ),
        {"f": finding_id, "s": summary, "sim": simulated},
    )
    owner_db.commit()


def test_contradictions_are_flagged_and_change_nothing(
    client: TestClient, env, owner_db, factory
) -> None:
    ws = env["ws"]
    _run_http(client, env)
    use(client, env["viewer"])
    findings = client.get(f"/api/workspaces/{ws}/findings").json()
    assert len(findings) >= 2, findings
    assert client.get(f"/api/workspaces/{ws}/contradictions").json() == []

    # A false positive observed again is flagged; the others were reproduced, so they aren't.
    fp, other = findings[0]["id"], findings[1]["id"]
    use(client, env["owner"])
    r = client.post(
        f"/api/workspaces/{ws}/findings/{fp}/status",
        json={"status": "false_positive", "note": "test"},
    )
    assert r.status_code == 200, r.text
    _run_http(client, env)
    use(client, env["viewer"])
    flags = client.get(f"/api/workspaces/{ws}/contradictions").json()
    assert [(f["finding_id"], f["kind"]) for f in flags] == [(fp, "seen_after_false_positive")]
    detail = client.get(f"/api/workspaces/{ws}/findings/{fp}").json()
    assert detail["validation_status"] == "false_positive"
    assert detail["contradiction"]["kind"] == "seen_after_false_positive"

    # Newer lab evidence never contradicts real evidence.
    empty = '{"http": [], "technologies": []}'
    _newer_copy(owner_db, other, empty, simulated=True)
    assert len(client.get(f"/api/workspaces/{ws}/contradictions").json()) == 1

    # A newer real re-check that no longer shows the conditions flags every open finding.
    _newer_copy(owner_db, other, empty, simulated=False)
    flags = {f["finding_id"]: f for f in client.get(f"/api/workspaces/{ws}/contradictions").json()}
    assert flags[fp]["kind"] == "seen_after_false_positive"
    assert flags[other]["kind"] == "not_reproduced"
    assert flags[other]["ref"].startswith("NF-")
    assert set(flags) == {f["id"] for f in findings}
    detail = client.get(f"/api/workspaces/{ws}/findings/{other}").json()
    assert detail["contradiction"]["kind"] == "not_reproduced"
    assert detail["validation_status"] == "unverified"  # nothing changed the finding

    # Project filter and workspace isolation.
    assert client.get(
        f"/api/workspaces/{ws}/contradictions", params={"project_id": env["pid"]}
    ).json()
    other_ws = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other_ws, Role.OWNER)))
    assert client.get(f"/api/workspaces/{other_ws}/contradictions").json() == []
    assert client.get(f"/api/workspaces/{other_ws}/findings/{other}").status_code == 404


def test_header_checks_need_a_comparable_response() -> None:
    no_https = {"posture": {"headers": {"http": {"status": 200}}}}
    with_https = {"posture": {"headers": {"https": {"status": 200, "cookies": [{"name": "sid"}]}}}}
    assert not retests("http.missing-hsts", no_https)
    assert retests("http.missing-hsts", with_https)
    assert retests("http.cookie-not-secure.sid", with_https)
    assert not retests("http.cookie-not-secure.other", with_https)
    assert not retests("http.no-https-redirect", with_https)
    assert retests("tls.certificate-expired", {})
