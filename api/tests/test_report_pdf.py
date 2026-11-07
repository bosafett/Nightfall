# ruff: noqa: F811  (pytest fixtures imported from test_agents)
"""Server-side PDF of a report snapshot."""

import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import Role
from nightfall.reports.pdf import render
from tests.conftest import Factory, audit_actions, use
from tests.test_agents import env  # noqa: F401 - fixture
from tests.test_blackice import _report_with_rule_findings


def test_pdf_is_rendered_from_the_snapshot(
    client: TestClient, env, factory: Factory, owner_db: Session
) -> None:
    report = _report_with_rule_findings(client, env)
    use(client, env["viewer"])
    url = f"/api/workspaces/{env['ws']}/reports/{report}/pdf"
    r = client.get(url)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith('attachment; filename="janus-report-')
    assert r.content.startswith(b"%PDF-") and len(r.content) > 5000
    # Same snapshot, same bytes.
    assert client.get(url).content == r.content
    pdf_sha = hashlib.sha256(r.content).hexdigest()
    row = owner_db.execute(
        text(
            "SELECT data FROM audit_events WHERE action = 'report.exported' "
            "ORDER BY occurred_at DESC LIMIT 1"
        )
    ).scalar_one()
    assert row["format"] == "pdf" and row["pdf_sha256"] == pdf_sha

    # Another workspace can't fetch it.
    other = factory.workspace("Other")
    use(client, factory.sign_in(factory.member(other, Role.OWNER)))
    assert client.get(f"/api/workspaces/{other}/reports/{report}/pdf").status_code == 404

    # A snapshot that fails its integrity check isn't exported.
    owner_db.execute(
        text(
            "UPDATE assessment_snapshots SET content = jsonb_set(content, '{project,name}', "
            "'\"Edited\"') WHERE id = :i"
        ),
        {"i": report},
    )
    owner_db.commit()
    use(client, env["viewer"])
    bad = client.get(url)
    assert bad.status_code == 409 and "SHA-256" in bad.text
    assert audit_actions(owner_db).count("report.exported") == 2


def test_render_handles_unicode_and_empty_sections() -> None:
    content = {
        "generated_at": "2026-11-07T10:00:00+00:00",
        "organization": {"name": "Ærø Søk — 東京"},
        "project": {"name": "Ünïcødé ✓", "assessment_type": "external"},
        "executive_summary": ["Nothing yet."],
        "scope": None,
        "findings": [],
        "assets": [],
        "attack_paths": [],
        "limitations": ["Early."],
    }
    a = render(content, report_id="r1", sha256="0" * 64, taken_by="Zoë")
    assert a.startswith(b"%PDF-")
    assert a == render(content, report_id="r1", sha256="0" * 64, taken_by="Zoë")
