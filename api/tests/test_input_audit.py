# ruff: noqa: F811  (pytest fixtures imported from other test modules)
"""Profile B playbook 6: Safe Injection Surface Assessment, against a fake site."""

import html
from itertools import count
from urllib.parse import parse_qs

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import from_posture
from nightfall.blackops.catalog import PLAYBOOKS
from nightfall.core.clock import utcnow
from nightfall.recon.collectors import RunContext
from nightfall.recon.input_audit import WRAP, InputAudit
from tests.phase3_helpers import make_worker
from tests.test_auth_audit import client_for, live_gates  # noqa: F401 - fixture
from tests.test_ownership import FakeProbes, env, probes  # noqa: F401 - fixtures
from tests.test_profile_b import TARGET, W, prove

HOME = (
    b'<a href="/search?q=hello">s</a> <a href="/about">a</a> <a href="https://evil.test/x">x</a>'
    b'<form action="/search"><input name="q"></form>'
    b'<form method="post" action="/contact"><input name="name"><input name="msg"></form>'
    b'<form method="post" action="/find"><input type="search" name="term"></form>'
)


def site(seen: list[tuple[str, str, str]]):  # type: ignore[no-untyped-def]
    def handler(req: httpx.Request) -> httpx.Response:
        q = {k: v[0] for k, v in parse_qs(req.url.query.decode()).items()}
        seen.append((req.method, req.url.host, req.url.path))
        if req.url.path == "/":
            return httpx.Response(200, content=HOME)
        if req.url.path == "/search":  # reflects without encoding
            return httpx.Response(200, content=f"Results for {q.get('q', '')}".encode())
        if req.url.path == "/about":
            return httpx.Response(200, content=b'<a href="/item?id=1">item</a>')
        if req.url.path == "/item":
            if "'" in q.get("id", ""):
                return httpx.Response(500, content=b"You have an error in your SQL syntax near")
            return httpx.Response(200, content=b"item")
        if req.url.path == "/find" and req.method == "POST":  # encodes: fine
            term = parse_qs(req.content.decode()).get("term", [""])[0]
            return httpx.Response(200, content=f"Found {html.escape(term)}".encode())
        if req.url.path == "/contact":
            raise AssertionError("a POST form that wasn't marked safe was submitted")
        return httpx.Response(404)

    return handler


def audit(safe_forms: list[str]):  # type: ignore[no-untyped-def]
    seen: list[tuple[str, str, str]] = []
    n = count()
    res = InputAudit(
        make_client=lambda nets: client_for(site(seen)),
        sleep=lambda s: None,
        markers=lambda: f"jnsmark{next(n):03d}",
    ).run(TARGET, RunContext(params={"safe_forms": safe_forms}))
    return res, seen


def test_marks_reflection_and_error_disclosure() -> None:
    res, seen = audit(["/find"])
    r = res.posture["inputs"]
    assert r["stopped"] is None and len(r["pages"]) <= 20
    checks = {d.check_id for d in from_posture(res.posture, utcnow())}
    assert checks == {
        "input.reflected-unencoded./search.q",
        "input.error-disclosure./item.sql-error",
    }
    find = next(e for e in r["inputs"] if e.get("path") == "/find" and "name" in e)
    assert find["reflected"] and not find["reflected_unencoded"]  # encoded: not reported
    contact = next(e for e in r["inputs"] if e.get("path") == "/contact")
    assert contact["skipped"] == "POST form not marked safe"
    # POST only to the safe form; the other host was never contacted.
    assert {p for m, _, p in seen if m == "POST"} == {"/find"}
    assert all(h != "evil.test" for _, h, _ in seen)
    assert r["requests"] <= 200
    # The only thing sent in inputs is the marker corpus.
    assert r["corpus"] == "janus-markers/1" and "<script" not in res.raw.decode().lower()
    assert WRAP == "'\"<jns>"  # the corpus is this one inert suffix after a unique marker


def test_without_safe_forms_no_post_at_all() -> None:
    res, seen = audit([])
    assert all(m == "GET" for m, _, _ in seen)
    skipped = {e["path"] for e in res.posture["inputs"]["inputs"] if e.get("skipped")}
    assert skipped == {"/contact", "/find"}


def test_profile_b_input_run_end_to_end(
    client: TestClient, env: dict, owner_db: Session, probes: FakeProbes, live_gates: None
) -> None:
    p = PLAYBOOKS["safe-injection-surface-assessment"]
    prove(client, env, probes)
    url = f"{W(env)}/blackops/projects/{env['pid']}"
    pre = client.post(
        f"{url}/preflight",
        json={"playbook_id": p.id, "target": TARGET, "safe_forms": ["http://x/find"]},
    ).json()
    assert {c["key"]: c["status"] for c in pre["checks"]}["safe_forms"] == "fail"
    body = {
        "playbook_id": p.id, "target": TARGET, "safe_forms": ["/find"],
        "version": p.version, "definition_sha256": p.sha256,
    }  # fmt: skip
    r = client.post(f"{url}/runs", json=body)
    assert r.status_code == 201, r.text
    assert owner_db.execute(text("SELECT params FROM operations")).scalar_one()["safe_forms"] == [
        "/find"
    ]
    owner_db.execute(text("UPDATE workspaces SET approval_policy = 'single_operator'"))
    owner_db.commit()
    approve = client.post(f"{W(env)}/blackops/runs/{r.json()['id']}/approve", json={"reason": "ok"})
    assert approve.status_code == 200
    seen: list[tuple[str, str, str]] = []
    worker = make_worker(
        {
            "input-audit": InputAudit(
                make_client=lambda n: client_for(site(seen)), sleep=lambda s: None
            )
        }
    )
    while worker.run_once():
        pass
    assert owner_db.execute(text("SELECT status FROM operations")).scalar_one() == "succeeded"
    checks = set(owner_db.execute(text("SELECT check_id FROM findings")).scalars())
    assert checks == {
        "input.reflected-unencoded./search.q",
        "input.error-disclosure./item.sql-error",
    }
    assert set(owner_db.execute(text("SELECT validation_status FROM findings")).scalars()) == {
        "unverified"
    }
