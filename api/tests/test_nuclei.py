import datetime as dt
import functools
import http.server
import json
import os
import shutil
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.blackice.finding_rules import from_nuclei
from nightfall.core.db.models import Role, ScopeEntryKind, ScopeStatus
from nightfall.recon.collectors import NucleiScan, RunContext, collectors
from nightfall.recon.safe_http import Refused, SafeHttp
from nightfall.scope.engine import Entry, ScopeSnapshot
from nightfall.scope.normalize import NormalizationError
from nightfall.tools import nuclei
from nightfall.tools.runner import Sandbox
from tests.conftest import Factory, use
from tests.phase3_helpers import authorize_scope, make_worker, org_project

NUCLEI_BIN = os.environ.get("NIGHTFALL_TEST_NUCLEI_BIN")
SCOPE = ScopeSnapshot(
    status=ScopeStatus.ACTIVE,
    valid_from=None,
    valid_until=None,
    targets=(Entry(ScopeEntryKind.DOMAIN_TREE, "example.com"),),
    exclusions=(Entry(ScopeEntryKind.HOST, "blocked.example.com"),),
)


def test_templates_match_their_pinned_hashes() -> None:
    assert len(nuclei.template_paths()) == len(nuclei.CATALOG)
    assert {p.stem for p in nuclei.TEMPLATE_DIR.glob("*.yaml")} == set(nuclei.CATALOG)


def test_tampered_template_refuses_to_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shutil.copytree(nuclei.TEMPLATE_DIR, tmp_path / "t")
    path = tmp_path / "t" / "nf-directory-listing.yaml"
    path.write_text(path.read_text().replace("GET", "POST"))
    monkeypatch.setattr(nuclei, "TEMPLATE_DIR", tmp_path / "t")
    with pytest.raises(nuclei.TemplateTampered):
        nuclei.build_invocation("/bin/nuclei", "www.example.com", "http://p")


def test_templates_are_get_only_http_without_payloads() -> None:
    for path in nuclei.TEMPLATE_DIR.glob("*.yaml"):
        body = path.read_text()
        assert "method: GET" in body and "\nhttp:\n" in body
        for banned in ("payloads", "fuzzing", "interactsh", "code:", "headless", "redirects"):
            assert banned not in body, (path.name, banned)


def test_invocation_has_the_safety_flags_and_no_shell() -> None:
    argv = nuclei.build_invocation("/opt/nuclei", "WWW.Example.com.", "http://nf:t@127.0.0.1:1")
    assert argv[0] == "/opt/nuclei"
    for flag in ("-ni", "-duc", "-dr", "-or", "-ot"):
        assert flag in argv
    assert argv[argv.index("-pt") + 1] == "http"
    assert "https://www.example.com" in argv and "http://www.example.com" in argv
    assert argv.count("-t") == len(nuclei.CATALOG)
    assert nuclei.redact(argv, "http://nf:t@127.0.0.1:1").count("http://nf:REDACTED@proxy") == 1


@pytest.mark.parametrize("target", ["example.com -t /etc", "a;b", "http://x", "", "x/../y"])
def test_targets_that_are_not_hosts_never_reach_argv(target: str) -> None:
    with pytest.raises(NormalizationError):
        nuclei.build_invocation("/opt/nuclei", target, "http://p")


def test_parse_keeps_only_catalog_matches_for_the_target() -> None:
    lines = [
        {"template-id": "nf-missing-hsts", "matched-at": "https://www.example.com/"},
        {"template-id": "nf-missing-hsts", "matched-at": "https://www.example.com/"},  # dup
        {"template-id": "cve-2099-0001", "matched-at": "https://www.example.com/"},
        {"template-id": "nf-git-head-exposed", "matched-at": "https://evil.test/.git/HEAD"},
        {"template-id": "nf-directory-listing", "matched-at": "javascript:alert(1)"},
        {"template-id": ["x"], "matched-at": 1},
    ]
    raw = "\n".join(json.dumps(x) for x in lines).encode() + b"\nnot json\n"
    matches, rejected = nuclei.parse(raw, "www.example.com")
    assert matches == [
        {
            "template_id": "nf-missing-hsts",
            "check_id": "http.missing-hsts",
            "title": nuclei.CATALOG["nf-missing-hsts"].title,
            "matched_at": "https://www.example.com/",
        }
    ]
    assert rejected == 5


def test_finding_wording_comes_from_the_catalog() -> None:
    drafts = from_nuclei(
        [
            {"template_id": "nf-git-head-exposed", "matched_at": "https://a.example.com/.git/HEAD"},
            {"template_id": "unknown", "matched_at": "x"},
        ]
    )
    assert [d.check_id for d in drafts] == ["web.git-metadata-exposed"]
    assert drafts[0].title == nuclei.CATALOG["nf-git-head-exposed"].title


def test_live_scan_refuses_without_the_network_lock() -> None:
    scan = NucleiScan("/opt/nuclei", Sandbox(mode="none"))
    with pytest.raises(Refused, match="sandbox"):
        scan.run("www.example.com", RunContext(scope=SCOPE))


def test_unavailable_binary_fails_clearly() -> None:
    with pytest.raises(RuntimeError, match="isn't installed"):
        NucleiScan(None, Sandbox()).run("www.example.com", RunContext(scope=SCOPE))


# --- end to end with the fixture collector ------------------------------------------


def test_nuclei_needs_approval_and_creates_unverified_findings(
    client: TestClient, factory: Factory, owner_db: Session
) -> None:
    ws = factory.workspace()
    _, pid = org_project(owner_db, ws)
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    authorize_scope(client, ws, pid, [("domain_tree", "example.com")])
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    r = client.post(
        f"/api/workspaces/{ws}/projects/{pid}/collections",
        json={"tool": "nuclei", "target": "www.example.com"},
    )
    assert r.status_code == 202 and r.json()["status"] == "awaiting_approval"
    op_id = r.json()["id"]
    assert make_worker().run_once() is False

    use(client, factory.sign_in(factory.member(ws, Role.OPERATOR)))
    ok = client.post(f"/api/workspaces/{ws}/operations/{op_id}/approve", json={"reason": "SOW-42"})
    assert ok.status_code == 200
    make_worker().run_once()
    done = client.get(f"/api/workspaces/{ws}/operations/{op_id}").json()
    assert done["status"] == "succeeded", done
    rows = owner_db.execute(
        text(
            "SELECT check_id, validation_status, rule_id FROM findings "
            "WHERE project_id = :p ORDER BY check_id"
        ),
        {"p": pid},
    ).all()
    assert [r.check_id for r in rows] == ["http.missing-hsts", "web.git-metadata-exposed"]
    assert all(r.validation_status == "unverified" for r in rows)
    assert all(r.rule_id.startswith("R6-curated-check:") for r in rows)
    tool = owner_db.execute(
        text("SELECT tool_name FROM evidence WHERE operation_id = :o"), {"o": op_id}
    ).scalar_one()
    assert tool == "fixture-nuclei"


def test_tool_list_includes_nuclei_as_low_risk(client: TestClient, factory: Factory) -> None:
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.ANALYST)))
    tools = {t["key"]: t for t in client.get(f"/api/workspaces/{ws}/recon/tools").json()}
    assert tools["nuclei"]["risk_class"] == "low"
    assert set(collectors("fixture")) == set(tools)


# --- the real binary, through the real proxy (skipped unless a binary is provided) ---


@pytest.fixture
def site(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / "index.html").write_text("<html><title>Index of /</title></html>")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


@pytest.mark.skipif(not NUCLEI_BIN, reason="set NIGHTFALL_TEST_NUCLEI_BIN to run")
def test_real_nuclei_through_the_proxy(site: int, monkeypatch: pytest.MonkeyPatch) -> None:
    # The test site can't listen on port 80, so the plain-HTTP URL is pointed at its port
    # and the proxy policy allows that port. Everything else is the production path.
    real_build = nuclei.build_invocation

    def build(binary: str, target: str, proxy_url: str) -> list[str]:
        argv = real_build(binary, target, proxy_url)
        return [a.replace(f"http://{target}", f"http://{target}:{site}") for a in argv]

    monkeypatch.setattr(nuclei, "build_invocation", build)
    scan = NucleiScan(
        NUCLEI_BIN,
        Sandbox(mode="none"),
        require_lock=False,  # tests only: isolation rests on the proxy here
        make_pinner=lambda nets: SafeHttp(resolver=lambda h: ["127.0.0.1"], allow_private=True),
        clock=lambda: dt.datetime.now(dt.UTC),
        timeout=120,
        ports=frozenset({80, 443, site}),
    )
    result = scan.run("www.example.com", RunContext(scope=SCOPE))
    ids = {m["template_id"] for m in result.matches}
    assert ids == {"nf-git-head-exposed", "nf-directory-listing"}
    raw = json.loads(result.raw)
    assert raw["egress"], "nuclei sent nothing through the proxy"
    assert all(e["host"] == "www.example.com" for e in raw["egress"])
    assert "REDACTED" in " ".join(raw["argv"])
    assert result.tool_version.startswith("nuclei v3.")
