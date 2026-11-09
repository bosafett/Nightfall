"""Lab tool pack 1: the reviewed, pinned Nuclei template subset (lab only, moderate risk)."""

import dataclasses
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nightfall.blackice.finding_rules import from_nuclei
from nightfall.blackops.catalog import PLAYBOOKS, Profile
from nightfall.config import get_settings
from nightfall.core.db.models import RiskClass, Role, Severity
from nightfall.recon.collectors import LAB_TOOLS, PACK_TOOLS, TOOLS, NucleiPackScan, RunContext
from nightfall.recon.safe_http import Refused
from nightfall.tools.nuclei import TemplateTampered, pack1
from nightfall.tools.runner import Sandbox
from tests.conftest import Factory, use

ROOT = Path(__file__).resolve().parents[2]


def test_manifest_rules_and_groups() -> None:
    m = pack1.manifest()
    assert m["release"] == "v10.5.1" and re.fullmatch(r"[0-9a-f]{40}", m["commit"])
    ts = m["templates"]
    assert len(ts) == m["counts"]["kept"] == len(pack1.templates())  # ids are unique
    for t in ts:
        assert re.fullmatch(r"[0-9a-f]{64}", t["sha256"]), t
        assert t["path"].startswith("http/") and ".." not in t["path"], t
        assert t["severity"] in {s.value for s in Severity}
    sizes = {g: len(pack1.group_templates(g)) for g in pack1.GROUPS}
    assert sum(sizes.values()) == len(ts)
    assert all(0 < n <= pack1.MAX_TEMPLATES for n in sizes.values())
    # The playbook's step text states each group's size (what the approver sees).
    p = PLAYBOOKS["known-weakness-scan-lab"]
    for step in p.steps:
        n = sizes[pack1.group_of(step.tool)]
        assert f"{n:,}" in step.purpose, (step.tool, n)
    logins = sum(1 for t in pack1.group_templates("config") if t.category == "default-login")
    assert f"{logins} default-login" in p.steps[1].purpose
    assert p.profiles == (Profile.LAB,) and p.risk_class is RiskClass.MODERATE


def test_import_rules_drop_what_the_design_excludes(tmp_path: Path) -> None:
    pytest.importorskip("yaml")  # the import script is a development tool
    spec = importlib.util.spec_from_file_location(
        "imp", ROOT / "infra" / "tools" / "import_nuclei_pack.py"
    )
    assert spec and spec.loader
    imp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imp)
    import yaml

    def why(body: str) -> str | None:
        return imp.reason_to_drop(yaml.safe_load(body), body)

    ok = "id: x\ninfo:\n  name: X\n  severity: high\n  tags: cve,apache\nhttp:\n  - method: GET\n"
    assert why(ok) is None
    assert why(ok.replace("cve,apache", "cve,dos")) == "dropped tag"
    assert why(ok.replace("cve,apache", "cve,intrusive")) == "dropped tag"
    assert why(ok.replace("cve,apache", "panel")) == "category"
    assert why(ok.replace("http:", "tcp:")) == "not HTTP"
    assert why(ok + "code:\n  - engine: [sh]\n") == "other protocol"
    assert why(ok + "flow: http(1)\n") == "other protocol"
    assert why(ok + "self-contained: true\n") == "self-contained"
    assert why(ok.replace("method: GET", "method: DELETE")) == "fuzzing or method"
    assert why(ok + "    path: ['{{BaseURL}}/{{interactsh-url}}']\n") == "out-of-band or random"
    assert why(ok + "    body: '{{rand_text_alpha(8)}}'\n") == "out-of-band or random"
    assert why(ok.replace("severity: high", "severity: unknown")) == "unknown severity"
    # rules/2: only GET, HEAD, POST and OPTIONS, also in raw requests (after annotations).
    assert why(ok.replace("method: GET", "method: PURGE")) == "method"
    raw = "id: x\ninfo:\n  name: X\n  severity: high\n  tags: cve\nhttp:\n  - raw:\n      - |\n"
    assert why(raw + "        @timeout 10s\n        GET /status HTTP/1.1\n") is None
    assert why(raw + "        DEBUG /x.aspx HTTP/1.1\n") == "method"
    # rules/2: no request naming a state-changing action, structured or raw.
    assert why(ok + "    path: ['{{BaseURL}}/wp-admin/admin-post.php?do_reset_wordpress=1']\n") == (
        "state-changing request"
    )
    assert why(raw + "        POST /wp-json/x/v1/purge-error-logs HTTP/1.1\n") == (
        "state-changing request"
    )
    assert why(ok + "    path: ['{{BaseURL}}/status']\n") is None
    # rules/2: a POST naming a write is dropped (a GET isn't); nested random values are caught.
    post = raw + "        POST /wp-json/rankmath/v1/updateRedirection HTTP/1.1\n"
    assert why(post) == "state-changing request"
    assert why(ok + "    path: ['{{BaseURL}}/settings/update']\n") is None
    body = raw + "        GET / HTTP/1.1\n\n        x={{to_lower(rand_text_alpha(5))}}\n"
    assert why(body) == "out-of-band or random"


def test_registered_as_moderate_lab_only_and_never_a_single_collection(
    client: TestClient, factory: Factory
) -> None:
    for tool in PACK_TOOLS:
        assert TOOLS[tool][1] is RiskClass.MODERATE and tool in LAB_TOOLS
    ws = factory.workspace()
    use(client, factory.sign_in(factory.member(ws, Role.OWNER)))
    listed = {t["key"] for t in client.get(f"/api/workspaces/{ws}/recon/tools").json()}
    assert not listed & set(PACK_TOOLS)


def _fake_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "pack"
    entries = {}
    for i, cat in enumerate(("tech", "tech", "cve")):
        rel = f"http/t{i}.yaml"
        body = f"id: t{i}\n".encode()
        (root / "http").mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(body)
        entries[f"t{i}"] = pack1.Template(
            f"t{i}", rel, hashlib.sha256(body).hexdigest(), f"Template {i}", Severity.HIGH, cat,
            ("CVE-2024-0001",) if cat == "cve" else (),
        )  # fmt: skip
    monkeypatch.setattr(pack1, "templates", lambda: entries)
    return root


def test_pack_runs_only_with_review_and_verified_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = get_settings()
    assert pack1.unavailable_reason(dataclasses.replace(s, blacksite_enabled=False))
    on = dataclasses.replace(s, blacksite_enabled=True, lab_pack1_review_ref=None)
    assert "no recorded review" in (pack1.unavailable_reason(on) or "")
    assert pack1.unavailable_reason(dataclasses.replace(on, lab_pack1_review_ref="R-1")) is None

    root = _fake_pack(tmp_path, monkeypatch)
    paths = pack1.verified_paths(root, "tech")
    assert [Path(p).name for p in paths] == ["t0.yaml", "t1.yaml"]
    (root / "http" / "t1.yaml").write_text("id: t1\nhttp: [{method: DELETE}]\n")
    with pytest.raises(TemplateTampered, match="t1"):
        pack1.verified_paths(root, "tech")
    (root / "http" / "t2.yaml").unlink()
    with pytest.raises(TemplateTampered, match="missing"):
        pack1.verified_paths(root, "cve")

    # The collector refuses before running anything when the pack isn't reviewed.
    scan = NucleiPackScan("tech", "/bin/false", Sandbox(), root, require_lock=False)
    monkeypatch.setattr("nightfall.config.get_settings", lambda: on)
    with pytest.raises(Refused, match="no recorded review"):
        scan.run("10.0.0.5", RunContext())


def test_invocation_limits_and_output_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _fake_pack(tmp_path, monkeypatch)
    paths = pack1.verified_paths(root, "tech")
    argv = pack1.build_invocation("/usr/local/bin/nuclei", "10.0.0.5", "http://nf:t@p:1", paths)
    for flag in ("-ni", "-duc", "-dr", "-or", "-ot"):
        assert flag in argv
    assert argv[argv.index("-pt") + 1] == "http"
    assert argv[argv.index("-rl") + 1] == "10" and argv[argv.index("-c") + 1] == "10"
    assert argv.count("-t") == 2 and "https://10.0.0.5" in argv
    scan = NucleiPackScan("tech", "/x", Sandbox(), root)
    scan._paths = paths
    assert "-t" not in scan.redact_argv(argv) and "<2 pack templates>" in scan.redact_argv(argv)

    lines = [
        {"template-id": "t0", "matched-at": "http://10.0.0.5/admin"},
        {"template-id": "t0", "matched-at": "http://10.0.0.6/admin"},  # another host
        {"template-id": "not-listed", "matched-at": "http://10.0.0.5/"},
    ]
    out = b"\n".join(json.dumps(x).encode() for x in lines)
    matches, rejected = scan.parse(out, "10.0.0.5")
    assert [m["template_id"] for m in matches] == ["t0"] and rejected == 2
    assert matches[0]["title"] == "Template 0" and matches[0]["check_id"] == "lab-pack1.t0"


def test_findings_use_manifest_wording(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_pack(tmp_path, monkeypatch)
    drafts = from_nuclei(
        [
            {"template_id": "t2", "matched_at": "http://10.0.0.5/x"},
            {"template_id": "t2", "matched_at": "https://10.0.0.5/x"},  # one finding
            {"template_id": "evil", "matched_at": "http://10.0.0.5/"},
        ]
    )
    assert len(drafts) == 1
    d = drafts[0]
    assert d.rule_id == "R17-lab-pack1:t2" and d.severity is Severity.HIGH
    assert "CVE-2024-0001" in d.description and "not exploited" in d.description
