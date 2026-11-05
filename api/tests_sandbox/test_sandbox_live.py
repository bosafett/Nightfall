"""Live tool-sandbox checks. They need the real lock, so they don't run with `pytest`:

    sudo NIGHTFALL_EGRESS_LOCK_ONLY= ../infra/tools/egress-lock.sh \\
        .venv/bin/python -m pytest tests_sandbox

(as CI's `sandbox` job does). Run that way, the tests execute as the worker user with only
CAP_SETUID/CAP_SETGID, and tools run as the tool user behind the firewall rule.
"""

import datetime as dt
import functools
import http.server
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from nightfall.core.db.models import ScopeEntryKind, ScopeStatus
from nightfall.recon.collectors import NucleiScan, RunContext
from nightfall.recon.safe_http import SafeHttp
from nightfall.scope.engine import Entry, ScopeSnapshot
from nightfall.tools import nuclei
from nightfall.tools.runner import Sandbox, run

TOOL_USER = os.environ.get("NIGHTFALL_TOOL_USER", "nftool")
NUCLEI_BIN = os.environ.get("NIGHTFALL_TEST_NUCLEI_BIN")
SANDBOX = Sandbox(mode="uid", user=TOOL_USER)
SCOPE = ScopeSnapshot(
    status=ScopeStatus.ACTIVE,
    valid_from=None,
    valid_until=None,
    targets=(Entry(ScopeEntryKind.DOMAIN_TREE, "example.com"),),
    exclusions=(),
)
pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="run under egress-lock.sh, not as root")

PROBE = """
import json, os, socket
out = {"status": {l.split(":")[0]: l.split(":")[1].strip() for l in open("/proc/self/status")
                  if l.startswith(("CapEff", "CapPrm", "CapAmb", "NoNewPrivs"))}}
for name, addr in {"internet": ("1.1.1.1", 443), "dns": ("1.1.1.1", 53),
                   "loopback": ("127.0.0.1", 5432)}.items():
    s = socket.socket(); s.settimeout(3)
    out[name] = s.connect_ex(addr)
try:
    socket.getaddrinfo("example.com", 443); out["resolve"] = "ok"
except OSError:
    out["resolve"] = "failed"
for uid in (0, os.getuid() + 1):
    try:
        os.setuid(uid); out["setuid"] = uid
    except PermissionError:
        pass
print(json.dumps(out))
"""


def test_lock_is_verified() -> None:
    SANDBOX.verify_lock()


def test_tool_process_has_no_privileges_and_no_route_out() -> None:
    res = run([sys.executable, "-I", "-c", PROBE], sandbox=SANDBOX, timeout=30)
    out = json.loads(res.stdout)
    assert out["status"] == {
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }
    assert out["internet"] != 0 and out["dns"] != 0 and out["loopback"] != 0
    assert out["resolve"] == "failed"
    assert "setuid" not in out


@pytest.mark.skipif(not NUCLEI_BIN, reason="set NIGHTFALL_TEST_NUCLEI_BIN")
def test_sandboxed_nuclei_reaches_the_target_only_through_the_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / "index.html").write_text("<title>Index of /</title>")
    tmp_path.chmod(0o755)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    real = nuclei.build_invocation
    monkeypatch.setattr(
        nuclei,
        "build_invocation",
        lambda b, t, p: [a.replace(f"http://{t}", f"http://{t}:{port}") for a in real(b, t, p)],
    )
    scan = NucleiScan(
        NUCLEI_BIN,
        SANDBOX,
        egress_port=int(os.environ.get("NIGHTFALL_EGRESS_PORT", "3128")),
        make_pinner=lambda nets: SafeHttp(resolver=lambda h: ["127.0.0.1"], allow_private=True),
        clock=lambda: dt.datetime.now(dt.UTC),
        ports=frozenset({80, 443, port}),
        timeout=120,
    )
    try:
        result = scan.run("www.example.com", RunContext(scope=SCOPE))
    finally:
        httpd.shutdown()
    assert {m["template_id"] for m in result.matches} == {
        "nf-git-head-exposed",
        "nf-directory-listing",
    }
    assert all(e["host"] == "www.example.com" for e in json.loads(result.raw)["egress"])
