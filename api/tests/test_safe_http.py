"""Safe HTTP client and fingerprinting, against a local test server."""

import ipaddress
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from nightfall.recon.collectors import HttpFingerprint, RunContext
from nightfall.recon.fingerprint import fingerprint, page_title
from nightfall.recon.safe_http import MAX_BODY, Refused, SafeHttp

SEEN: list[dict[str, str]] = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        SEEN.append(
            {"host": self.headers["Host"], "ua": self.headers["User-Agent"], "method": self.command}
        )
        mode = self.server.mode  # type: ignore[attr-defined]
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        body = (
            b"x" * (MAX_BODY * 2)
            if mode == "big"
            else (b'<html><title> Portal </title><meta name="generator" content="WordPress 6.4.2">')
        )
        self.send_response(200)
        self.send_header("Server", "nginx/1.25.3")
        self.send_header("Set-Cookie", "PHPSESSID=abc; path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.mode = "ok"  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    SEEN.clear()
    yield srv
    srv.shutdown()


def local(server, calls: list[str] | None = None, **kw) -> SafeHttp:
    def resolver(host: str) -> list[str]:
        if calls is not None:
            calls.append(host)
        return ["127.0.0.1"]

    return SafeHttp(
        resolver=resolver, allow_private=True, http_port=server.server_port, https_port=1, **kw
    )


@pytest.mark.parametrize(
    "addrs",
    [
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["100.64.1.1"],
        ["::1"],
        ["fd00:ec2::254"],
        ["192.168.1.1"],
        ["8.8.8.8", "10.0.0.1"],
        ["0.0.0.0"],  # noqa: S104
        ["224.0.0.1"],
    ],
)
def test_blocked_addresses_are_refused_before_connecting(addrs: list[str]) -> None:
    client = SafeHttp(resolver=lambda h: addrs)
    with pytest.raises(Refused):
        client.get("www.example.com", "http", False)


def test_scope_ip_exclusions_apply_to_resolved_addresses() -> None:
    client = SafeHttp(
        resolver=lambda h: ["8.8.8.8"], excluded_networks=[ipaddress.ip_network("8.8.8.0/24")]
    )
    with pytest.raises(Refused, match="scope excludes"):
        client.get("www.example.com", "http", False)


def test_unresolvable_host_is_refused() -> None:
    def fail(host: str) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(Refused, match="did not resolve"):
        SafeHttp(resolver=fail).get("nope.example.com", "http", False)


def test_resolves_once_connects_to_pinned_ip_with_host_header(server) -> None:
    calls: list[str] = []
    ex = local(server, calls).get("www.example.com", "http", False)
    assert calls == ["www.example.com"]  # one resolution: no rebinding window
    assert ex.connected_ip == "127.0.0.1" and ex.status == 200
    assert SEEN == [
        {
            "host": "www.example.com",
            "ua": "JANUS/0.1 (authorized security assessment)",
            "method": "GET",
        }
    ]


def test_redirects_are_recorded_not_followed(server) -> None:
    server.mode = "redirect"
    ex = local(server).get("www.example.com", "http", False)
    assert ex.status == 302 and ex.location.startswith("http://169.254.169.254")
    assert len(SEEN) == 1


def test_body_is_capped(server) -> None:
    server.mode = "big"
    ex = local(server).get("www.example.com", "http", False)
    assert ex.body_truncated and len(ex.body) == MAX_BODY


def test_collector_falls_back_to_http_and_fingerprints(server) -> None:
    collector = HttpFingerprint(make_client=lambda nets: local(server, excluded_networks=nets))
    result = collector.run("www.example.com", RunContext())
    techs = {(t["name"], t["version"]) for t in result.technologies}
    assert (
        ("nginx", "1.25.3") in techs and ("WordPress", "6.4.2") in techs and ("PHP", None) in techs
    )
    attempts = result.http[0]["attempts"]
    assert attempts[0]["url"] == "https://www.example.com/" and "error" in attempts[0]
    assert attempts[-1] == {"url": "http://www.example.com/", "verified_tls": False, "status": 200}
    assert result.http[0]["title"] == "Portal"
    assert result.addresses == ["127.0.0.1"]


def test_fingerprint_rules() -> None:
    techs = fingerprint(
        [
            ("Server", "Microsoft-IIS/10.0"),
            ("X-Powered-By", "ASP.NET"),
            ("X-AspNet-Version", "4.0.30319"),
            ("Set-Cookie", "ASP.NET_SessionId=1; path=/"),
        ],
        b'<script id="__NEXT_DATA__" type="application/json">{}</script>',
    )
    found = {(t.name, t.version, t.confidence) for t in techs}
    assert ("Microsoft IIS", "10.0", "high") in found
    assert ("ASP.NET", "4.0.30319", "high") in found
    assert ("ASP.NET", None, "medium") in found
    assert ("Next.js", None, "medium") in found
    assert fingerprint([("Server", "unknown-thing")], b"") == []
    assert page_title(b"<TITLE>\n A  B </title>") == "A B"
    assert page_title(b"no title") is None
