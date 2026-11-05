"""Scope-enforcing egress proxy: raw-socket tests against local upstreams."""

import base64
import socket
import threading
from collections.abc import Iterator

import pytest

from nightfall.recon.safe_http import SafeHttp
from nightfall.tools.egress import EgressProxy, Policy

ALLOWED = "app.example.com"


class Upstream:
    """Records every byte it receives; answers each connection with one fixed response."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.settimeout(2)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if data.startswith(b"PING"):  # CONNECT tunnel echo
                    conn.sendall(b"PONG:" + data)
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                try:  # anything sent after the first request
                    while extra := conn.recv(4096):
                        data += extra
                except OSError:
                    pass
            except OSError:
                pass
            self.received.append(data)
            conn.close()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def upstream() -> Iterator[Upstream]:
    u = Upstream()
    yield u
    u.close()


def make_proxy(upstream: Upstream, resolve_to: str = "127.0.0.1", **kw) -> EgressProxy:
    pinner = kw.pop(
        "pinner", SafeHttp(resolver=lambda h: [resolve_to], allow_private=resolve_to == "127.0.0.1")
    )
    policy = Policy(
        check_host=lambda h: None if h == ALLOWED else f"{h} is out of scope",
        ports=frozenset({upstream.port}),
        pinner=pinner,
        **kw,
    )
    return EgressProxy(policy)


def auth(proxy: EgressProxy, token: str | None = None) -> bytes:
    cred = base64.b64encode(f"nf:{token or proxy.token}".encode()).decode()
    return f"Proxy-Authorization: Basic {cred}\r\n".encode()


def send(proxy: EgressProxy, raw: bytes, read_after: bytes | None = None) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(raw)
        if read_after is not None:
            s.recv(4096)
            s.sendall(read_after)
        out = b""
        try:
            while chunk := s.recv(4096):
                out += chunk
        except TimeoutError:
            pass
        return out


def get(proxy: EgressProxy, host: str, port: int, extra: bytes = b"", method: str = "GET") -> bytes:
    return send(
        proxy,
        f"{method} http://{host}:{port}/x?y=1 HTTP/1.1\r\nHost: ignored\r\n".encode()
        + auth(proxy)
        + b"Connection: keep-alive\r\nX-Test: 1\r\n"
        + extra
        + b"\r\n",
    )


def test_in_scope_plain_http_is_forwarded_with_clean_headers(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        out = get(proxy, ALLOWED, upstream.port)
        log = proxy.log()
    assert out.endswith(b"hello")
    req = upstream.received[0].decode()
    assert req.startswith("GET /x?y=1 HTTP/1.1\r\n")
    assert f"Host: {ALLOWED}:{upstream.port}" in req
    assert "Proxy-Authorization" not in req and "keep-alive" not in req
    assert "Connection: close" in req and "X-Test: 1" in req
    assert log[0]["allowed"] is True and log[0]["ip"] == "127.0.0.1"


@pytest.mark.parametrize("token", [None, "wrong"])
def test_credential_is_required(upstream: Upstream, token: str | None) -> None:
    with make_proxy(upstream) as proxy:
        header = b"" if token is None else auth(proxy, token)
        out = send(
            proxy, f"GET http://{ALLOWED}:{upstream.port}/ HTTP/1.1\r\n".encode() + header + b"\r\n"
        )
    assert out.startswith(b"HTTP/1.1 407") and b"Proxy-Authenticate" in out
    assert upstream.received == []


def test_out_of_scope_host_is_refused_and_logged(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        out = get(proxy, "other.example.net", upstream.port)
        log = proxy.log()
    assert out.startswith(b"HTTP/1.1 403")
    assert upstream.received == []
    assert log == [
        {
            **log[0],
            "host": "other.example.net",
            "allowed": False,
            "reason": "other.example.net is out of scope",
        }
    ]


def test_port_outside_policy_is_refused(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        out = get(proxy, ALLOWED, 22)
    assert out.startswith(b"HTTP/1.1 403") and b"port 22" in out


def test_only_bodyless_get_and_head(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        assert get(proxy, ALLOWED, upstream.port, method="POST").startswith(b"HTTP/1.1 405")
        body = b"Content-Length: 3\r\n"
        assert get(proxy, ALLOWED, upstream.port, body).startswith(b"HTTP/1.1 400")
        te = b"Transfer-Encoding: chunked\r\n"
        assert get(proxy, ALLOWED, upstream.port, te).startswith(b"HTTP/1.1 400")
    assert upstream.received == []


@pytest.mark.parametrize("resolve_to", ["10.0.0.5", "169.254.169.254", "100.64.1.1", "::1"])
def test_private_and_metadata_resolution_is_refused(upstream: Upstream, resolve_to: str) -> None:
    with make_proxy(upstream, resolve_to=resolve_to) as proxy:
        out = get(proxy, ALLOWED, upstream.port)
    assert out.startswith(b"HTTP/1.1 403")
    assert upstream.received == []


def test_scope_exclusion_is_refused(upstream: Upstream) -> None:
    import ipaddress

    pinner = SafeHttp(
        resolver=lambda h: ["127.0.0.1"],
        allow_private=True,
        excluded_networks=[ipaddress.ip_network("127.0.0.0/8")],
    )
    with make_proxy(upstream, pinner=pinner) as proxy:
        out = get(proxy, ALLOWED, upstream.port)
    assert out.startswith(b"HTTP/1.1 403") and b"excludes" in out


def test_ip_literals_are_checked_too(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        raw = b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n" + auth(proxy) + b"\r\n"
        assert send(proxy, raw).startswith(b"HTTP/1.1 403")
        raw = b"GET http://user@app.example.com/ HTTP/1.1\r\n" + auth(proxy) + b"\r\n"
        assert send(proxy, raw).startswith(b"HTTP/1.1 400")


def test_connect_tunnel_to_allowed_host(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        raw = f"CONNECT {ALLOWED}:{upstream.port} HTTP/1.1\r\n".encode() + auth(proxy) + b"\r\n"
        out = send(proxy, raw, read_after=b"PING\r\n\r\n")
        log = proxy.log()
    assert out.startswith(b"PONG:PING")
    assert log[0]["method"] == "CONNECT" and log[0]["allowed"] is True


def test_pipelined_second_request_never_reaches_upstream(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        first = (
            f"GET http://{ALLOWED}:{upstream.port}/ HTTP/1.1\r\n".encode() + auth(proxy) + b"\r\n"
        )
        smuggled = b"GET / HTTP/1.1\r\nHost: other.example.net\r\n\r\n"
        send(proxy, first + smuggled)
    assert len(upstream.received) == 1
    assert b"other.example.net" not in upstream.received[0]


def test_connection_budget(upstream: Upstream) -> None:
    with make_proxy(upstream, max_connections=2) as proxy:
        results = [get(proxy, ALLOWED, upstream.port) for _ in range(3)]
    assert results[0].endswith(b"hello") and results[1].endswith(b"hello")
    assert results[2].startswith(b"HTTP/1.1 429")


def test_malformed_requests_are_refused(upstream: Upstream) -> None:
    with make_proxy(upstream) as proxy:
        assert send(proxy, b"GARBAGE\r\n\r\n").startswith(b"HTTP/1.1 400")
        dup = auth(proxy) * 2
        assert send(proxy, b"GET http://a/ HTTP/1.1\r\n" + dup + b"\r\n").startswith(
            b"HTTP/1.1 400"
        )
        big = b"GET http://a/ HTTP/1.1\r\nX: " + b"a" * 20000 + b"\r\n\r\n"
        assert send(proxy, big).startswith(b"HTTP/1.1 431")
    assert upstream.received == []
