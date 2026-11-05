"""Scope-enforcing forward proxy for third-party tools (review §13).

External tools follow links, resolve names on their own and can be configured in ways
we don't control, so their own scope flags are not a guarantee. Every connection a tool
makes goes through this proxy instead, and the tool's sandbox has no other route out
(`infra/tools/egress-lock.sh`). For each connection:

  1. The client must present this run's proxy credential (one random token per run).
  2. The destination port must be in the policy's port set.
  3. The destination host must pass the policy's host check (the operation's target and
     its pinned scope).
  4. The name is resolved once by the proxy and every address is checked: no private,
     loopback, link-local, metadata, CGNAT or scope-excluded address. The proxy then
     connects to that exact address, so a tool can't be steered elsewhere by DNS.
  5. Plain HTTP: one request per connection, only the policy's methods, no request body,
     hop-by-hop and Upgrade headers dropped, Host rewritten to the checked host.
     HTTPS (CONNECT): the TCP destination is enforced; what travels inside the TLS tunnel
     isn't inspected (no interception).
  6. Connection count, bytes and duration are capped.

Every decision, allowed or refused, is recorded and stored with the tool's evidence.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import ipaddress
import secrets
import select
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from nightfall.recon.safe_http import Refused, SafeHttp, blocked_reason
from nightfall.scope import normalize
from nightfall.scope.normalize import NormalizationError

HEAD_LIMIT = 16 * 1024
IO_TIMEOUT = 15.0
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
}
MAX_LOG = 2000


@dataclass(frozen=True)
class Policy:
    """check_host returns None when a host may be contacted, or a refusal reason."""

    check_host: Callable[[str], str | None]
    ports: frozenset[int] = frozenset({80, 443})
    methods: frozenset[str] = frozenset({"GET", "HEAD"})
    pinner: SafeHttp = field(default_factory=SafeHttp)
    max_connections: int = 300
    max_bytes_per_connection: int = 8 * 1024 * 1024
    max_seconds_per_connection: float = 60.0


@dataclass
class Decision:
    at: float
    method: str
    host: str
    port: int | None
    ip: str | None
    allowed: bool
    reason: str
    bytes_up: int = 0
    bytes_down: int = 0


class _Refusal(Exception):
    def __init__(self, status: int, reason: str, host: str = "", port: int | None = None) -> None:
        super().__init__(reason)
        self.status, self.reason, self.host, self.port = status, reason, host, port


def _split_hostport(value: str, default_port: int | None) -> tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("bad IPv6 literal")
        host, rest = value[1:end], value[end + 1 :]
        port_s = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") == 1:
        host, port_s = value.split(":")
    else:
        host, port_s = value, ""
    if port_s:
        if not port_s.isdigit():
            raise ValueError("bad port")
        port = int(port_s)
    elif default_port is not None:
        port = default_port
    else:
        raise ValueError("port required")
    if not 0 < port < 65536:
        raise ValueError("bad port")
    return host, port


def canonical_host(raw: str) -> str:
    """IP literal or hostname, normalized the same way the scope engine stores them."""
    try:
        return str(normalize.ip(raw))
    except NormalizationError:
        return normalize.hostname(raw)


class EgressProxy:
    def __init__(self, policy: Policy, bind: tuple[str, int] = ("127.0.0.1", 0)) -> None:
        self.policy = policy
        self.token = secrets.token_urlsafe(24)
        self.decisions: list[Decision] = []
        self.dropped_log_entries = 0
        self._lock = threading.Lock()
        self._connections = 0
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                proxy._handle(self.request)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = Server(bind, Handler, bind_and_activate=False)
        self._thread: threading.Thread | None = None

    # --- lifecycle ---------------------------------------------------------------

    def __enter__(self) -> EgressProxy:
        self._server.server_bind()
        self._server.server_activate()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://nf:{self.token}@127.0.0.1:{self.port}"

    def log(self) -> list[dict[str, object]]:
        with self._lock:
            return [asdict(d) for d in self.decisions]

    def _record(self, d: Decision) -> None:
        with self._lock:
            if len(self.decisions) < MAX_LOG:
                self.decisions.append(d)
            else:
                self.dropped_log_entries += 1

    # --- request handling ----------------------------------------------------------

    def _handle(self, client: socket.socket) -> None:
        client.settimeout(IO_TIMEOUT)
        method, host, port, ip = "?", "", None, None
        try:
            head = _read_head(client)
            request_line, _, rest = head.partition(b"\r\n")
            parts = request_line.decode("latin-1").split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise _Refusal(400, "malformed request line")
            method, target, _version = parts
            headers = _parse_headers(rest)
            self._authenticate(headers)
            with self._lock:
                self._connections += 1
                over = self._connections > self.policy.max_connections
            if over:
                raise _Refusal(429, "connection budget for this run is spent")

            if method == "CONNECT":
                try:
                    raw_host, port = _split_hostport(target, None)
                except ValueError as exc:
                    raise _Refusal(400, f"bad CONNECT target: {exc}") from exc
                host, ip = self._authorize(raw_host, port)
                upstream = socket.create_connection((ip, port), timeout=IO_TIMEOUT)
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                up, down = _relay(client, upstream, b"", self.policy)
            else:
                if method not in self.policy.methods:
                    raise _Refusal(405, f"method {method} not allowed")
                url = urlsplit(target)
                if url.scheme != "http" or not url.netloc or "@" in url.netloc:
                    raise _Refusal(400, "plain-HTTP requests must use an absolute http:// URL")
                try:
                    raw_host, port = _split_hostport(url.netloc, 80)
                except ValueError as exc:
                    raise _Refusal(400, f"bad URL: {exc}") from exc
                if headers.get("transfer-encoding") or headers.get("content-length", "0") != "0":
                    raise _Refusal(400, "request bodies are not allowed")
                host, ip = self._authorize(raw_host, port)
                path = url.path or "/"
                if url.query:
                    path += "?" + url.query
                host_header = host if port == 80 else f"{host}:{port}"
                if ":" in host and not host.startswith("["):  # IPv6 literal
                    host_header = f"[{host}]" if port == 80 else f"[{host}]:{port}"
                lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
                lines += [
                    f"{k}: {v}" for k, v in _header_items(rest) if k.lower() not in HOP_BY_HOP
                ]
                lines.append("Connection: close")
                first = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
                upstream = socket.create_connection((ip, port), timeout=IO_TIMEOUT)
                # One request per connection: anything else the client sends is dropped.
                up, down = _relay(client, upstream, first, self.policy, client_to_upstream=False)
            self._record(Decision(time.time(), method, host, port, ip, True, "in scope", up, down))
        except _Refusal as r:
            if r.status == 400 and method == "?" and r.reason.startswith("connection closed"):
                return  # a reachability probe that sent nothing; not a connection attempt
            self._record(
                Decision(time.time(), method, r.host or host, r.port or port, ip, False, r.reason)
            )
            _reply(client, r.status, r.reason)
        except OSError as exc:
            self._record(
                Decision(
                    time.time(),
                    method,
                    host,
                    port,
                    ip,
                    True,
                    f"network error: {type(exc).__name__}",
                )
            )
            _reply(client, 502, "upstream connection failed")
        finally:
            with contextlib.suppress(OSError):
                client.close()

    def _authenticate(self, headers: dict[str, str]) -> None:
        value = headers.get("proxy-authorization", "")
        scheme, _, encoded = value.partition(" ")
        ok = False
        if scheme.lower() == "basic":
            try:
                user, _, password = base64.b64decode(encoded, validate=True).decode().partition(":")
                ok = user == "nf" and hmac.compare_digest(password, self.token)
            except (ValueError, UnicodeDecodeError):
                ok = False
        if not ok:
            raise _Refusal(407, "missing or wrong proxy credential")

    def _authorize(self, raw_host: str, port: int) -> tuple[str, str]:
        try:
            host = canonical_host(raw_host)
        except NormalizationError as exc:
            raise _Refusal(403, f"invalid host: {exc}", raw_host, port) from exc
        if port not in self.policy.ports:
            raise _Refusal(403, f"port {port} is not allowed for this tool", host, port)
        if reason := self.policy.check_host(host):
            raise _Refusal(403, reason, host, port)
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        try:
            if addr is not None:
                nets = self.policy.pinner.excluded_networks
                if any(addr.version == n.version and addr in n for n in nets):
                    raise Refused(f"{addr} is excluded by the scope.")
                if not self.policy.pinner.allow_private and (why := blocked_reason(addr)):
                    raise Refused(f"{addr} is a {why}; connections to it are blocked.")
                ip = str(addr)
            else:
                ip = self.policy.pinner.pin(host)
        except Refused as exc:
            raise _Refusal(403, str(exc), host, port) from exc
        return host, ip


def _read_head(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise _Refusal(400, "connection closed before the request was complete")
        buf += chunk
        if len(buf) > HEAD_LIMIT:
            raise _Refusal(431, "request head too large")
    head, _, _extra = buf.partition(b"\r\n\r\n")
    # Bytes after the head (a pipelined request or a body) are never forwarded.
    return head


def _header_items(raw: bytes) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for line in raw.decode("latin-1").split("\r\n"):
        if not line:
            continue
        if line[0] in " \t" or ":" not in line:
            raise _Refusal(400, "malformed header")
        k, _, v = line.partition(":")
        if not k or any(c in k for c in " \t"):
            raise _Refusal(400, "malformed header")
        items.append((k, v.strip()))
    return items


def _parse_headers(raw: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for k, v in _header_items(raw):
        key = k.lower()
        if key in headers and key in ("content-length", "transfer-encoding", "proxy-authorization"):
            raise _Refusal(400, f"duplicate {key} header")
        headers[key] = v
    return headers


def _reply(sock: socket.socket, status: int, reason: str) -> None:
    body = f"NIGHTFALL egress proxy refused this connection: {reason}\n".encode()
    extra = 'Proxy-Authenticate: Basic realm="nightfall"\r\n' if status == 407 else ""
    with contextlib.suppress(OSError):
        sock.sendall(
            f"HTTP/1.1 {status} Refused\r\nContent-Type: text/plain\r\n{extra}"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )


def _relay(
    client: socket.socket,
    upstream: socket.socket,
    first: bytes,
    policy: Policy,
    client_to_upstream: bool = True,
) -> tuple[int, int]:
    up = down = 0
    deadline = time.monotonic() + policy.max_seconds_per_connection
    try:
        if first:
            upstream.sendall(first)
            up += len(first)
        socks = [client, upstream] if client_to_upstream else [upstream]
        while socks and time.monotonic() < deadline:
            readable, _, _ = select.select(socks, [], [], 1.0)
            for s in readable:
                data = s.recv(65536)
                if not data:
                    return up, down
                if s is client:
                    upstream.sendall(data)
                    up += len(data)
                else:
                    client.sendall(data)
                    down += len(data)
                if up + down > policy.max_bytes_per_connection:
                    return up, down
    finally:
        upstream.close()
    return up, down
