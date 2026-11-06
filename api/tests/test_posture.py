"""TLS configuration and HTTP security-header collectors, against local servers."""

import datetime as dt
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import socket

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from nightfall.blackice.finding_rules import from_posture
from nightfall.recon.collectors import RunContext
from nightfall.recon.posture import HeaderAudit, TlsAudit, parse_cookie
from nightfall.recon.safe_http import Refused, SafeHttp

NOW = dt.datetime(2026, 11, 6, tzinfo=dt.UTC)


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[int]:
    """A TLS 1.2+ server with a self-signed 2048-bit certificate for www.lab.test."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.lab.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime.now(dt.UTC) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("www.lab.test")]), False)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()


def local(port: int = 1, http_port: int = 1) -> SafeHttp:
    return SafeHttp(
        resolver=lambda host: ["127.0.0.1"],
        allow_private=True,
        https_port=port,
        http_port=http_port,
    )


def test_tls_audit_against_a_local_server(tls_server: int) -> None:
    res = TlsAudit(make_client=lambda nets: local(tls_server)).run("www.lab.test", RunContext())
    audit = res.posture["tls"]
    assert audit["connected_ip"] == "127.0.0.1"
    assert audit["validation"]["result"] == "cert_invalid"  # self-signed
    assert "TLSv1.2" in audit["accepted"]
    assert audit["protocols"]["TLSv1"]["result"] in ("refused", "untestable")
    assert audit["certificate"]["key_type"] == "RSA" and audit["certificate"]["key_bits"] == 2048
    assert audit["certificate"]["sans"] == ["www.lab.test"]
    checks = {d.check_id for d in from_posture(res.posture, dt.datetime.now(dt.UTC))}
    assert checks == {"tls.certificate-not-trusted", "tls.certificate-expiring"}
    assert b"PRIVATE" not in res.raw


def test_tls_audit_refuses_blocked_addresses_before_connecting() -> None:
    calls: list[tuple[str, int]] = []

    def connect(ip: str, port: int) -> socket:
        calls.append((ip, port))
        raise AssertionError("must not connect")

    audit = TlsAudit(
        make_client=lambda nets: SafeHttp(resolver=lambda h: ["169.254.169.254"]), connect=connect
    )
    with pytest.raises(Refused, match="metadata"):
        audit.run("www.lab.test", RunContext())
    assert calls == []


def test_tls_audit_without_a_tls_service_fails_cleanly() -> None:
    with pytest.raises(RuntimeError, match="No TLS service"):
        TlsAudit(make_client=lambda nets: local(1)).run("www.lab.test", RunContext())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.server.seen.append(self.command)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=very-secret; Path=/")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


def test_header_audit_against_a_local_server() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.seen = []  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = HeaderAudit(make_client=lambda nets: local(1, srv.server_port)).run(
            "www.lab.test", RunContext()
        )
    finally:
        srv.shutdown()
    audit = res.posture["headers"]
    assert audit["https"] is None and audit["http"]["status"] == 200
    assert audit["http"]["cookies"] == [
        {"name": "sid", "secure": False, "httponly": False, "samesite": None}
    ]
    assert b"very-secret" not in res.raw and b"sid=<redacted>" in res.raw
    assert srv.seen == ["GET"]  # type: ignore[attr-defined]
    # HTTPS didn't answer, so header rules don't judge plain-HTTP-only responses here
    # (technology identification reports "no HTTPS" as R3).
    assert from_posture(res.posture, NOW) == []


def test_cookie_parsing_keeps_attributes_only() -> None:
    assert parse_cookie("a=b=c; Secure; HttpOnly; SameSite=Strict") == {
        "name": "a",
        "secure": True,
        "httponly": True,
        "samesite": "Strict",
    }
