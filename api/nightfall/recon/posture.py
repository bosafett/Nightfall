"""Configuration-posture collectors: TLS configuration and HTTP security headers.

Both are LOW risk (they contact the target, so each run needs an approved operation) and
read-only: TLS handshakes with no application data, and GET / only. They use the same
scope-enforcing client as technology identification (SafeHttp): the name is resolved once,
every address is checked, and the connection goes to the checked address.

What is stored is the configuration, never secrets: cookie values are dropped (only names
and attributes are kept) and response bodies are reduced to their SHA-256 and length.
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from collections.abc import Callable
from typing import Any

import httpx
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from nightfall.core.db.models import Confidence, RiskClass
from nightfall.recon.collectors import CollectorResult, Network, RunContext, _is_tls_error
from nightfall.recon.safe_http import TIMEOUT, Exchange, Refused, SafeHttp, certificate_summary

TLS_RULESET = "tls-audit/2026.11-1"
HEADERS_RULESET = "header-audit/2026.11-1"
# Offered one at a time, oldest first. A protocol the local TLS library can't offer is
# reported as "untestable", never as "refused".
PROTOCOLS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)
_LOCAL_LIMITS = {"NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL_VERSION"}
MAX_COOKIES = 20

MakeClient = Callable[[list[Network]], SafeHttp]


def _default_client(nets: list[Network]) -> SafeHttp:
    return SafeHttp(excluded_networks=nets)


# --- TLS configuration ---------------------------------------------------------------


def key_summary(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        kind, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        kind, bits = f"EC {key.curve.name}", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        kind, bits = "DSA", key.key_size
    else:
        kind, bits = type(key).__name__.removesuffix("PublicKey"), None
    try:
        algo = cert.signature_hash_algorithm
        sig = algo.name if algo is not None else None
    except UnsupportedAlgorithm:
        sig = None
    return {"key_type": kind, "key_bits": bits, "signature_hash": sig}


def _context(verify: bool, version: ssl.TLSVersion | None) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        if version < ssl.TLSVersion.TLSv1_2:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # let the old protocol be offered at all
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


Connect = Callable[[str, int], socket.socket]


def _connect(ip: str, port: int) -> socket.socket:
    return socket.create_connection((ip, port), timeout=TIMEOUT)


def handshake(
    ip: str,
    port: int,
    host: str,
    *,
    verify: bool,
    version: ssl.TLSVersion | None = None,
    connect: Connect = _connect,
) -> dict[str, Any]:
    """One TLS handshake to the pinned address, then close. No application data is sent."""
    try:
        ctx = _context(verify, version)
    except (ValueError, ssl.SSLError) as exc:
        return {"result": "untestable", "detail": f"local TLS library: {exc}"}
    try:
        sock = connect(ip, port)
    except OSError as exc:
        return {"result": "no_connection", "detail": f"{type(exc).__name__}: {str(exc)[:200]}"}
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            return {
                "result": "accepted",
                "version": tls.version(),
                "cipher": (tls.cipher() or ("",))[0],
                "der": der,
            }
    except ssl.SSLCertVerificationError as exc:
        return {"result": "cert_invalid", "detail": str(exc.verify_message or exc)[:200]}
    except ssl.SSLError as exc:
        if exc.reason in _LOCAL_LIMITS and version is not None:
            return {"result": "untestable", "detail": f"local TLS library: {exc.reason}"}
        return {"result": "refused", "detail": str(exc.reason or exc)[:200]}
    except OSError as exc:
        return {"result": "refused", "detail": f"{type(exc).__name__}: {str(exc)[:200]}"}
    finally:
        sock.close()


class TlsAudit:
    """TLS configuration on port 443: one handshake per protocol version (TLS 1.0 to 1.3),
    plus one with certificate validation. At most five handshakes, no HTTP request."""

    key = "tls"
    label = "TLS configuration audit"
    risk_class = RiskClass.LOW
    method = "TLS handshakes on port 443 (one per protocol version, one validated); no HTTP"

    def __init__(self, make_client: MakeClient | None = None, connect: Connect = _connect) -> None:
        self.make_client = make_client or _default_client
        self.connect = connect

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        client = self.make_client(list(ctx.excluded_networks))
        ip = client.pin(target)  # Refused propagates: nothing is sent
        port = client.https_port
        validated = handshake(ip, port, target, verify=True, connect=self.connect)
        if validated["result"] == "no_connection":
            raise RuntimeError(f"No TLS service on port {port} ({validated['detail']}).")
        protocols: dict[str, dict[str, Any]] = {}
        der: bytes | None = validated.get("der")
        for name, version in PROTOCOLS:
            res = handshake(ip, port, target, verify=False, version=version, connect=self.connect)
            der = der or res.get("der")
            protocols[name] = {k: v for k, v in res.items() if k != "der"}
        if der is None:
            raise RuntimeError(f"No TLS handshake completed on port {port}.")
        audit = tls_audit(target, ip, port, validated, protocols, der)
        return CollectorResult(
            raw=json.dumps(audit, indent=2).encode(),
            content_type="application/json",
            tool_name="nightfall-tls",
            tool_version=f"{TLS_RULESET}; {ssl.OPENSSL_VERSION}",
            source="tls",
            confidence=Confidence.HIGH,
            addresses=[ip],
            posture={"tls": audit},
        )


def tls_audit(
    target: str,
    ip: str,
    port: int,
    validated: dict[str, Any],
    protocols: dict[str, dict[str, Any]],
    der: bytes,
) -> dict[str, Any]:
    return {
        "target": target,
        "connected_ip": ip,
        "port": port,
        "validation": {
            "trusted": validated["result"] == "accepted",
            "result": validated["result"],
            "detail": validated.get("detail"),
            "version": validated.get("version"),
            "cipher": validated.get("cipher"),
        },
        "protocols": protocols,
        "accepted": [n for n, p in protocols.items() if p["result"] == "accepted"],
        "certificate": {**certificate_summary(der), **key_summary(der)},
    }


class FixtureTlsAudit(TlsAudit):
    """Canned result labelled 'fixture-tls'. Never contacts the network."""

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        audit = {
            "target": target,
            "connected_ip": "192.0.2.10",
            "port": 443,
            "validation": {
                "trusted": True,
                "result": "accepted",
                "detail": None,
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
            },
            "protocols": {
                "TLSv1": {"result": "accepted", "version": "TLSv1", "cipher": "AES256-SHA"},
                "TLSv1.1": {"result": "refused", "detail": "TLSV1_ALERT_PROTOCOL_VERSION"},
                "TLSv1.2": {"result": "accepted", "version": "TLSv1.2", "cipher": "ECDHE-RSA"},
                "TLSv1.3": {"result": "accepted", "version": "TLSv1.3", "cipher": "TLS_AES"},
            },
            "accepted": ["TLSv1", "TLSv1.2", "TLSv1.3"],
            "certificate": {
                "subject_cn": target,
                "issuer_cn": "Fixture CA",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-06-01T00:00:00+00:00",
                "sans": [target],
                "sha256": "00" * 32,
                "key_type": "RSA",
                "key_bits": 2048,
                "signature_hash": "sha256",
            },
        }
        return CollectorResult(
            raw=json.dumps(audit, indent=2).encode(),
            content_type="application/json",
            tool_name="fixture-tls",
            tool_version="fixture",
            source="fixture",
            confidence=Confidence.HIGH,
            addresses=["192.0.2.10"],
            posture={"tls": audit},
        )


# --- HTTP security headers -----------------------------------------------------------


def _first(headers: list[tuple[str, str]], name: str) -> str | None:
    name = name.lower()
    return next((v for k, v in headers if k.lower() == name), None)


def parse_cookie(value: str) -> dict[str, Any]:
    """Name and attributes of one Set-Cookie header. The value is never kept."""
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()[:100] if parts else ""
    attrs = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:] if p}
    samesite = attrs.get("samesite", "")
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": samesite.split("=", 1)[1].strip() if "=" in samesite else None,
    }


def _hsts_max_age(value: str) -> int | None:
    for part in value.split(";"):
        k, _, v = part.strip().partition("=")
        if k.lower() == "max-age":
            try:
                return int(v.strip().strip('"'))
            except ValueError:
                return None
    return None


def _redacted_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [
        (k, f"{parse_cookie(v)['name']}=<redacted>" if k.lower() == "set-cookie" else v[:2000])
        for k, v in headers
    ]


def response_posture(ex: Exchange) -> dict[str, Any]:
    h = ex.headers
    hsts = _first(h, "strict-transport-security")
    csp = _first(h, "content-security-policy")
    return {
        "url": ex.url,
        "status": ex.status,
        "location": ex.location,
        "content_type": _first(h, "content-type"),
        "hsts": hsts,
        "hsts_max_age": _hsts_max_age(hsts) if hsts else None,
        "csp": csp[:2000] if csp else None,
        "csp_frame_ancestors": bool(csp and "frame-ancestors" in csp.lower()),
        "x_frame_options": _first(h, "x-frame-options"),
        "x_content_type_options": _first(h, "x-content-type-options"),
        "referrer_policy": _first(h, "referrer-policy"),
        "permissions_policy": _first(h, "permissions-policy"),
        "cookies": [parse_cookie(v) for k, v in h if k.lower() == "set-cookie"][:MAX_COOKIES],
        "headers": _redacted_headers(h),
        "body_sha256": hashlib.sha256(ex.body).hexdigest(),
        "body_bytes": len(ex.body),
    }


class HeaderAudit:
    """HTTP security headers and cookie attributes: GET / over HTTPS (validated, then
    unvalidated if the certificate fails) and GET / over plain HTTP to see whether it
    redirects to HTTPS. At most three GET requests; redirects are recorded, not followed."""

    key = "headers"
    label = "HTTP security headers audit"
    risk_class = RiskClass.LOW
    method = "HTTP GET / on ports 443 and 80; security headers and cookie attributes"

    def __init__(self, make_client: MakeClient | None = None) -> None:
        self.make_client = make_client or _default_client

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        client = self.make_client(list(ctx.excluded_networks))
        attempts: list[dict[str, Any]] = []

        def get(scheme: str, verify: bool) -> tuple[Exchange | None, BaseException | None]:
            try:
                ex = client.get(target, scheme, verify)
            except Refused:
                raise
            except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
                attempts.append(
                    {
                        "url": f"{scheme}://{target}/",
                        "verified_tls": verify,
                        "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                    }
                )
                return None, exc
            attempts.append(
                {"url": f"{scheme}://{target}/", "verified_tls": verify, "status": ex.status}
            )
            return ex, None

        https, err = get("https", True)
        if https is None and err is not None and _is_tls_error(err):
            https, _ = get("https", False)
        plain, _ = get("http", False)
        if https is None and plain is None:
            raise RuntimeError("No response on ports 443 or 80.")
        audit = header_audit(target, attempts, https, plain)
        ip = (https or plain).connected_ip  # type: ignore[union-attr]
        return CollectorResult(
            raw=json.dumps(audit, indent=2).encode(),
            content_type="application/json",
            tool_name="nightfall-headers",
            tool_version=HEADERS_RULESET,
            source="headers",
            confidence=Confidence.HIGH,
            addresses=[ip],
            posture={"headers": audit},
        )


def header_audit(
    target: str, attempts: list[dict[str, Any]], https: Exchange | None, plain: Exchange | None
) -> dict[str, Any]:
    location = (plain.location or "") if plain else ""
    return {
        "target": target,
        "attempts": attempts,
        "https": response_posture(https) if https else None,
        "http": response_posture(plain) if plain else None,
        "http_redirects_to_https": bool(
            plain and 300 <= plain.status < 400 and location.lower().startswith("https://")
        ),
    }


class FixtureHeaderAudit(HeaderAudit):
    """Canned result labelled 'fixture-headers'. Never contacts the network."""

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        https = Exchange(
            url=f"https://{target}/",
            connected_ip="192.0.2.10",
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", "max-age=86400"),
                ("Set-Cookie", "session=secret-value; Path=/; HttpOnly"),
            ],
            body=b"<html></html>",
            body_truncated=False,
            elapsed_ms=10,
            tls=None,
            location=None,
        )
        plain = Exchange(
            url=f"http://{target}/",
            connected_ip="192.0.2.10",
            status=301,
            headers=[("Location", f"https://{target}/")],
            body=b"",
            body_truncated=False,
            elapsed_ms=5,
            tls=None,
            location=f"https://{target}/",
        )
        attempts = [
            {"url": https.url, "verified_tls": True, "status": 200},
            {"url": plain.url, "verified_tls": False, "status": 301},
        ]
        audit = header_audit(target, attempts, https, plain)
        return CollectorResult(
            raw=json.dumps(audit, indent=2).encode(),
            content_type="application/json",
            tool_name="fixture-headers",
            tool_version="fixture",
            source="fixture",
            confidence=Confidence.HIGH,
            addresses=["192.0.2.10"],
            posture={"headers": audit},
        )
