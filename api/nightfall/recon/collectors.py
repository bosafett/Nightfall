"""Passive collectors. Each returns raw output (kept as evidence) plus parsed observations.

Everything a collector returns is untrusted data: names from certificate logs and DNS
answers are attacker-influenced. Every name is re-validated by the normalizer before it
is used, and counts are capped.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import version
from typing import Protocol

import httpx

from nightfall.core.db.models import Confidence, RiskClass
from nightfall.core.evidence_store import MAX_BLOB_BYTES
from nightfall.recon.fingerprint import RULESET, fingerprint, page_title
from nightfall.recon.safe_http import Exchange, Refused, SafeHttp
from nightfall.scope import normalize
from nightfall.scope.normalize import NormalizationError

MAX_NAMES = 5000
CT_TIMEOUT = 30.0
DNS_LIFETIME = 5.0
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


@dataclass
class CollectorResult:
    raw: bytes
    content_type: str
    tool_name: str
    tool_version: str
    source: str
    confidence: Confidence
    names: list[str] = field(default_factory=list)  # discovered hostnames (normalized)
    addresses: list[str] = field(default_factory=list)  # resolved IPs (normalized)
    cnames: list[str] = field(default_factory=list)  # CNAME targets (normalized)
    records: dict[str, list[str]] = field(default_factory=dict)
    rejected: int = 0  # values dropped as malformed
    technologies: list[dict[str, str | None]] = field(default_factory=list)
    http: list[dict[str, object]] = field(default_factory=list)  # per-request summaries


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class RunContext:
    """Scope facts a collector needs at run time (from the operation's pinned scope)."""

    excluded_networks: tuple[Network, ...] = ()


class Collector(Protocol):
    key: str
    label: str
    risk_class: RiskClass
    method: str

    def run(self, target: str, ctx: RunContext) -> CollectorResult: ...


def clean_names(values: list[str]) -> tuple[list[str], int]:
    seen: dict[str, None] = {}
    rejected = 0
    for v in values:
        v = v.strip().removeprefix("*.")
        try:
            seen[normalize.hostname(v)] = None
        except NormalizationError:
            rejected += 1
        if len(seen) >= MAX_NAMES:
            break
    return sorted(seen), rejected


class CertificateTransparency:
    """Names from public certificate-transparency logs via crt.sh. Contacts only crt.sh,
    never the target."""

    key = "ct"
    label = "Certificate transparency (crt.sh)"
    risk_class = RiskClass.PASSIVE
    method = "Certificate transparency log search"
    url = "https://crt.sh/"

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        params = {"q": f"%.{target}", "output": "json"}
        chunks: list[bytes] = []
        size = 0
        headers = {"User-Agent": "nightfall-recon"}
        with (
            httpx.Client(timeout=CT_TIMEOUT, follow_redirects=False) as client,
            client.stream("GET", self.url, params=params, headers=headers) as resp,
        ):
            resp.raise_for_status()
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > MAX_BLOB_BYTES:
                    raise RuntimeError("crt.sh response exceeded the 5 MiB evidence limit")
                chunks.append(chunk)
        raw = b"".join(chunks)
        entries = json.loads(raw or b"[]")
        values: list[str] = []
        for e in entries if isinstance(entries, list) else []:
            if isinstance(e, dict):
                for key in ("name_value", "common_name"):
                    if isinstance(e.get(key), str):
                        values.extend(e[key].splitlines())
        names, rejected = clean_names(values)
        return CollectorResult(
            raw=raw,
            content_type="application/json",
            tool_name="crt.sh",
            tool_version="crt.sh-json",
            source="crt.sh",
            confidence=Confidence.HIGH,
            names=names,
            rejected=rejected,
        )


class DnsRecords:
    """Public DNS lookups through the configured resolver."""

    key = "dns"
    label = "DNS records"
    risk_class = RiskClass.PASSIVE
    method = "DNS resolution (A, AAAA, CNAME, MX, NS, TXT)"

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_LIFETIME
        records: dict[str, list[str]] = {}
        for rtype in DNS_TYPES:
            try:
                answer = resolver.resolve(target, rtype, raise_on_no_answer=False)
                records[rtype] = [r.to_text() for r in answer][:100]
            except dns.resolver.NXDOMAIN:
                records = {"NXDOMAIN": []}
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
                records[rtype] = [f"error: {type(exc).__name__}"]
        return _dns_result(records, "dnspython", version("dnspython"), "dns")


def _dns_result(records: dict[str, list[str]], tool: str, ver: str, source: str) -> CollectorResult:
    addresses: list[str] = []
    for rtype in ("A", "AAAA"):
        for v in records.get(rtype, []):
            with contextlib.suppress(NormalizationError):
                addresses.append(str(normalize.ip(v)))
    cnames, rejected = clean_names(records.get("CNAME", []))
    raw = json.dumps(records, sort_keys=True, indent=2).encode()
    return CollectorResult(
        raw=raw,
        content_type="application/json",
        tool_name=tool,
        tool_version=ver,
        source=source,
        confidence=Confidence.HIGH,
        addresses=sorted(set(addresses)),
        cnames=cnames,
        records=records,
        rejected=rejected,
    )


# --- Fixture mode (tests only) ---------------------------------------------------


class FixtureCertificateTransparency(CertificateTransparency):
    """Canned results. Evidence is labelled tool_name 'fixture-ct' so it can never be
    mistaken for real collection. Never contacts the network."""

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        values = [
            f"www.{target}",
            f"api.{target}",
            f"*.{target}",
            f"mail.{target}",
            f"old.legacy.{target}",
            "cdn.third-party.example",
            "bad_name!",
            target,
        ]
        raw = json.dumps([{"name_value": "\n".join(values)}]).encode()
        names, rejected = clean_names(values)
        return CollectorResult(
            raw=raw,
            content_type="application/json",
            tool_name="fixture-ct",
            tool_version="fixture",
            source="fixture",
            confidence=Confidence.HIGH,
            names=names,
            rejected=rejected,
        )


class FixtureDnsRecords(DnsRecords):
    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        records = {
            "A": ["192.0.2.10"],
            "AAAA": ["2001:db8::10"],
            "CNAME": ["edge.third-party.example."],
            "MX": [],
            "NS": [],
            "TXT": [],
        }
        return _dns_result(records, "fixture-dns", "fixture", "fixture")


class HttpFingerprint:
    """Technology identification: at most three GET requests to the target's web root
    (HTTPS verified, HTTPS unverified if the certificate fails, then HTTP). LOW risk: it
    contacts the target, so it needs an approved operation (review decision 8)."""

    key = "http"
    label = "Technology identification (HTTP)"
    risk_class = RiskClass.LOW
    method = "HTTP GET / on ports 443 and 80; headers, TLS and page markers"

    def __init__(self, make_client: Callable[[list[Network]], SafeHttp] | None = None) -> None:
        self.make_client = make_client or (lambda nets: SafeHttp(excluded_networks=nets))

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        client = self.make_client(list(ctx.excluded_networks))
        attempts: list[dict[str, object]] = []

        def attempt(scheme: str, verify: bool) -> tuple[Exchange | None, BaseException | None]:
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

        exchange, err = attempt("https", True)
        if exchange is None and err is not None and _is_tls_error(err):
            # Certificate problem: fingerprint anyway, and record that TLS didn't verify.
            exchange, _ = attempt("https", False)
        if exchange is None:
            exchange, _ = attempt("http", False)
        if exchange is None:
            raise RuntimeError("No response on ports 443 or 80.")
        return http_result(target, exchange, attempts, "nightfall-http", RULESET, "http")


def _is_tls_error(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return "ssl" in text or "certificate" in text or "tls" in text


def http_result(
    target: str, ex: Exchange, attempts: list[dict[str, object]], tool: str, ver: str, source: str
) -> CollectorResult:
    techs = [t.as_dict() for t in fingerprint(ex.headers, ex.body)]
    title = page_title(ex.body)
    raw = json.dumps(
        {
            "target": target,
            "attempts": attempts,
            "url": ex.url,
            "connected_ip": ex.connected_ip,
            "status": ex.status,
            "headers": ex.headers,
            "location": ex.location,
            "tls": ex.tls,
            "elapsed_ms": ex.elapsed_ms,
            "body_sha256": hashlib.sha256(ex.body).hexdigest(),
            "body_truncated": ex.body_truncated,
            "body_base64": base64.b64encode(ex.body).decode(),
            "ruleset": ver,
        },
        indent=2,
    ).encode()
    summary: dict[str, object] = {
        "url": ex.url,
        "status": ex.status,
        "title": title,
        "location": ex.location,
        "tls": ex.tls,
        "attempts": attempts,
        "connected_ip": ex.connected_ip,
    }
    return CollectorResult(
        raw=raw,
        content_type="application/json",
        tool_name=tool,
        tool_version=ver,
        source=source,
        confidence=Confidence.HIGH,
        addresses=[ex.connected_ip],
        technologies=techs,
        http=[summary],
    )


class FixtureHttpFingerprint(HttpFingerprint):
    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        body = (
            b"<html><head><title>Acme portal</title>"
            b'<meta name="generator" content="WordPress 6.4.2"></head>'
            b'<body><link href="/wp-content/themes/x.css"></body></html>'
        )
        ex = Exchange(
            url=f"https://{target}/",
            connected_ip="192.0.2.10",
            status=200,
            headers=[
                ("Server", "nginx/1.25.3"),
                ("X-Powered-By", "PHP/8.2.12"),
                ("Content-Type", "text/html"),
            ],
            body=body,
            body_truncated=False,
            elapsed_ms=12,
            tls={"version": "TLSv1.3", "subject_cn": target, "issuer_cn": "Fixture CA"},
            location=None,
        )
        return http_result(
            target,
            ex,
            [{"url": ex.url, "verified_tls": True, "status": 200}],
            "fixture-http",
            "fixture",
            "fixture",
        )


def collectors(mode: str) -> dict[str, Collector]:
    if mode == "fixture":
        return {
            "ct": FixtureCertificateTransparency(),
            "dns": FixtureDnsRecords(),
            "http": FixtureHttpFingerprint(),
        }
    return {"ct": CertificateTransparency(), "dns": DnsRecords(), "http": HttpFingerprint()}


# Tool metadata used by the API without instantiating anything.
TOOLS: dict[str, tuple[str, RiskClass]] = {
    "ct": (CertificateTransparency.label, RiskClass.PASSIVE),
    "dns": (DnsRecords.label, RiskClass.PASSIVE),
    "http": (HttpFingerprint.label, RiskClass.LOW),
}
