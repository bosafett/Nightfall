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
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from importlib.metadata import version
from typing import Protocol

import httpx

from nightfall.core.clock import utcnow
from nightfall.core.db.models import Confidence, RiskClass
from nightfall.core.evidence_store import MAX_BLOB_BYTES
from nightfall.recon.fingerprint import RULESET, fingerprint, page_title
from nightfall.recon.safe_http import Exchange, Refused, SafeHttp
from nightfall.scope import normalize
from nightfall.scope.engine import ScopeSnapshot, evaluate
from nightfall.scope.normalize import NormalizationError
from nightfall.tools import nuclei
from nightfall.tools.egress import EgressProxy, Policy, canonical_host
from nightfall.tools.runner import Sandbox
from nightfall.tools.runner import run as run_tool

MAX_NAMES = 5000
CT_TIMEOUT = 30.0
# crt.sh is a free public service that often answers 502/503 under load. Transient
# failures are retried with a short backoff (worst case ~100 s, well inside the function
# time limit); anything else fails at once.
CT_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
CT_BACKOFF = (2.0, 5.0)  # seconds before attempts 2 and 3
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
    matches: list[dict[str, str]] = field(default_factory=list)  # catalog check matches
    egress: dict[str, int] = field(default_factory=dict)  # proxy connection counts
    posture: dict[str, object] = field(default_factory=dict)  # TLS / header audits


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class RunContext:
    """Scope facts a collector needs at run time (from the operation's pinned scope)."""

    excluded_networks: tuple[Network, ...] = ()
    scope: ScopeSnapshot | None = None


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

    transport: httpx.BaseTransport | None = None  # tests inject a mock transport

    def sleep(self, seconds: float) -> None:  # replaced in tests
        time.sleep(seconds)

    def _fetch(self, target: str) -> bytes:
        params = {"q": f"%.{target}", "output": "json"}
        chunks: list[bytes] = []
        size = 0
        headers = {"User-Agent": "nightfall-recon"}
        with (
            httpx.Client(
                timeout=CT_TIMEOUT, follow_redirects=False, transport=self.transport
            ) as client,
            client.stream("GET", self.url, params=params, headers=headers) as resp,
        ):
            resp.raise_for_status()
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > MAX_BLOB_BYTES:
                    raise RuntimeError("crt.sh response exceeded the 5 MiB evidence limit")
                chunks.append(chunk)
        return b"".join(chunks)

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        last = ""
        for attempt in range(len(CT_BACKOFF) + 1):
            if attempt:
                self.sleep(CT_BACKOFF[attempt - 1])
            try:
                raw_bytes = self._fetch(target)
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in CT_RETRY_STATUS:
                    raise
                last = f"HTTP {exc.response.status_code}"
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = type(exc).__name__
        else:
            raise RuntimeError(
                f"crt.sh (the public certificate-log search) is unavailable right now "
                f"({last}, {len(CT_BACKOFF) + 1} attempts). It's a free service that is often "
                "overloaded; request the collection again in a few minutes."
            )
        chunks = [raw_bytes]
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


class NucleiScan:
    """Curated Nuclei checks (nightfall.tools.nuclei.CATALOG), run in the tool sandbox with
    all traffic through a per-run egress proxy that admits only the operation target, and
    only while the operation's pinned scope still allows it."""

    key = "nuclei"
    label = "Web exposure checks (Nuclei, curated)"
    risk_class = RiskClass.LOW
    method = "Nuclei with NIGHTFALL's pinned GET-only templates, through the scope proxy"

    def __init__(
        self,
        binary: str | None,
        sandbox: Sandbox,
        egress_port: int = 0,
        require_lock: bool = True,
        make_pinner: Callable[[list[Network]], SafeHttp] | None = None,
        clock: Callable[[], datetime] = utcnow,
        timeout: float = 300.0,
        ports: frozenset[int] = frozenset({80, 443}),
    ) -> None:
        self.binary = binary
        self.sandbox = sandbox
        self.egress_port = egress_port
        self.require_lock = require_lock
        self.make_pinner = make_pinner or (lambda nets: SafeHttp(excluded_networks=nets))
        self.clock = clock
        self.timeout = timeout
        self.ports = ports

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        if not self.binary:
            raise RuntimeError("Nuclei isn't installed on this worker (NIGHTFALL_NUCLEI_BIN).")
        if self.require_lock:
            self.sandbox.verify_lock()
        scope = ctx.scope
        if scope is None:
            raise Refused("No pinned scope for this run.")
        target = canonical_host(target)

        def check_host(host: str) -> str | None:
            if host != target:
                return f"{host} is not this operation's target"
            decision = evaluate(scope, host, self.clock())
            return None if decision.allowed else decision.reason

        policy = Policy(
            check_host=check_host,
            ports=self.ports,
            pinner=self.make_pinner(list(ctx.excluded_networks)),
        )
        with EgressProxy(policy, bind=("127.0.0.1", self.egress_port)) as proxy:
            argv = nuclei.build_invocation(self.binary, target, proxy.url)
            res = run_tool(argv, sandbox=self.sandbox, timeout=self.timeout)
            version_res = run_tool(
                [self.binary, "-version", "-duc"], sandbox=self.sandbox, timeout=30
            )
            egress = proxy.log()
            dropped = proxy.dropped_log_entries
            safe_argv = nuclei.redact(argv, proxy.url)
        matches, rejected = nuclei.parse(res.stdout, target)
        if res.returncode != 0 and not matches:
            tail = res.stderr.decode("utf-8", "replace")[-300:]
            raise RuntimeError(f"Nuclei exited with {res.returncode}: {tail}")
        tool_version = (
            f"nuclei {nuclei.engine_version(version_res.stderr)}; {nuclei.CATALOG_VERSION}"
        )
        raw = json.dumps(
            {
                "target": target,
                "argv": safe_argv,
                "tool_version": tool_version,
                "templates": {t: c.sha256 for t, c in sorted(nuclei.CATALOG.items())},
                "returncode": res.returncode,
                "timed_out": res.timed_out,
                "output_truncated": res.stdout_truncated,
                "output_jsonl": res.stdout.decode("utf-8", "replace"),
                "stderr_tail": res.stderr.decode("utf-8", "replace")[-2000:],
                "egress": egress,
                "egress_log_dropped": dropped,
                "matches": matches,
                "rejected_lines": rejected,
            },
            indent=2,
        ).encode()
        if len(raw) > MAX_BLOB_BYTES:
            raise RuntimeError("Nuclei output exceeded the evidence size limit.")
        addresses = sorted(
            {str(d["ip"]) for d in egress if d["allowed"] and d["host"] == target and d["ip"]}
            - {target}
        )
        return CollectorResult(
            raw=raw,
            content_type="application/json",
            tool_name="nuclei",
            tool_version=tool_version,
            source="nuclei",
            confidence=Confidence.HIGH,
            addresses=addresses,
            matches=matches,
            rejected=rejected,
            egress={
                "allowed": sum(1 for d in egress if d["allowed"]),
                "refused": sum(1 for d in egress if not d["allowed"]),
            },
        )


class FixtureNucleiScan(NucleiScan):
    """Canned matches, labelled 'fixture-nuclei'. Never runs a binary or contacts anything."""

    def __init__(self) -> None:
        super().__init__(None, Sandbox())

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        matches = [
            {
                "template_id": tid,
                "check_id": nuclei.CATALOG[tid].check_id,
                "title": nuclei.CATALOG[tid].title,
                "matched_at": f"https://{target}{path}",
            }
            for tid, path in (("nf-git-head-exposed", "/.git/HEAD"), ("nf-missing-hsts", "/"))
        ]
        raw = json.dumps({"target": target, "fixture": True, "matches": matches}).encode()
        return CollectorResult(
            raw=raw,
            content_type="application/json",
            tool_name="fixture-nuclei",
            tool_version="fixture",
            source="fixture",
            confidence=Confidence.HIGH,
            matches=matches,
            egress={"allowed": 0, "refused": 0},
        )


# Defined after CollectorResult and RunContext, which it imports.
from nightfall.recon import posture  # noqa: E402


def collectors(mode: str, nuclei_scan: NucleiScan | None = None) -> dict[str, Collector]:
    if mode == "fixture":
        return {
            "ct": FixtureCertificateTransparency(),
            "dns": FixtureDnsRecords(),
            "http": FixtureHttpFingerprint(),
            "nuclei": FixtureNucleiScan(),
            "tls": posture.FixtureTlsAudit(),
            "headers": posture.FixtureHeaderAudit(),
        }
    return {
        "ct": CertificateTransparency(),
        "dns": DnsRecords(),
        "http": HttpFingerprint(),
        "nuclei": nuclei_scan or NucleiScan(None, Sandbox()),
        "tls": posture.TlsAudit(),
        "headers": posture.HeaderAudit(),
    }


# Tools the isolated lab worker runs (they contact a target directly; the passive ones need
# public records the lab has no route to).
LAB_TOOLS = frozenset({"http", "nuclei", "tls", "headers"})


def lab_collectors(
    networks: tuple[Network, ...], nuclei_scan: NucleiScan | None = None
) -> dict[str, Collector]:
    """The lab worker's tools: every address they contact must be inside the lab networks
    (SafeHttp.only_networks), on top of the scope check and the tool sandbox."""

    def pinner(excluded: list[Network]) -> SafeHttp:
        return SafeHttp(excluded_networks=excluded, only_networks=list(networks))

    scan = nuclei_scan or NucleiScan(None, Sandbox())
    scan.make_pinner = pinner
    return {
        "http": HttpFingerprint(make_client=pinner),
        "nuclei": scan,
        "tls": posture.TlsAudit(make_client=pinner),
        "headers": posture.HeaderAudit(make_client=pinner),
    }


# Tool metadata used by the API without instantiating anything.
TOOLS: dict[str, tuple[str, RiskClass]] = {
    "ct": (CertificateTransparency.label, RiskClass.PASSIVE),
    "dns": (DnsRecords.label, RiskClass.PASSIVE),
    "http": (HttpFingerprint.label, RiskClass.LOW),
    "nuclei": (NucleiScan.label, RiskClass.LOW),
    "tls": (posture.TlsAudit.label, RiskClass.LOW),
    "headers": (posture.HeaderAudit.label, RiskClass.LOW),
}
