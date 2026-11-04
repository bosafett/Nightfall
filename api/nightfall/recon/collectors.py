"""Passive collectors. Each returns raw output (kept as evidence) plus parsed observations.

Everything a collector returns is untrusted data: names from certificate logs and DNS
answers are attacker-influenced. Every name is re-validated by the normalizer before it
is used, and counts are capped.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from importlib.metadata import version
from typing import Protocol

import httpx

from nightfall.core.db.models import Confidence, RiskClass
from nightfall.core.evidence_store import MAX_BLOB_BYTES
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


class Collector(Protocol):
    key: str
    label: str
    risk_class: RiskClass
    method: str

    def run(self, target: str) -> CollectorResult: ...


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

    def run(self, target: str) -> CollectorResult:
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

    def run(self, target: str) -> CollectorResult:
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

    def run(self, target: str) -> CollectorResult:
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
    def run(self, target: str) -> CollectorResult:
        records = {
            "A": ["192.0.2.10"],
            "AAAA": ["2001:db8::10"],
            "CNAME": ["edge.third-party.example."],
            "MX": [],
            "NS": [],
            "TXT": [],
        }
        return _dns_result(records, "fixture-dns", "fixture", "fixture")


def collectors(mode: str) -> dict[str, Collector]:
    if mode == "fixture":
        return {"ct": FixtureCertificateTransparency(), "dns": FixtureDnsRecords()}
    return {"ct": CertificateTransparency(), "dns": DnsRecords()}


# Tool metadata used by the API without instantiating anything.
TOOLS: dict[str, tuple[str, RiskClass]] = {
    "ct": (CertificateTransparency.label, RiskClass.PASSIVE),
    "dns": (DnsRecords.label, RiskClass.PASSIVE),
}
