"""BLACKSITE probe deck (JANUS Phase 2): manual, bounded probes against lab targets.

A probe is an ordinary operation (tool "probe") with a validated spec in its params. It is
addressed by a registered asset id, checked against the pinned lab scope and that target
entry's allowed ports, approved explicitly, and run by the lab worker through SafeHttp with
only_networks set to the lab networks. No shell, no scripts, no free-form destinations.

Bounds (review §16.4, adapted to the lab):
  * http   GET/HEAD/OPTIONS (low risk). POST/PUT/PATCH/DELETE are moderate risk, lab only
           (database CHECK), and need an explicit state-change confirmation. Host and
           User-Agent are fixed; hop-by-hop headers refused; redirects recorded, never
           followed; 10 s timeout; 512 KiB response cap; 64 KiB request body cap.
  * tcp    connect then close, on at most 10 allowed ports; no payload.
  * tls    one validated and one unvalidated handshake on an allowed port; no data.
  Authorization and Cookie values, and Set-Cookie values, are redacted in stored evidence.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from nightfall.core.db.models import Confidence, RiskClass, ScopeEntryKind
from nightfall.core.schemas import Model
from nightfall.recon.collectors import CollectorResult, RunContext
from nightfall.recon.posture import (
    Connect,
    MakeClient,
    _connect,
    _default_client,
    handshake,
    key_summary,
)
from nightfall.recon.safe_http import TIMEOUT, Refused, certificate_summary

PROBE_VERSION = "probe-deck/2026.11-2"  # -2: Set-Cookie attributes kept, key strength
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Fixed by the client, hop-by-hop, or framing: never taken from the operator.
FORBIDDEN_HEADERS = frozenset(
    {
        "host", "user-agent", "connection", "keep-alive", "proxy-authorization",
        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length",
        "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip",
    }
)  # fmt: skip
REDACTED_HEADERS = frozenset({"authorization", "cookie", "set-cookie"})
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
_PATH = re.compile(r"^/[\x21-\x7e]{0,2000}$")  # printable, no spaces or control characters
MAX_BODY = 64 * 1024

Port = Annotated[int, Field(ge=1, le=65535)]


class ProbeRejected(ValueError):
    """The probe is outside its bounds. The message is safe to show."""


class ProbeSpec(Model):
    type: Literal["http", "tcp", "tls"]
    scheme: Literal["http", "https"] = "https"
    method: Annotated[str, StringConstraints(to_upper=True, max_length=8)] = "GET"
    path: Annotated[str, StringConstraints(max_length=2001)] = "/"
    port: Port | None = None
    ports: Annotated[list[Port], Field(max_length=10)] = []
    headers: Annotated[dict[str, str], Field(max_length=20)] = {}
    body: Annotated[str, StringConstraints(max_length=MAX_BODY)] | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not _PATH.match(v):
            raise ValueError("path must start with / and contain only printable characters")
        return v

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, val in v.items():
            if not _TOKEN.match(k):
                raise ValueError(f"invalid header name {k[:40]!r}")
            if k.lower() in FORBIDDEN_HEADERS:
                raise ValueError(f"header {k} can't be set")
            if len(val) > 1000 or any(c in val for c in "\r\n\0"):
                raise ValueError(f"invalid value for header {k}")
            out[k] = val
        return out

    @model_validator(mode="after")
    def _shape(self) -> ProbeSpec:
        if self.method not in SAFE_METHODS | STATE_METHODS:
            raise ValueError("method must be GET, HEAD, OPTIONS, POST, PUT, PATCH or DELETE")
        if self.type != "http" and (self.headers or self.body is not None or self.path != "/"):
            raise ValueError("headers, body and path apply to http probes only")
        if self.body is not None and self.method not in STATE_METHODS:
            raise ValueError("a body is only sent with POST, PUT, PATCH or DELETE")
        if self.type == "tcp" and not self.ports:
            raise ValueError("tcp probes need ports")
        if self.type != "tcp" and self.ports:
            raise ValueError("ports applies to tcp probes; use port")
        return self

    @property
    def state_changing(self) -> bool:
        return self.type == "http" and self.method in STATE_METHODS

    @property
    def risk(self) -> RiskClass:
        return RiskClass.MODERATE if self.state_changing else RiskClass.LOW

    def target_ports(self) -> list[int]:
        if self.type == "tcp":
            return sorted(set(self.ports))
        if self.port:
            return [self.port]
        return [443 if self.type == "tls" or self.scheme == "https" else 80]


class Bounds(Model):
    allowed_ports: list[int]
    max_rps: int
    daily_budget: int


def target_bounds(entries: Iterable[Any], target: str) -> Bounds | None:
    """The most specific scope entry covering an IP target: an exact IP entry, else the
    narrowest CIDR. None if nothing covers it."""
    addr = ipaddress.ip_address(target)
    best: tuple[int, Any] | None = None
    for e in entries:
        if e.kind is ScopeEntryKind.IP and ipaddress.ip_address(e.value) == addr:
            prefix: int = addr.max_prefixlen
        elif e.kind is ScopeEntryKind.CIDR and addr in ipaddress.ip_network(e.value):
            prefix = ipaddress.ip_network(e.value).prefixlen
        else:
            continue
        if best is None or prefix > best[0]:
            best = (prefix, e)
    if best is None:
        return None
    e = best[1]
    return Bounds(
        allowed_ports=list(e.allowed_ports), max_rps=e.max_rps, daily_budget=e.daily_budget
    )


def check_ports(spec: ProbeSpec, bounds: Bounds) -> None:
    bad = [p for p in spec.target_ports() if p not in bounds.allowed_ports]
    if bad:
        raise ProbeRejected(
            f"Port {', '.join(map(str, bad))} isn't allowed for this target "
            f"(allowed: {', '.join(map(str, bounds.allowed_ports))})."
        )


def _redact(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Credential values are dropped. For Set-Cookie the cookie's name and attributes are
    kept (Secure, HttpOnly, SameSite are what the header rules judge); only its value goes."""
    out = []
    for k, v in headers:
        low = k.lower()
        if low == "set-cookie":
            name, _, rest = v.partition(";")
            attrs = f";{rest}" if rest else ""
            out.append((k, f"{name.split('=', 1)[0].strip()[:100]}=<redacted>{attrs[:500]}"))
        elif low in REDACTED_HEADERS:
            out.append((k, "<redacted>"))
        else:
            out.append((k, v[:2000]))
    return out


class Probe:
    """Lab worker tool "probe". Re-validates the spec and the target's ports from the pinned
    scope (RunContext.params / RunContext.allowed_ports) before sending anything."""

    key = "probe"
    label = "Manual probe (BLACKSITE)"
    risk_class = RiskClass.LOW
    method = "BLACKSITE probe deck: bounded HTTP, TCP connect or TLS handshake"

    def __init__(self, make_client: MakeClient | None = None, connect: Connect = _connect) -> None:
        self.make_client = make_client or _default_client
        self.connect = connect

    def run(self, target: str, ctx: RunContext) -> CollectorResult:
        try:
            spec = ProbeSpec.model_validate(ctx.params.get("probe") or {})
        except ValueError as exc:
            raise Refused(f"Invalid probe: {str(exc)[:200]}") from exc
        if ctx.bounds is None:
            raise Refused("No scope entry with probe bounds covers this target.")
        try:
            check_ports(spec, Bounds.model_validate(ctx.bounds))
        except ProbeRejected as exc:
            raise Refused(str(exc)) from exc
        client = self.make_client(list(ctx.excluded_networks))
        ip = client.pin(target)  # lab networks only (only_networks); Refused otherwise
        result: dict[str, Any]
        if spec.type == "http":
            result = self._http(client, target, spec)
        elif spec.type == "tcp":
            result = self._tcp(ip, spec)
        else:
            result = self._tls(ip, target, spec)
        record: dict[str, object] = {
            "version": PROBE_VERSION,
            "target": target,
            "connected_ip": ip,
            "spec": {**spec.model_dump(), "headers": dict(_redact(spec.headers.items()))},
            "result": result,
        }
        return CollectorResult(
            raw=json.dumps(record, indent=2).encode(),
            content_type="application/json",
            tool_name="nightfall-probe",
            tool_version=PROBE_VERSION,
            source="probe",
            confidence=Confidence.HIGH,
            addresses=[ip],
            probe=record,
        )

    def _http(self, client: Any, target: str, spec: ProbeSpec) -> dict[str, Any]:
        body = spec.body.encode() if spec.body is not None else None
        ex = client.request(
            target,
            spec.scheme,
            False,  # lab practice apps use self-signed certificates; reported, not enforced
            method=spec.method,
            path=spec.path,
            port=spec.target_ports()[0],
            headers=spec.headers,
            body=body,
        )
        return {
            "request": {
                "method": spec.method,
                "url": ex.url,
                "headers": _redact(spec.headers.items()),
                "body_sha256": hashlib.sha256(body).hexdigest() if body is not None else None,
                "body_bytes": len(body) if body is not None else 0,
            },
            "status": ex.status,
            "headers": _redact(ex.headers),
            "location": ex.location,  # recorded, not followed
            "tls": ex.tls,
            "elapsed_ms": ex.elapsed_ms,
            "body_sha256": hashlib.sha256(ex.body).hexdigest(),
            "body_bytes": len(ex.body),
            "body_truncated": ex.body_truncated,
            # Shown as escaped text by clients, never rendered.
            "body_base64": base64.b64encode(ex.body).decode(),
        }

    def _tcp(self, ip: str, spec: ProbeSpec) -> dict[str, Any]:
        ports: dict[str, str] = {}
        for port in spec.target_ports():
            try:
                sock = self.connect(ip, port)
                sock.close()
                ports[str(port)] = "open"
            except TimeoutError:
                ports[str(port)] = "filtered"
            except OSError:
                ports[str(port)] = "closed"
        return {"ports": ports, "timeout_s": TIMEOUT}

    def _tls(self, ip: str, target: str, spec: ProbeSpec) -> dict[str, Any]:
        port = spec.target_ports()[0]
        validated = handshake(ip, port, target, verify=True, connect=self.connect)
        raw = handshake(ip, port, target, verify=False, connect=self.connect)
        der = raw.get("der") or validated.get("der")
        return {
            "port": port,
            "validation": {k: v for k, v in validated.items() if k != "der"},
            "handshake": {k: v for k, v in raw.items() if k != "der"},
            "certificate": {**certificate_summary(der), **key_summary(der)} if der else None,
        }


def diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Structured comparison of two probe results of the same target."""
    ra, rb = a.get("result") or {}, b.get("result") or {}
    out: dict[str, Any] = {}
    for key in ("status", "location", "body_sha256", "body_bytes", "ports", "validation"):
        if ra.get(key) != rb.get(key):
            out[key] = {"a": ra.get(key), "b": rb.get(key)}
    ha = {k.lower(): v for k, v in ra.get("headers") or []}
    hb = {k.lower(): v for k, v in rb.get("headers") or []}
    changed = {k: {"a": ha.get(k), "b": hb.get(k)} for k in sorted(ha.keys() | hb.keys())
               if ha.get(k) != hb.get(k)}  # fmt: skip
    if changed:
        out["headers"] = changed
    ta, tb = (
        ra.get("tls") or ra.get("certificate") or {},
        rb.get("tls") or rb.get("certificate") or {},
    )
    if ta != tb:
        out["tls"] = {k: {"a": ta.get(k), "b": tb.get(k)} for k in sorted(ta.keys() | tb.keys())
                      if ta.get(k) != tb.get(k)}  # fmt: skip
    return out


def observations(record: dict[str, Any]) -> CollectorResult | None:
    """A stored probe record as BLACK ICE observations, so the existing deterministic
    finding rules can judge it ("Submit to BLACK ICE", review §16.6). None when the probe
    type has nothing the rules judge (TCP connect)."""
    from nightfall.recon.fingerprint import fingerprint
    from nightfall.recon.posture import response_posture
    from nightfall.recon.safe_http import Exchange

    spec = record.get("spec") or {}
    r = record.get("result") or {}

    def make(**extra: Any) -> CollectorResult:
        return CollectorResult(
            raw=json.dumps(record, sort_keys=True).encode(),
            content_type="application/json",
            tool_name="nightfall-probe",
            tool_version=str(record.get("version") or PROBE_VERSION),
            source="probe",
            confidence=Confidence.HIGH,
            **extra,
        )

    if spec.get("type") == "http" and r.get("status") is not None:
        headers = [(str(k), str(v)) for k, v in r.get("headers") or []]
        try:
            body = base64.b64decode(r.get("body_base64") or "")
        except ValueError:
            body = b""
        ex = Exchange(
            url=str((r.get("request") or {}).get("url") or ""),
            connected_ip=str(record.get("connected_ip") or ""),
            status=int(r["status"]),
            headers=headers,
            body=body,
            body_truncated=bool(r.get("body_truncated")),
            elapsed_ms=int(r.get("elapsed_ms") or 0),
            tls=r.get("tls"),
            location=r.get("location"),
        )
        page = response_posture(ex)
        https = spec.get("scheme") == "https"
        audit = {
            "target": record.get("target"),
            "https": page if https else None,
            "http": None if https else page,
            "http_redirects_to_https": False,
        }
        return make(
            technologies=[t.as_dict() for t in fingerprint(headers, body)],
            posture={"headers": audit},
        )
    if spec.get("type") == "tls" and r.get("certificate"):
        validation = r.get("validation") or {}
        handshake_ = r.get("handshake") or {}
        accepted = [handshake_["version"]] if handshake_.get("result") == "accepted" else []
        return make(
            posture={
                "tls": {
                    "target": record.get("target"),
                    "validation": {
                        "result": validation.get("result"),
                        "detail": validation.get("detail"),
                    },
                    "accepted": accepted,
                    "certificate": r["certificate"],
                }
            },
        )
    return None
