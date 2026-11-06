"""Scope-enforcing HTTP client for low-risk probes (review §13, §16.3).

For each request:
  1. The hostname must already have passed the scope engine (caller's job).
  2. It is resolved once. Every resolved address is checked: none may be private,
     loopback, link-local, multicast, reserved, shared (CGNAT), or cloud-metadata, and
     none may match an IP/CIDR exclusion in the scope. If any fails, nothing is sent.
  3. The connection goes to that exact address, with the hostname as SNI and Host.
     Resolving once and connecting to the checked address defeats DNS rebinding.
  4. GET only, redirects are never followed (Location is recorded), 10 s timeout,
     response body capped, honest User-Agent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID

from nightfall.scope import normalize
from nightfall.scope.normalize import IPAddress

USER_AGENT = "JANUS/0.1 (authorized security assessment)"
TIMEOUT = 10.0
MAX_BODY = 512 * 1024
METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
Resolver = Callable[[str], list[str]]


class Refused(Exception):
    """The probe was not sent. The message is safe to show to users."""


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


def blocked_reason(addr: IPAddress) -> str | None:
    if addr in METADATA:
        return "cloud metadata address"
    for attr in (
        "is_loopback",
        "is_private",
        "is_link_local",
        "is_multicast",
        "is_reserved",
        "is_unspecified",
    ):
        if getattr(addr, attr):
            return attr.removeprefix("is_").replace("_", "-") + " address"
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return "shared (CGNAT) address"
    return None


@dataclass
class Exchange:
    url: str
    connected_ip: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    body_truncated: bool
    elapsed_ms: int
    tls: dict[str, Any] | None
    location: str | None


@dataclass
class SafeHttp:
    resolver: Resolver = system_resolver
    allow_private: bool = False  # tests only
    # Isolated lab worker: every address must be inside these networks (and nothing else
    # is allowed, private or public). Empty means the normal rules above.
    only_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    transport: httpx.BaseTransport | None = None
    https_port: int = 443  # overridable for tests only
    http_port: int = 80

    def pin(self, host: str) -> str:
        try:
            raw = self.resolver(host)
        except OSError as exc:
            raise Refused(f"{host} did not resolve.") from exc
        if not raw:
            raise Refused(f"{host} did not resolve.")
        addrs = [normalize.ip(a) for a in raw]
        for a in addrs:
            if any(a.version == n.version and a in n for n in self.excluded_networks):
                raise Refused(f"{host} resolves to {a}, which the scope excludes.")
            if self.only_networks:
                if not any(a.version == n.version and a in n for n in self.only_networks):
                    raise Refused(f"{host} resolves to {a}, which is outside the lab network.")
                continue
            if not self.allow_private and (why := blocked_reason(a)):
                raise Refused(f"{host} resolves to {a} ({why}); probes to it are blocked.")
        return str(addrs[0])

    def get(self, host: str, scheme: str, verify: bool) -> Exchange:
        return self.request(host, scheme, verify)

    def request(
        self,
        host: str,
        scheme: str,
        verify: bool,
        *,
        method: str = "GET",
        path: str = "/",
        port: int | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> Exchange:
        """One request to the pinned address. Host and User-Agent are always set here, so
        callers can't override them; redirects are never followed."""
        ip = self.pin(host)
        port = port or (self.https_port if scheme == "https" else self.http_port)
        netloc = f"[{ip}]" if ":" in ip else ip
        url = f"{scheme}://{netloc}:{port}{path}"
        ctx: ssl.SSLContext | bool = ssl.create_default_context() if verify else False
        started = time.monotonic()
        with httpx.Client(
            verify=ctx,
            timeout=TIMEOUT,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            req = client.build_request(
                method,
                url,
                headers={
                    "Accept": "*/*",
                    **(headers or {}),
                    "Host": host,
                    "User-Agent": USER_AGENT,
                },
                content=body,
                extensions={"sni_hostname": host},
            )
            resp = client.send(req, stream=True)
            try:
                tls = _tls_info(resp) if scheme == "https" else None
                chunks: list[bytes] = []
                size = 0
                truncated = False
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY:
                        chunks.append(chunk[: MAX_BODY - (size - len(chunk))])
                        truncated = True
                        break
                    chunks.append(chunk)
            finally:
                resp.close()
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        return Exchange(
            url=f"{scheme}://{host}{'' if default else f':{port}'}{path}",
            connected_ip=ip,
            status=resp.status_code,
            headers=[(k, v) for k, v in resp.headers.multi_items()],
            body=b"".join(chunks),
            body_truncated=truncated,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            tls=tls,
            location=resp.headers.get("location"),
        )


def _tls_info(resp: httpx.Response) -> dict[str, Any] | None:
    stream = resp.extensions.get("network_stream")
    sslobj = stream.get_extra_info("ssl_object") if stream is not None else None
    if sslobj is None:
        return None
    info: dict[str, Any] = {"version": sslobj.version(), "cipher": (sslobj.cipher() or ("",))[0]}
    der = sslobj.getpeercert(binary_form=True)
    if der:
        info.update(certificate_summary(der))
    return info


def certificate_summary(der: bytes) -> dict[str, Any]:
    """The fields NIGHTFALL keeps about a peer certificate (all public information)."""
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {
        "subject_cn": str(cn[0].value) if cn else None,
        "issuer_cn": str(issuer[0].value) if issuer else None,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sans": sans[:100],
        "sha256": hashlib.sha256(der).hexdigest(),
    }
