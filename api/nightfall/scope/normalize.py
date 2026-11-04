"""Canonical forms for hostnames and IP addresses.

The same functions normalize scope entries, collection targets and discovered names, so
"in scope" and "same asset" can never disagree because of spelling (case, trailing dot,
Unicode vs punycode, IP notation).
"""

from __future__ import annotations

import ipaddress
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class NormalizationError(ValueError):
    pass


def hostname(value: str) -> str:
    """Lowercase, punycode, no trailing dot, valid DNS labels, at least two labels.
    Rejects IP literals, wildcards, ports, paths and anything else."""
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253:
        raise NormalizationError("Enter a hostname like app.example.com.")
    if _is_ip(v):
        raise NormalizationError("That's an IP address, not a hostname.")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError("That hostname isn't valid.") from exc
    labels = v.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise NormalizationError("Enter a hostname like app.example.com.")
    if labels[-1].isdigit():
        raise NormalizationError("That hostname isn't valid.")
    return v


def ip(value: str) -> IPAddress:
    """Strict parsing: rejects octal/hex/short forms ('0177.0.0.1', '127.1').
    IPv4-mapped IPv6 addresses are reduced to their IPv4 address."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise NormalizationError("Enter a valid IPv4 or IPv6 address.") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def network(value: str) -> IPNetwork:
    try:
        net = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise NormalizationError(
            "Enter a network like 192.0.2.0/24 (host bits must be zero)."
        ) from exc
    return net


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True
