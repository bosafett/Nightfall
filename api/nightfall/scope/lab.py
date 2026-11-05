"""Isolated lab rules (Phase 6b, review §16.5).

A lab scope may name only IP addresses and ranges inside the configured lab networks; a
normal scope may never name them. Hostnames aren't allowed in lab scopes: they would be
resolved on the lab machine, where this API can't check them. The same networks bound
what the lab worker may contact at run time (SafeHttp.only_networks), so a lab scope can
never authorize an outside target, and a normal scope can never reach into the lab.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from nightfall.core.db.models import ScopeEntryKind

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _describe(networks: Iterable[Network]) -> str:
    return ", ".join(str(n) for n in networks)


def entry_problem(
    kind: ScopeEntryKind, value: str, is_lab: bool, networks: tuple[Network, ...]
) -> str | None:
    """None when the (normalized) entry fits the scope type, else the reason it doesn't."""
    net: Network | None = None
    if kind in (ScopeEntryKind.IP, ScopeEntryKind.CIDR):
        net = ipaddress.ip_network(value, strict=False)
    inside = net is not None and any(
        net.version == n.version and net.subnet_of(n)  # type: ignore[arg-type]
        for n in networks
    )
    if is_lab:
        if net is None:
            return (
                "Lab scopes can only name IP addresses or ranges inside the lab network "
                f"({_describe(networks)}), not hostnames."
            )
        if not inside:
            return f"{value} is outside the lab network ({_describe(networks)})."
        return None
    if net is not None and any(net.version == n.version and net.overlaps(n) for n in networks):
        return f"{value} is in the isolated lab network; it can only be used in a lab scope."
    return None
