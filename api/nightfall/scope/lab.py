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


# --- Lab worker start-up check (authorization review finding F4) ------------------------


def connected_networks(route_table: str) -> tuple[dict[ipaddress.IPv4Network, str], set[str]]:
    """Parses /proc/net/route: directly connected IPv4 networks (no gateway) and their
    interfaces, plus the interfaces that carry a default route."""
    connected: dict[ipaddress.IPv4Network, str] = {}
    default_ifaces: set[str] = set()

    def addr(hexle: str) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(hexle), "little"))

    for line in route_table.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        iface, dest, gateway, mask = f[0], f[1], f[2], f[7]
        if dest == "00000000":
            default_ifaces.add(iface)
        elif gateway == "00000000":
            net = ipaddress.IPv4Network(f"{addr(dest)}/{addr(mask)}", strict=False)
            connected[net] = iface
    return connected, default_ifaces


def lab_network_problem(networks: tuple[Network, ...], route_table: str) -> str | None:
    """None when every configured lab network is exactly a network this machine is
    directly attached to, and none is the network that leads out (the default route's).
    Otherwise the reason the lab worker must not start: a mistyped or widened range could
    otherwise cover the owner's home network or the uplink."""
    connected, default_ifaces = connected_networks(route_table)
    for n in networks:
        iface = connected.get(n) if isinstance(n, ipaddress.IPv4Network) else None
        if iface is None:
            attached = ", ".join(str(c) for c in connected) or "none"
            return (
                f"Lab network {n} isn't a network this lab worker is attached to "
                f"(attached: {attached}). NIGHTFALL_LAB_NETWORKS must be exactly the lab-net "
                "subnet in infra/lab/compose.yml."
            )
        if iface in default_ifaces:
            return f"Lab network {n} is on the interface that leads out ({iface}); refusing."
    return None


# Authorization review finding F5: a lab approval is only good for this long. A lab job
# that waits longer (e.g. the lab machine was off) is refused and must be approved again.
LAB_APPROVAL_TTL_HOURS = 24
