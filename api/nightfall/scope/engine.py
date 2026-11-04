"""Scope evaluation. Pure functions over a snapshot of one scope version.

Rules:
  * A target is allowed only if it matches at least one target entry and no exclusion.
    Exclusions always win.
  * host        matches exactly that hostname.
  * domain_tree matches the domain itself and any subdomain at any depth, on label
    boundaries (example.com matches a.b.example.com, never badexample.com).
  * ip / cidr   match IP targets only. Hostnames are never matched by IP entries.
  * Hostname targets are never matched by IP entries and vice versa; resolving a name to
    check its addresses is the job of active tools (not used by passive collection).
  * The scope must be active and inside its validity window.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from nightfall.core.db.models import ScopeEntryKind, ScopeStatus
from nightfall.scope import normalize
from nightfall.scope.normalize import IPAddress, NormalizationError


@dataclass(frozen=True)
class Entry:
    kind: ScopeEntryKind
    value: str


@dataclass(frozen=True)
class ScopeSnapshot:
    status: ScopeStatus
    valid_from: datetime | None
    valid_until: datetime | None
    targets: tuple[Entry, ...]
    exclusions: tuple[Entry, ...]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    target: str  # normalized form (or the raw input if it couldn't be normalized)
    matched: Entry | None = None


def normalize_entry(kind: ScopeEntryKind, value: str) -> str:
    """Canonical stored value for a scope entry (raises NormalizationError)."""
    if kind in (ScopeEntryKind.HOST, ScopeEntryKind.DOMAIN_TREE):
        return normalize.hostname(value)
    if kind is ScopeEntryKind.IP:
        return str(normalize.ip(value))
    return str(normalize.network(value))


def _matches(entry: Entry, host: str | None, addr: IPAddress | None) -> bool:
    if host is not None:
        if entry.kind is ScopeEntryKind.HOST:
            return host == entry.value
        if entry.kind is ScopeEntryKind.DOMAIN_TREE:
            return host == entry.value or host.endswith("." + entry.value)
        return False
    if addr is None:
        return False
    if entry.kind is ScopeEntryKind.IP:
        return addr == normalize.ip(entry.value)
    if entry.kind is ScopeEntryKind.CIDR:
        net = normalize.network(entry.value)
        return addr.version == net.version and addr in net
    return False


def parse_target(value: str) -> tuple[str | None, IPAddress | None]:
    """Hostname or IP literal → (host, None) or (None, ip)."""
    try:
        return None, normalize.ip(value)
    except NormalizationError:
        return normalize.hostname(value), None


def evaluate(scope: ScopeSnapshot | None, target: str, now: datetime) -> Decision:
    try:
        host, addr = parse_target(target)
    except NormalizationError as exc:
        return Decision(False, str(exc), target)
    canonical = host if host is not None else str(addr)

    if scope is None:
        return Decision(False, "This project has no authorized scope.", canonical)
    if scope.status is not ScopeStatus.ACTIVE:
        return Decision(False, "The scope version isn't authorized.", canonical)
    if scope.valid_from is not None and now < scope.valid_from:
        return Decision(False, "The scope's authorization period hasn't started.", canonical)
    if scope.valid_until is not None and now >= scope.valid_until:
        return Decision(False, "The scope's authorization period has ended.", canonical)

    for ex in scope.exclusions:
        if _matches(ex, host, addr):
            return Decision(False, f"Excluded by scope: {ex.value}", canonical, ex)
    for entry in scope.targets:
        if _matches(entry, host, addr):
            return Decision(True, "In scope.", canonical, entry)
    return Decision(False, "Not in the authorized scope.", canonical)
