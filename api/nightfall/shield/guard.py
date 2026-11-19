"""SHIELD v3 phase 2: GUARD, the automatic response tier (design
docs/designs/2026-11-shield-v3-intrusion-detection.md §4, §11.1; migration 0025).

Deterministic rules only, never AI. When a sensor reports an alert, `decide` either creates one
time-limited block of that single address on the sensor that saw it, or leaves the alert as
alert-only and says why. It blocks only when every one of these holds:

  * the alert's category is one GUARD acts on, it isn't simulated, and its source is a single
    public-routable address (never loopback, link-local, multicast, unspecified or reserved);
  * the kill switch is off;
  * a live standing response authorization covers this sensor and the block_ip action;
  * no live allow-list entry covers the address (refused, and recorded, if one does);
  * the address isn't already blocked on this sensor;
  * the sensor has had fewer than the authorization's per-hour cap of automatic blocks;
  * the trial week is over (migration 0030): the authorization's trial days, and a new rule's
    first week (NEW_RULES). Until then GUARD records what it would have blocked, and doesn't.

The database (nf_shield_block_guard) enforces the allow list and the authorization's limits
again, so a bug here can't create a violating block; the cap and kill switch are policy that
falls back to alert-only. AI agents have no path into this module.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.db.models import (
    ActorType,
    Severity,
    ShieldBlock,
    ShieldIntrusionAlert,
    ShieldResponseAuthorization,
    ShieldResponseSettings,
    ShieldSensor,
)

Category = str  # one of CATEGORIES (the database CHECK lists the same values)
CATEGORIES = ("ssh_bruteforce", "web_scan", "exploit_attempt", "http_bruteforce", "other")

# GUARD acts on these; "other" is always alert-only.
AUTO_CATEGORIES = frozenset({"ssh_bruteforce", "http_bruteforce", "exploit_attempt", "web_scan"})

# Safeguard 21: a category added to AUTO_CATEGORIES later goes here with the time it shipped,
# and stays alert-only for its first week everywhere, whatever the authorization says.
NEW_RULES: dict[Category, datetime] = {}
TRIAL = timedelta(days=7)

SEVERITY: dict[Category, Severity] = {
    "exploit_attempt": Severity.HIGH,
    "ssh_bruteforce": Severity.MEDIUM,
    "http_bruteforce": Severity.MEDIUM,
    "web_scan": Severity.LOW,
    "other": Severity.LOW,
}

# Matched against the CrowdSec scenario name (lower-cased), first match wins, so an ssh CVE is an
# exploit attempt and ssh-bf is matched before the generic -bf. Scenario names are sensor-supplied
# text: they only choose a category from this fixed list, nothing more.
_RULES: tuple[tuple[Category, tuple[str, ...]], ...] = (
    ("exploit_attempt", ("cve", "exploit", "backdoor", "sqli", "xss", "log4j", "traversal")),
    ("ssh_bruteforce", ("ssh-bf", "ssh-slow-bf", "ssh-cve", "ssh_bf", "sshd")),
    ("http_bruteforce", ("-bf", "_bf", "bruteforce", "brute-force")),
    ("web_scan", ("http-probing", "http-crawl", "sensitive-files", "bad-user-agent", "scan")),
)


def categorize(scenario: str) -> Category:
    s = scenario.lower()
    for category, needles in _RULES:
        if any(n in s for n in needles):
            return category
    return "other"


def never_block(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    """Addresses no tier may ever block, whatever the allow list says. None if blockable."""
    for attr, why in (
        ("is_loopback", "a loopback address"),
        ("is_unspecified", "the unspecified address"),
        ("is_multicast", "a multicast address"),
        ("is_link_local", "a link-local address"),
        ("is_reserved", "a reserved address"),
    ):
        if getattr(net.network_address, attr) or getattr(net.broadcast_address, attr):
            return f"{net} is {why} and is never blocked."
    return None


def single_address(source: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The /32 or /128 network for a single address ("a.b.c.d" or "a.b.c.d/32"), or None for a
    range or garbage."""
    try:
        net = ipaddress.ip_network(source, strict=True)
    except ValueError:
        return None
    return net if net.num_addresses == 1 else None


def live_authorization(
    db: Session, workspace_id: uuid.UUID, now: datetime
) -> ShieldResponseAuthorization | None:
    return db.scalar(
        select(ShieldResponseAuthorization).where(
            ShieldResponseAuthorization.workspace_id == workspace_id,
            ShieldResponseAuthorization.ended_at.is_(None),
            ShieldResponseAuthorization.expires_at > now,
        )
    )


def paused(db: Session, workspace_id: uuid.UUID) -> bool:
    return bool(
        db.scalar(
            select(ShieldResponseSettings.automatic_paused).where(
                ShieldResponseSettings.workspace_id == workspace_id
            )
        )
    )


def allowlisted(db: Session, workspace_id: uuid.UUID, target: str) -> bool:
    """Same test as the database trigger: a live entry that contains the target."""
    return bool(
        db.scalar(
            text(
                "SELECT EXISTS (SELECT 1 FROM shield_block_allowlist WHERE workspace_id = :w "
                "AND removed_at IS NULL AND cidr >>= CAST(:t AS cidr))"
            ),
            {"w": workspace_id, "t": target},
        )
    )


def active_block_covering(
    db: Session, sensor_id: uuid.UUID, target: str, now: datetime
) -> uuid.UUID | None:
    found: uuid.UUID | None = db.scalar(
        text(
            "SELECT id FROM shield_blocks WHERE sensor_id = :s AND lifted_at IS NULL "
            "AND removed_at IS NULL AND expires_at > :n AND target >>= CAST(:t AS cidr) LIMIT 1"
        ),
        {"s": sensor_id, "t": target, "n": now},
    )
    return found


def automatic_blocks_last_hour(db: Session, sensor_id: uuid.UUID, now: datetime) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(ShieldBlock)
            .where(
                ShieldBlock.sensor_id == sensor_id,
                ShieldBlock.tier == "automatic",
                ShieldBlock.created_at > now - timedelta(hours=1),
            )
        )
        or 0
    )


def trial_ends(auth: ShieldResponseAuthorization, category: Category) -> datetime:
    """When automatic blocks for this category start under this authorization."""
    ends = auth.authorized_at + timedelta(days=auth.trial_days)
    if category in NEW_RULES:
        ends = max(ends, NEW_RULES[category] + TRIAL)
    return ends


@dataclass
class Decision:
    outcome: str  # "blocked" | "already_blocked" | "alert_only" | "refused"
    reason: str
    block_id: uuid.UUID | None = None


def _audit(
    db: Session, sensor: ShieldSensor, action: str, alert: ShieldIntrusionAlert, **data: object
) -> None:
    record(
        db,
        action,
        actor_type=ActorType.SYSTEM,
        workspace_id=sensor.workspace_id,
        entity_type="shield_intrusion_alert",
        entity_id=alert.id,
        data={"sensor_id": str(sensor.id), "source": str(alert.source), **data},
    )


def decide(
    db: Session,
    sensor: ShieldSensor,
    alert: ShieldIntrusionAlert,
    *,
    simulated: bool,
    now: datetime,
) -> Decision:
    """GUARD for one alert. The caller holds a row lock on the sensor (serializes the cap)."""
    if alert.category not in AUTO_CATEGORIES:
        return Decision("alert_only", "GUARD doesn't act on this category.")
    if simulated:
        return Decision("alert_only", "CrowdSec marked this alert as simulated.")
    net = single_address(str(alert.source))
    if net is None:
        return Decision("alert_only", "The source is a range; only a person can block a range.")
    target = str(net)
    if why := never_block(net):
        _audit(db, sensor, "shield.guard.refused", alert, reason="never_block")
        return Decision("refused", why)
    if paused(db, sensor.workspace_id):
        return Decision("alert_only", "Automatic response is paused (kill switch).")
    auth = live_authorization(db, sensor.workspace_id, now)
    if auth is None:
        return Decision("alert_only", "No live response authorization.")
    if sensor.id not in auth.sensor_ids or "block_ip" not in auth.actions:
        return Decision("alert_only", "The response authorization doesn't cover this sensor.")
    if allowlisted(db, sensor.workspace_id, target):
        _audit(db, sensor, "shield.guard.refused", alert, reason="allowlisted")
        return Decision("refused", f"{target} is on the allow list; not blocked.")
    if existing := active_block_covering(db, sensor.id, target, now):
        return Decision("already_blocked", "Already blocked on this sensor.", existing)
    if automatic_blocks_last_hour(db, sensor.id, now) >= auth.per_hour_cap:
        _audit(db, sensor, "shield.guard.cap_reached", alert, cap=auth.per_hour_cap)
        return Decision(
            "alert_only",
            f"This sensor reached its cap of {auth.per_hour_cap} automatic blocks an hour.",
        )
    if now < (ends := trial_ends(auth, alert.category)):
        _audit(db, sensor, "shield.guard.trial", alert, target=target, trial_ends=ends.isoformat())
        return Decision(
            "alert_only",
            f"Trial week: GUARD would have blocked {target}. Automatic blocks start "
            f"{ends:%Y-%m-%d %H:%M} UTC.",
        )
    block = ShieldBlock(
        workspace_id=sensor.workspace_id,
        sensor_id=sensor.id,
        target=target,
        tier="automatic",
        action="block_ip",
        reason=f"GUARD: {alert.scenario}"[:1000],
        authorization_id=auth.id,
        alert_id=alert.id,
        created_at=now,
        expires_at=now + timedelta(seconds=auth.default_block_seconds),
    )
    try:
        with db.begin_nested():
            db.add(block)
            db.flush()
    except DBAPIError:  # the database guard refused it: never retry, alert instead
        _audit(db, sensor, "shield.guard.refused", alert, reason="database_guard")
        return Decision("refused", "The database refused the block (allow list or limits).")
    _audit(
        db,
        sensor,
        "shield.guard.blocked",
        alert,
        block_id=str(block.id),
        target=target,
        seconds=auth.default_block_seconds,
        authorization_id=str(auth.id),
    )
    return Decision("blocked", f"Blocked {target} on this sensor.", block.id)
