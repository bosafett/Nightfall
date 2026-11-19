"""SENTINEL step 3a: deterministic extraction of indicators and sightings from the detectors
(design docs/designs/2026-11-sentinel-indicator-store.md §3-5; migration 0028).

Called by the detectors in the same transaction as the row they write. A sighting points at that
row (kind and id) rather than copying it. Never an indicator: allow-listed addresses, any address
that isn't globally routable (private, CGNAT, documentation, loopback, link-local, reserved),
multicast, and address ranges, so
spoofed traffic can't get the owner's own addresses marked hostile. Computed confidence is low
on the first sighting and medium when repeated; it never becomes high here.

Analysis only: nothing in this module blocks, opens an incident, or changes a machine.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from nightfall.core.db.models import (
    SentinelSighting,
    ShieldBlock,
    ShieldHostAlert,
    ShieldHostChange,
    ShieldIntrusionAlert,
)
from nightfall.warpath.catalogue import techniques as attack_catalogue

# Owner decision 2: how long an indicator stays active after it was last seen (None: never expires).
TTL: dict[str, timedelta | None] = {
    "ip": timedelta(days=30),
    "domain": timedelta(days=90),
    "url": timedelta(days=90),
    "user_agent": timedelta(days=30),
    "sha256": None,
    "cert_sha256": None,
}

# Owner decision 5: the fixed, reviewed ATT&CK mapping (design §4).
INTRUSION_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "ssh_bruteforce": ("T1110", "T1021.004"),
    "http_bruteforce": ("T1110",),
    "web_scan": ("T1595",),
    "exploit_attempt": ("T1190",),
}
HOST_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "new_admin": ("T1098",),
    "new_account": ("T1136",),
    "new_ssh_key": ("T1098.004",),
}
PERSISTENCE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "systemd": ("T1543",),
    "service": ("T1543",),
    "cron": ("T1053",),
    "scheduled_task": ("T1053",),
    "startup_item": ("T1547",),
    "kernel_module": ("T1547.006",),
}


def check_mapping() -> None:
    """Every mapped technique exists in the pinned catalogue (run by the tests)."""
    known = attack_catalogue()
    for group in (INTRUSION_TECHNIQUES, HOST_TECHNIQUES, PERSISTENCE_TECHNIQUES):
        for ids in group.values():
            missing = [t for t in ids if t not in known]
            if missing:
                raise ValueError(f"techniques not in the pinned ATT&CK catalogue: {missing}")


def ip_value(db: Session, workspace_id: uuid.UUID, source: str) -> str | None:
    """The normalized address if it may become an indicator, else None."""
    try:
        net = ipaddress.ip_network(source, strict=True)
    except ValueError:
        return None
    if net.num_addresses != 1:
        return None
    addr = net.network_address
    if not addr.is_global or addr.is_multicast:  # private, CGNAT, documentation, loopback, ...
        return None
    from nightfall.shield.guard import allowlisted  # late: guard imports nothing from here

    if allowlisted(db, workspace_id, str(net)):
        return None
    return str(addr)


def record(
    db: Session,
    workspace_id: uuid.UUID,
    *,
    type_: str,
    value: str,
    source_kind: str,
    source_id: uuid.UUID,
    sensor_id: uuid.UUID | None,
    event_time: datetime,
    techniques: tuple[str, ...] = (),
) -> uuid.UUID:
    """Upsert the indicator (first/last seen, count, confidence, expiry) and add a sighting."""
    ttl = TTL[type_]
    indicator_id: uuid.UUID = db.execute(
        text(
            "INSERT INTO sentinel_indicators (workspace_id, type, value, first_seen, last_seen, "
            " sighting_count, computed_confidence, expires_at) "
            "VALUES (:w, :t, :v, :e, :e, 1, 'low', :x) "
            "ON CONFLICT (workspace_id, type, value) DO UPDATE SET "
            " first_seen = LEAST(sentinel_indicators.first_seen, EXCLUDED.first_seen), "
            " last_seen = GREATEST(sentinel_indicators.last_seen, EXCLUDED.last_seen), "
            " sighting_count = sentinel_indicators.sighting_count + 1, "
            " computed_confidence = 'medium', "
            " expires_at = CASE WHEN EXCLUDED.expires_at IS NULL THEN NULL "
            "   ELSE GREATEST(sentinel_indicators.expires_at, EXCLUDED.expires_at) END "
            "RETURNING id"
        ),
        {
            "w": workspace_id,
            "t": type_,
            "v": value,
            "e": event_time,
            "x": event_time + ttl if ttl else None,
        },  # fmt: skip
    ).scalar_one()
    db.add(
        SentinelSighting(
            workspace_id=workspace_id,
            indicator_id=indicator_id,
            source_kind=source_kind,
            source_id=source_id,
            sensor_id=sensor_id,
            techniques=list(techniques),
            event_time=event_time,
        )  # fmt: skip
    )
    return indicator_id


def from_intrusion_alert(db: Session, alert: ShieldIntrusionAlert) -> uuid.UUID | None:
    value = ip_value(db, alert.workspace_id, str(alert.source))
    if value is None:
        return None
    return record(
        db, alert.workspace_id, type_="ip", value=value, source_kind="intrusion_alert",
        source_id=alert.id, sensor_id=alert.sensor_id, event_time=alert.last_event_time,
        techniques=INTRUSION_TECHNIQUES.get(alert.category, ()),
    )  # fmt: skip


def from_block(db: Session, block: ShieldBlock) -> uuid.UUID | None:
    """A block is a response, not an observation: the target becomes an indicator, no tags."""
    value = ip_value(db, block.workspace_id, str(block.target))
    if value is None:
        return None
    return record(
        db, block.workspace_id, type_="ip", value=value, source_kind="block",
        source_id=block.id, sensor_id=block.sensor_id, event_time=block.created_at,
    )  # fmt: skip


def host_alert_techniques(
    alert: ShieldHostAlert, change: ShieldHostChange | None
) -> tuple[str, ...]:
    if alert.category == "new_persistence" and change is not None:
        return PERSISTENCE_TECHNIQUES.get(str(change.item.get("kind") or ""), ())
    return HOST_TECHNIQUES.get(alert.category, ())


def from_host_alert(db: Session, alert: ShieldHostAlert, change: ShieldHostChange | None) -> None:
    """Technique-only sighting: a host alert has no shared observable, but its technique lets an
    incident show the sequence (design §4)."""
    tags = host_alert_techniques(alert, change)
    if tags:
        db.add(
            SentinelSighting(
                workspace_id=alert.workspace_id,
                indicator_id=None,
                source_kind="host_alert",
                source_id=alert.id,
                sensor_id=alert.sensor_id,
                techniques=list(tags),
                event_time=alert.observed_at,
            )  # fmt: skip
        )


def from_host_change(db: Session, change: ShieldHostChange) -> uuid.UUID | None:
    """A watched file's new hash (files group, added or changed)."""
    if change.grp != "files" or change.action == "removed":
        return None
    sha = str(change.item.get("sha256") or "").lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        return None
    return record(
        db, change.workspace_id, type_="sha256", value=sha, source_kind="host_change",
        source_id=change.id, sensor_id=change.sensor_id, event_time=change.observed_at,
    )  # fmt: skip


def purge(db: Session) -> None:
    """Owner decision 3: one-year retention, this workspace only (fixed interval)."""
    db.execute(text("SELECT nf_purge_sentinel()"))
