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
import re
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import insert, text
from sqlalchemy.orm import Session

from nightfall.core.db.models import (
    Alert,
    IncidentEntry,
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
    # A Core insert (no RETURNING): the worker role may add sightings but not read them back.
    db.execute(
        insert(SentinelSighting).values(
            id=uuid.uuid4(),  # given, so the primary key isn't read back either
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


# --- Step 3c: normalization, AEGIS alerts and indicators a person enters ----------------------

TYPES = tuple(TTL)
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def domain_value(name: str) -> str | None:
    """Lower case, no trailing dot, no leading wildcard; None if it isn't a host name."""
    n = name.strip().lower().rstrip(".")
    n = n.removeprefix("*.")
    labels = n.split(".")
    if len(n) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    return n if all(_LABEL.match(x) for x in labels) else None


def sha256_value(value: str) -> str | None:
    v = value.strip().lower().replace(":", "")
    return v if _HEX64.match(v) else None


def url_value(value: str) -> str | None:
    """Scheme, host (and port), path; query, fragment and credentials dropped (design §3)."""
    try:
        u = urlsplit(value.strip())
        port = u.port
    except ValueError:
        return None
    if u.scheme.lower() not in ("http", "https") or not u.hostname:
        return None
    host = u.hostname.lower()
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        if domain_value(host) is None:
            return None
    out = f"{u.scheme.lower()}://{host}{f':{port}' if port else ''}{u.path or '/'}"
    return out if len(out) <= 2048 else None


def user_agent_value(value: str) -> str | None:
    v = " ".join(value.split())
    return v if 0 < len(v) <= 300 and v.isprintable() else None


def entered_value(db: Session, workspace_id: uuid.UUID, type_: str, raw: str) -> str:
    """Normalize an indicator a person entered. A person may add a private address by hand
    (design §3), but not one on the SHIELD allow list, a range, loopback or multicast."""
    if type_ == "ip":
        try:
            addr = ipaddress.ip_address(raw.strip())
        except ValueError as exc:
            raise ValueError("Enter a single IP address, not a range.") from exc
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            raise ValueError("Loopback, multicast and unspecified addresses can't be indicators.")
        from nightfall.shield.guard import allowlisted

        if allowlisted(db, workspace_id, str(addr)):
            raise ValueError("That address is on the SHIELD allow list.")
        return str(addr)
    value = {
        "domain": domain_value,
        "url": url_value,
        "sha256": sha256_value,
        "cert_sha256": sha256_value,
        "user_agent": user_agent_value,
    }[type_](raw)
    if value is None:
        raise ValueError(f"That isn't a valid {type_.replace('_', ' ')}.")
    return value


def from_aegis_alert(db: Session, alert: Alert) -> None:
    """A new AEGIS alert: a changed certificate gives its fingerprint; certificate-log and DNS
    changes give the names outside the authorized scope (names in scope are the owner's own)."""
    data = alert.data or {}
    found: list[tuple[str, str]] = []
    if alert.kind == "cert.changed":
        sha = sha256_value(str(data.get("cert_sha256") or ""))
        if sha:
            found.append(("cert_sha256", sha))
    elif alert.kind in ("ct.new_names", "dns.changed"):
        names = {domain_value(str(n)) for n in (data.get("outside_scope") or [])[:50]}
        found += [("domain", n) for n in sorted(x for x in names if x)]
    for type_, value in found:
        record(
            db, alert.workspace_id, type_=type_, value=value, source_kind="aegis_alert",
            source_id=alert.id, sensor_id=None, event_time=alert.first_seen_at,
        )  # fmt: skip


def from_incident_entry(
    db: Session, entry: IncidentEntry, type_: str, value: str, event_time: datetime
) -> uuid.UUID:
    return record(
        db, entry.workspace_id, type_=type_, value=value, source_kind="incident_entry",
        source_id=entry.id, sensor_id=None, event_time=event_time,
    )  # fmt: skip


def purge(db: Session) -> None:
    """Owner decision 3: one-year retention, this workspace only (fixed interval)."""
    db.execute(text("SELECT nf_purge_sentinel()"))
