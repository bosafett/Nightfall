"""SHIELD v4 step 4a: host state from janus-sensor's osquery module (design
docs/designs/2026-11-shield-v4-host-network-monitoring.md §4-6; migration 0026).

The machine runs a fixed osquery pack (infra/janus-sensor/osquery/janus.conf) that writes full
snapshots of each group to its local results log. The sensor reads that file and sends the
latest snapshot per group. JANUS never sends a query, rule or command to the machine.

Each snapshot replaces the group's state. The difference from the previous snapshot is appended
to the change log; the first snapshot of a group is the baseline and logs nothing. One mechanism
(snapshots, diffed here) means a lost log line can't leave the state wrong or double-count.

Everything the sensor sends is untrusted data: only the columns this module lists per group are
kept, values are short scalars, and the group decides the item key. Detection only: nothing here
blocks or changes anything (GUARD is unchanged).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter
from pydantic import Field
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    Severity,
    ShieldHostAlert,
    ShieldHostChange,
    ShieldHostState,
    ShieldIntrusionAlert,
    ShieldSensor,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.shield import guard
from nightfall.shield.sensors import FUTURE_SKEW, Sensor, sensor_router

Group = Literal[
    "accounts", "admins", "ssh_keys", "listeners", "persistence", "software", "posture", "files"
]

# Columns kept per group (anything else the sensor sends is dropped), and which of them identify
# an item. These match the SELECTs of the fixed pack.
COLUMNS: dict[str, tuple[str, ...]] = {
    "accounts": ("username", "uid", "shell", "directory"),
    "admins": ("username", "groupname"),
    "ssh_keys": ("username", "key_file", "algorithm", "key"),
    "listeners": ("process", "path", "address", "port", "protocol"),
    "persistence": ("kind", "name", "path", "command_sha256"),
    "software": ("name", "version", "source"),
    "posture": ("check", "ok", "detail"),
    "files": ("path", "sha256"),
}
KEYS: dict[str, tuple[str, ...]] = {
    "accounts": ("username", "uid"),
    "admins": ("groupname", "username"),
    "ssh_keys": ("username", "key_file", "key"),
    "listeners": ("path", "address", "port", "protocol"),
    "persistence": ("kind", "name", "path", "command_sha256"),
    "software": ("name", "version", "source"),
    "posture": ("check",),
    "files": ("path",),
}
MAX_ITEMS = 5000
MAX_VALUE = 500
SHOW_CHANGES = timedelta(days=90)  # owner decision 4: the retention period

Scalar = str | int | float | bool | None


def clean(group: str, raw: dict[str, Any]) -> dict[str, Scalar]:
    """Only the group's columns, as short scalars."""
    out: dict[str, Scalar] = {}
    for col in COLUMNS[group]:
        v = raw.get(col)
        if isinstance(v, str):
            v = v[:MAX_VALUE]
        elif not isinstance(v, int | float | bool) and v is not None:
            v = str(v)[:MAX_VALUE]
        out[col] = v
    return out


def item_key(group: str, item: dict[str, Scalar]) -> str:
    """A stable, bounded key: sha256 of the group's key columns."""
    ident = json.dumps([item.get(c) for c in KEYS[group]], separators=(",", ":"), default=str)
    return hashlib.sha256(ident.encode()).hexdigest()


class SnapshotIn(Model):
    group: Group
    observed_at: datetime
    items: Annotated[list[dict[str, Any]], Field(max_length=MAX_ITEMS)]


class HostIn(Model):
    snapshots: Annotated[list[SnapshotIn], Field(min_length=1, max_length=len(COLUMNS))]


class GroupResult(Model):
    group: str
    item_count: int
    added: int
    removed: int
    changed: int = 0
    baseline: bool


def _apply(
    db: Session, sensor: ShieldSensor, snap: SnapshotIn, now: datetime
) -> tuple[GroupResult, list[ShieldHostChange]]:
    observed = min(snap.observed_at, now + FUTURE_SKEW)
    items = {item_key(snap.group, it): it for it in (clean(snap.group, r) for r in snap.items)}
    state = db.get(ShieldHostState, (sensor.id, snap.group))
    if state is None:
        db.add(
            ShieldHostState(
                workspace_id=sensor.workspace_id,
                sensor_id=sensor.id,
                grp=snap.group,
                items=list(items.values()),
                item_count=len(items),
                observed_at=observed,
                ingested_at=now,
                snapshot_at=observed,
            )  # fmt: skip
        )
        return GroupResult(group=snap.group, item_count=len(items), added=0, removed=0,
                           baseline=True), []  # fmt: skip
    if observed < state.observed_at:  # an older snapshot arriving late changes nothing
        return GroupResult(group=snap.group, item_count=state.item_count, added=0, removed=0,
                           baseline=False), []  # fmt: skip
    before = {item_key(snap.group, it): it for it in state.items}
    diff: list[tuple[str, str, dict[str, Scalar], dict[str, Scalar] | None]] = (
        [("added", k, items[k], None) for k in items if k not in before]
        + [("removed", k, before[k], None) for k in before if k not in items]
        + [("changed", k, items[k], before[k])
           for k in items if k in before and items[k] != before[k]]
    )  # fmt: skip
    changes = [
        ShieldHostChange(
            workspace_id=sensor.workspace_id,
            sensor_id=sensor.id,
            grp=snap.group,
            action=action,
            item_key=k,
            item=item,
            previous=prev,
            observed_at=observed,
            ingested_at=now,
        )  # fmt: skip
        for action, k, item, prev in diff
    ]
    db.add_all(changes)
    state.items, state.item_count = list(items.values()), len(items)
    state.observed_at, state.ingested_at, state.snapshot_at = observed, now, observed
    count = {a: sum(d[0] == a for d in diff) for a in ("added", "removed", "changed")}
    return GroupResult(group=snap.group, item_count=len(items), baseline=False, **count), changes


# --- Host alerts (step 4b) -----------------------------------------------------------------

CORRELATION_WINDOW = timedelta(hours=1)


def _v(item: dict[str, Scalar], col: str) -> str:
    v = item.get(col)
    return "" if v is None else str(v)


def alert_for(c: ShieldHostChange) -> tuple[str, Severity, str] | None:
    """The alert a host change raises, if any: category, severity, title. Fixed rules."""
    it, g, a = c.item, c.grp, c.action
    if g == "accounts" and a == "added":
        return "new_account", Severity.MEDIUM, f"New local account {_v(it, 'username')}"
    if g == "admins" and a == "added":
        return ("new_admin", Severity.HIGH,
                f"{_v(it, 'username')} added to {_v(it, 'groupname')}")  # fmt: skip
    if g == "ssh_keys" and a == "added":
        return ("new_ssh_key", Severity.HIGH,
                f"New SSH key for {_v(it, 'username')} ({_v(it, 'key_file')})")  # fmt: skip
    if g == "listeners" and a == "added":
        what = _v(it, "process") or _v(it, "path") or "unknown process"
        return ("new_listener", Severity.MEDIUM, f"{what} listening on "
                f"{_v(it, 'address')}:{_v(it, 'port')}/{_v(it, 'protocol')}")  # fmt: skip
    if g == "persistence" and a == "added":
        return ("new_persistence", Severity.MEDIUM,
                f"New {_v(it, 'kind').replace('_', ' ')}: {_v(it, 'name')}")  # fmt: skip
    if (
        g == "posture" and a == "changed" and c.previous is not None
        and _ok(c.previous.get("ok")) is True and _ok(it.get("ok")) is False
    ):  # fmt: skip
        check = _v(it, "check").replace("_", " ")
        return "posture_degraded", Severity.MEDIUM, f"{check} no longer OK: {_v(it, 'detail')}"
    if g == "files":
        verb = {"added": "appeared", "removed": "disappeared", "changed": "changed"}[a]
        return "file_changed", Severity.HIGH, f"Watched file {verb}: {_v(it, 'path')}"
    return None


def raise_alerts(
    db: Session, sensor: ShieldSensor, changes: list[ShieldHostChange], now: datetime
) -> list[ShieldHostAlert]:
    """One alert per security-relevant change. If an attack alert on the same machine was seen
    within the hour before, link it: a hypothesis (possible compromise), never a finding."""
    rules = [(c, r) for c in changes if (r := alert_for(c)) is not None]
    if not rules:
        return []
    earliest = min(c.observed_at for c, _ in rules) - CORRELATION_WINDOW
    attacks = db.execute(
        select(ShieldIntrusionAlert.id, ShieldIntrusionAlert.last_event_time)
        .where(
            ShieldIntrusionAlert.sensor_id == sensor.id,
            ShieldIntrusionAlert.category.in_(guard.AUTO_CATEGORIES),
            ShieldIntrusionAlert.last_event_time >= earliest,
        )
        .order_by(ShieldIntrusionAlert.last_event_time.desc())
    ).all()
    alerts = []
    for c, (category, severity, title) in rules:
        lo, hi = c.observed_at - CORRELATION_WINDOW, c.observed_at + FUTURE_SKEW
        hit = next((a.id for a in attacks if lo <= a.last_event_time <= hi), None)
        alerts.append(
            ShieldHostAlert(
                workspace_id=sensor.workspace_id,
                sensor_id=sensor.id,
                category=category,
                severity=severity,
                title=title[:300],
                change_id=c.id,
                correlated_alert_id=hit,
                observed_at=c.observed_at,
                created_at=now,
            )  # fmt: skip
        )
    db.add_all(alerts)
    return alerts


@sensor_router.post("/host", response_model=list[GroupResult])
def report_host(body: HostIn, db: DB, s: Sensor) -> list[GroupResult]:
    """Full snapshots from the osquery module. Returns what changed per group."""
    if len({x.group for x in body.snapshots}) != len(body.snapshots):
        raise api_error(422, "duplicate_group", "Send at most one snapshot per group.")
    now = utcnow()
    applied = [_apply(db, s.sensor, snap, now) for snap in body.snapshots]
    out = [r for r, _ in applied]
    db.flush()
    alerts = raise_alerts(db, s.sensor, [c for _, cs in applied for c in cs], now)
    db.flush()
    db.execute(text("SELECT nf_purge_host_changes(:s)"), {"s": s.sensor.id})
    record(
        db,
        "shield.sensor.host",
        actor_type=ActorType.SYSTEM,
        workspace_id=s.sensor.workspace_id,
        entity_type="shield_sensor",
        entity_id=s.sensor.id,
        data={
            "groups": {
                r.group: {
                    "items": r.item_count,
                    "added": r.added,
                    "removed": r.removed,
                    "changed": r.changed,
                }
                for r in out
            },
            "alerts": [str(a.id) for a in alerts],
            "correlated": sum(a.correlated_alert_id is not None for a in alerts),
        },  # fmt: skip
        ip=s.ip,
    )
    return out


# --- Workspace route ---------------------------------------------------------------------

router = APIRouter(prefix="/api/workspaces/{workspace_id}/shield", tags=["shield"])


class HostGroupOut(Model):
    group: str
    item_count: int
    observed_at: datetime
    ingested_at: datetime
    items: list[dict[str, Scalar]]


class HostChangeOut(Model):
    group: str
    action: str
    item: dict[str, Scalar]
    previous: dict[str, Scalar] | None
    observed_at: datetime
    ingested_at: datetime


class PostureOut(Model):
    check: str
    ok: bool | None
    detail: str


class HostAlertOut(Model):
    id: uuid.UUID
    category: str
    severity: str
    title: str
    observed_at: datetime
    created_at: datetime
    state: str
    acknowledged_at: datetime | None
    # A hypothesis, never a finding: an attack alert on this machine within the hour before.
    possible_compromise: bool
    correlated_alert_id: uuid.UUID | None


class HostOut(Model):
    sensor_id: uuid.UUID
    sensor_name: str
    alerts: list[HostAlertOut]  # open ones and the last 90 days
    groups: list[HostGroupOut]
    posture: list[PostureOut]
    changes: list[HostChangeOut]  # newest first, last 90 days, at most 500
    retention_days: int


def _ok(v: Scalar) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, int | float):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes"):
        return True
    if isinstance(v, str) and v.strip().lower() in ("0", "false", "no"):
        return False
    return None


@router.get("/sensors/{sensor_id}/host", response_model=HostOut)
def host(
    sensor_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> HostOut:
    s = db.get(ShieldSensor, sensor_id)
    if s is None or s.workspace_id != ctx.workspace_id:
        raise not_found("Sensor not found.")
    states = db.scalars(
        select(ShieldHostState)
        .where(ShieldHostState.sensor_id == s.id)
        .order_by(ShieldHostState.grp)
    ).all()
    changes = db.scalars(
        select(ShieldHostChange)
        .where(
            ShieldHostChange.sensor_id == s.id,
            ShieldHostChange.ingested_at > utcnow() - SHOW_CHANGES,
        )  # fmt: skip
        .order_by(ShieldHostChange.ingested_at.desc())
        .limit(500)
    ).all()
    alerts = db.scalars(
        select(ShieldHostAlert)
        .where(
            ShieldHostAlert.sensor_id == s.id,
            or_(
                ShieldHostAlert.state == "open",
                ShieldHostAlert.created_at > utcnow() - SHOW_CHANGES,
            ),
        )  # fmt: skip
        .order_by(ShieldHostAlert.created_at.desc())
        .limit(500)
    ).all()
    posture = next((st for st in states if st.grp == "posture"), None)
    return HostOut(
        sensor_id=s.id,
        sensor_name=s.name,
        alerts=[
            HostAlertOut(
                id=a.id,
                category=a.category,
                severity=a.severity.value,
                title=a.title,
                observed_at=a.observed_at,
                created_at=a.created_at,
                state=a.state,
                acknowledged_at=a.acknowledged_at,
                possible_compromise=a.correlated_alert_id is not None,
                correlated_alert_id=a.correlated_alert_id,
            )  # fmt: skip
            for a in alerts
        ],
        groups=[
            HostGroupOut(
                group=st.grp,
                item_count=st.item_count,
                observed_at=st.observed_at,
                ingested_at=st.ingested_at,
                items=st.items,
            )  # fmt: skip
            for st in states
            if st.grp != "posture"
        ],
        posture=[
            PostureOut(
                check=str(p.get("check") or "?"),
                ok=_ok(p.get("ok")),
                detail=str(p.get("detail") or ""),
            )  # fmt: skip
            for p in (posture.items if posture else [])
        ],
        changes=[
            HostChangeOut(
                group=c.grp,
                action=c.action,
                item=c.item,
                previous=c.previous,
                observed_at=c.observed_at,
                ingested_at=c.ingested_at,
            )  # fmt: skip
            for c in changes
        ],
        retention_days=SHOW_CHANGES.days,
    )


@router.post("/host-alerts/{alert_id}/{action}", status_code=204)
def update_host_alert(
    alert_id: uuid.UUID,
    action: Literal["acknowledge", "resolve"],
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> None:
    a = db.get(ShieldHostAlert, alert_id)
    if a is None or a.workspace_id != ctx.workspace_id:
        raise not_found("Host alert not found.")
    target = "acknowledged" if action == "acknowledge" else "resolved"
    if a.state == target or a.state == "resolved":
        return
    a.state = target
    a.acknowledged_at = a.acknowledged_at or utcnow()
    db.flush()
    record(db, f"shield.host_alert.{target}", entity_type="shield_host_alert", entity_id=a.id,
           data={"category": a.category}, **ctx.audit_kwargs())  # fmt: skip
