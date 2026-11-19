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
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import ActorType, ShieldHostChange, ShieldHostState, ShieldSensor
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.shield.sensors import FUTURE_SKEW, Sensor, sensor_router

Group = Literal["accounts", "admins", "ssh_keys", "listeners", "persistence", "software", "posture"]

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
}
KEYS: dict[str, tuple[str, ...]] = {
    "accounts": ("username", "uid"),
    "admins": ("groupname", "username"),
    "ssh_keys": ("username", "key_file", "key"),
    "listeners": ("path", "address", "port", "protocol"),
    "persistence": ("kind", "name", "path", "command_sha256"),
    "software": ("name", "version", "source"),
    "posture": ("check",),
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
    snapshots: Annotated[list[SnapshotIn], Field(min_length=1, max_length=7)]


class GroupResult(Model):
    group: str
    item_count: int
    added: int
    removed: int
    baseline: bool


def _apply(db: Session, sensor: ShieldSensor, snap: SnapshotIn, now: datetime) -> GroupResult:
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
                           baseline=True)  # fmt: skip
    if observed < state.observed_at:  # an older snapshot arriving late changes nothing
        return GroupResult(group=snap.group, item_count=state.item_count, added=0, removed=0,
                           baseline=False)  # fmt: skip
    before = {item_key(snap.group, it): it for it in state.items}
    added = [k for k in items if k not in before]
    removed = [k for k in before if k not in items]
    for action, keys, source in (("added", added, items), ("removed", removed, before)):
        for k in keys:
            db.add(
                ShieldHostChange(
                    workspace_id=sensor.workspace_id,
                    sensor_id=sensor.id,
                    grp=snap.group,
                    action=action,
                    item_key=k,
                    item=source[k],
                    observed_at=observed,
                    ingested_at=now,
                )  # fmt: skip
            )
    state.items, state.item_count = list(items.values()), len(items)
    state.observed_at, state.ingested_at, state.snapshot_at = observed, now, observed
    return GroupResult(group=snap.group, item_count=len(items), added=len(added),
                       removed=len(removed), baseline=False)  # fmt: skip


@sensor_router.post("/host", response_model=list[GroupResult])
def report_host(body: HostIn, db: DB, s: Sensor) -> list[GroupResult]:
    """Full snapshots from the osquery module. Returns what changed per group."""
    if len({x.group for x in body.snapshots}) != len(body.snapshots):
        raise api_error(422, "duplicate_group", "Send at most one snapshot per group.")
    now = utcnow()
    out = [_apply(db, s.sensor, snap, now) for snap in body.snapshots]
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
            r.group: {"items": r.item_count, "added": r.added, "removed": r.removed} for r in out
        },
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
    observed_at: datetime
    ingested_at: datetime


class PostureOut(Model):
    check: str
    ok: bool | None
    detail: str


class HostOut(Model):
    sensor_id: uuid.UUID
    sensor_name: str
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
    posture = next((st for st in states if st.grp == "posture"), None)
    return HostOut(
        sensor_id=s.id,
        sensor_name=s.name,
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
                observed_at=c.observed_at,
                ingested_at=c.ingested_at,
            )  # fmt: skip
            for c in changes
        ],
        retention_days=SHOW_CHANGES.days,
    )
