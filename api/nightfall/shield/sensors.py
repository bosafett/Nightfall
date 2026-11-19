"""SHIELD v3 phase 2: CrowdSec sensors and the response tiers (design
docs/designs/2026-11-shield-v3-intrusion-detection.md §3-4, §6; migration 0025).

Two routers:

* `sensor_router` (/api/sensor/...): called only by janus-sensor on the owner's machine,
  authenticated by the sensor's own key (`Authorization: Bearer nfs_...`), never by a cookie.
  The sensor sends a heartbeat and alerts, fetches the blocks JANUS decided for its machine,
  and reports what it applied or removed. JANUS never connects to the machine, and nothing
  here runs anything there: a block is data (an address and an expiry) that the sensor turns
  into a CrowdSec decision. Alert content is untrusted data, never instructions.
* `router` (/api/workspaces/{id}/shield/...): the Intrusion Detection page.

Who may do what (anything that makes JANUS block more, or blinds it, needs the owner with a
fresh two-factor check; anything that makes it block less is fail-safe and open to admins):

  owner + fresh 2FA   register or revoke a sensor; record a response authorization; resume
                      automatic response; remove an allow-list entry
  admin + fresh 2FA   approve a block (the person-approved tier)
  admin               pause automatic response (kill switch); end the response authorization;
                      add an allow-list entry; lift a block
  analyst             acknowledge or resolve an intrusion alert
  any member          read
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import Field, StringConstraints, field_validator
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    ShieldBlock,
    ShieldBlockAllowlistEntry,
    ShieldHostAlert,
    ShieldIntrusionAlert,
    ShieldResponseAuthorization,
    ShieldResponseSettings,
    ShieldSensor,
    User,
)
from nightfall.core.db.session import DB, set_workspace_context
from nightfall.core.errors import api_error, not_found
from nightfall.core.identity.security import hash_token, new_token
from nightfall.core.request_info import client_ip
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.shield import guard

KEY_PREFIX = "nfs_"
SENSOR_OFFLINE = timedelta(minutes=5)
POLL_SECONDS = 30
MAX_ALERTS_PER_BATCH = 100
MAX_RAW_BYTES = 8192
# Person-approved blocks: longer than GUARD's 4 hours, but never open-ended or wider than this.
APPROVED_MAX_SECONDS = 7 * 24 * 3600
APPROVED_MIN_PREFIX = {4: 16, 6: 32}
FUTURE_SKEW = timedelta(minutes=5)

Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]


def _net(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Not an IP address or CIDR range.") from exc


# --- Sensor authentication ------------------------------------------------------------------


@dataclass
class SensorContext:
    sensor: ShieldSensor
    ip: str


def sensor_auth(request: Request, db: DB) -> SensorContext:
    """The sensor's key, looked up by hash through nf_sensor_authenticate (live sensors only).
    Every failure is the same 401, so a caller learns nothing about which keys exist."""
    header = request.headers.get("authorization", "")
    scheme, _, key = header.partition(" ")
    if not hmac.compare_digest(scheme.lower().encode(), b"bearer") or not key.startswith(
        KEY_PREFIX
    ):
        raise api_error(401, "sensor_unauthorized", "Sensor key missing or not valid.")
    row = db.execute(
        text("SELECT sensor_id, workspace_id FROM nf_sensor_authenticate(:h)"),
        {"h": hash_token(key.strip())},
    ).one_or_none()
    if row is None:
        raise api_error(401, "sensor_unauthorized", "Sensor key missing or not valid.")
    set_workspace_context(db, row.workspace_id)
    # The row lock serializes this sensor's requests, so GUARD's per-hour cap can't be raced.
    sensor = db.scalar(
        select(ShieldSensor).where(ShieldSensor.id == row.sensor_id).with_for_update()
    )
    if sensor is None or sensor.revoked_at is not None:
        raise api_error(401, "sensor_unauthorized", "Sensor key missing or not valid.")
    sensor.last_seen_at = utcnow()
    return SensorContext(sensor=sensor, ip=client_ip(request))


sensor_auth._nf_authz = True  # type: ignore[attr-defined]  # marker checked by tests
Sensor = Annotated[SensorContext, Depends(sensor_auth, scope="function")]
sensor_router = APIRouter(prefix="/api/sensor", tags=["shield-sensor"])


def _sensor_audit(db: Session, s: SensorContext, action: str, **data: Any) -> None:
    record(
        db,
        action,
        actor_type=ActorType.SYSTEM,
        workspace_id=s.sensor.workspace_id,
        entity_type="shield_sensor",
        entity_id=s.sensor.id,
        data=data,
        ip=s.ip,
    )


class HeartbeatIn(Model):
    agent_version: Annotated[str, StringConstraints(strip_whitespace=True, max_length=40)] = ""


class HeartbeatOut(Model):
    sensor_id: uuid.UUID
    name: str
    automatic: bool  # GUARD would block for this sensor right now
    poll_seconds: int


class SensorAlertIn(Model):
    ref: Annotated[str, StringConstraints(max_length=64)] = ""  # the sensor's own alert id
    scenario: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    source: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]
    events_count: int = Field(1, ge=1, le=1_000_000)
    start_at: datetime
    stop_at: datetime | None = None
    simulated: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        return str(_net(v))

    @field_validator("raw")
    @classmethod
    def _raw(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v, default=str)) > MAX_RAW_BYTES:
            raise ValueError(f"raw is limited to {MAX_RAW_BYTES} bytes.")
        return v


class AlertsIn(Model):
    alerts: Annotated[list[SensorAlertIn], Field(min_length=1, max_length=MAX_ALERTS_PER_BATCH)]


class AlertResult(Model):
    ref: str
    alert_id: uuid.UUID
    outcome: str  # blocked | already_blocked | alert_only | refused
    reason: str
    block_id: uuid.UUID | None


class SensorBlockOut(Model):
    id: uuid.UUID
    target: str
    expires_at: datetime
    seconds_left: int
    applied: bool


class DecisionsOut(Model):
    apply: list[SensorBlockOut]  # every live block for this machine (applied or not)
    remove: list[SensorBlockOut]  # lifted by a person, applied, not yet reported removed


class RefusedIn(Model):
    id: uuid.UUID
    reason: Annotated[str, StringConstraints(max_length=300)]


class SensorReportIn(Model):
    applied: Annotated[list[uuid.UUID], Field(max_length=500)] = []
    removed: Annotated[list[uuid.UUID], Field(max_length=500)] = []
    refused: Annotated[list[RefusedIn], Field(max_length=500)] = []


class SensorReportOut(Model):
    applied: int
    removed: int
    refused: int


def _guard_live_for(db: Session, sensor: ShieldSensor, now: datetime) -> bool:
    auth = guard.live_authorization(db, sensor.workspace_id, now)
    return (
        auth is not None
        and sensor.id in auth.sensor_ids
        and not guard.paused(db, sensor.workspace_id)
    )


@sensor_router.post("/heartbeat", response_model=HeartbeatOut)
def heartbeat(body: HeartbeatIn, db: DB, s: Sensor) -> HeartbeatOut:
    s.sensor.agent_version = body.agent_version
    return HeartbeatOut(
        sensor_id=s.sensor.id,
        name=s.sensor.name,
        automatic=_guard_live_for(db, s.sensor, utcnow()),
        poll_seconds=POLL_SECONDS,
    )


def _ingest(
    db: Session, sensor: ShieldSensor, a: SensorAlertIn, now: datetime
) -> ShieldIntrusionAlert:
    category = guard.categorize(a.scenario)
    severity = guard.SEVERITY[category]
    start = min(a.start_at, now + FUTURE_SKEW)
    stop = max(start, min(a.stop_at or a.start_at, now + FUTURE_SKEW))
    raw = {"ref": a.ref, "scenario": a.scenario, "events_count": a.events_count, **a.raw}
    existing = db.scalar(
        select(ShieldIntrusionAlert).where(
            ShieldIntrusionAlert.sensor_id == sensor.id,
            ShieldIntrusionAlert.source == a.source,
            ShieldIntrusionAlert.category == category,
            ShieldIntrusionAlert.state == "open",
        )
    )
    if existing is not None:
        existing.count = min(existing.count + a.events_count, 2_000_000_000)
        existing.last_event_time = max(existing.last_event_time, stop)
        existing.scenario = a.scenario
        existing.raw = raw
        return existing
    alert = ShieldIntrusionAlert(
        workspace_id=sensor.workspace_id,
        sensor_id=sensor.id,
        scenario=a.scenario,
        category=category,
        severity=severity,
        source=a.source,
        count=a.events_count,
        event_time=start,
        last_event_time=stop,
        ingested_at=now,
        raw=raw,
    )
    db.add(alert)
    db.flush()
    return alert


@sensor_router.post("/alerts", response_model=list[AlertResult])
def report_alerts(body: AlertsIn, db: DB, s: Sensor) -> list[AlertResult]:
    """Record each alert, then let GUARD decide. Returns what was done for each."""
    now = utcnow()
    out = []
    for a in body.alerts:
        alert = _ingest(db, s.sensor, a, now)
        d = guard.decide(db, s.sensor, alert, simulated=a.simulated, now=now)
        out.append(
            AlertResult(
                ref=a.ref,
                alert_id=alert.id,
                outcome=d.outcome,
                reason=d.reason,
                block_id=d.block_id,
            )  # fmt: skip
        )
    _sensor_audit(
        db,
        s,
        "shield.sensor.alerts",
        received=len(body.alerts),
        blocked=sum(r.outcome == "blocked" for r in out),
    )
    return out


def _sensor_block(b: ShieldBlock, now: datetime) -> SensorBlockOut:
    return SensorBlockOut(
        id=b.id,
        target=str(b.target),
        expires_at=b.expires_at,
        seconds_left=max(0, int((b.expires_at - now).total_seconds())),
        applied=b.applied_at is not None,
    )


@sensor_router.get("/decisions", response_model=DecisionsOut)
def decisions(db: DB, s: Sensor) -> DecisionsOut:
    now = utcnow()
    mine = select(ShieldBlock).where(
        ShieldBlock.sensor_id == s.sensor.id,
        ShieldBlock.removed_at.is_(None),
        ShieldBlock.expires_at > now,
    )
    apply = db.scalars(mine.where(ShieldBlock.lifted_at.is_(None)).limit(1000)).all()
    remove = db.scalars(
        mine.where(ShieldBlock.lifted_at.is_not(None), ShieldBlock.applied_at.is_not(None))
    ).all()
    return DecisionsOut(
        apply=[_sensor_block(b, now) for b in apply],
        remove=[_sensor_block(b, now) for b in remove],
    )


@sensor_router.post("/decisions/report", response_model=SensorReportOut)
def report_decisions(body: SensorReportIn, db: DB, s: Sensor) -> SensorReportOut:
    """What the sensor actually did. Ids of other sensors' blocks are ignored."""
    now = utcnow()
    ids = set(body.applied) | set(body.removed) | {r.id for r in body.refused}
    rows = {
        b.id: b
        for b in db.scalars(
            select(ShieldBlock).where(
                ShieldBlock.id.in_(ids), ShieldBlock.sensor_id == s.sensor.id
            )
        )
    } if ids else {}  # fmt: skip
    applied = removed = 0
    for i in body.applied:
        if (b := rows.get(i)) is not None and b.applied_at is None:
            b.applied_at = now
            applied += 1
    for i in body.removed:
        if (b := rows.get(i)) is not None and b.removed_at is None:
            b.removed_at = now
            removed += 1
    refused = [r for r in body.refused if r.id in rows]
    for r in refused:
        _sensor_audit(db, s, "shield.sensor.block_refused", block_id=str(r.id), reason=r.reason)
    if applied or removed:
        _sensor_audit(db, s, "shield.sensor.decisions", applied=applied, removed=removed)
    return SensorReportOut(applied=applied, removed=removed, refused=len(refused))


# --- Workspace routes (Intrusion Detection page) -------------------------------------------

router = APIRouter(prefix="/api/workspaces/{workspace_id}/shield", tags=["shield"])
OWNER = Permission.MONITORS_MANAGE  # owner only
ADMIN = Permission.INCIDENTS_MANAGE  # owner and admins


class SensorOut(Model):
    id: uuid.UUID
    name: str
    key_prefix: str
    created_by: str
    created_at: datetime
    last_seen_at: datetime | None
    online: bool
    agent_version: str
    revoked_at: datetime | None
    revoked_reason: str
    open_host_alerts: int = 0  # SHIELD v4: alerts from this machine's host state


class SensorCreatedOut(SensorOut):
    key: str  # shown once; only its hash is stored


class SensorIn(Model):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class RevokeIn(Model):
    reason: Reason


class ResponseAuthorizationIn(Model):
    sensor_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=50)]
    max_block_seconds: int = Field(3600, ge=60, le=14400)
    default_block_seconds: int = Field(3600, ge=60, le=14400)
    per_hour_cap: int = Field(50, ge=1, le=1000)
    days: int = Field(90, ge=1, le=90)


class ResponseAuthorizationOut(Model):
    id: uuid.UUID
    sensor_ids: list[uuid.UUID]
    actions: list[str]
    max_block_seconds: int
    default_block_seconds: int
    per_hour_cap: int
    authorized_by: str
    authorized_at: datetime
    expires_at: datetime
    ended_at: datetime | None
    ended_reason: str | None
    live: bool


class SettingsOut(Model):
    automatic_paused: bool
    paused_by: str | None
    paused_at: datetime | None
    pause_reason: str


class PauseIn(Model):
    reason: Reason


class AllowlistIn(Model):
    cidr: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    note: Note = ""

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return str(_net(v))


class AllowlistOut(Model):
    id: uuid.UUID
    cidr: str
    note: str
    added_by: str
    added_at: datetime


class BlockIn(Model):
    target: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    sensor_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=50)]
    seconds: int = Field(3600, ge=60, le=APPROVED_MAX_SECONDS)
    reason: Reason
    alert_id: uuid.UUID | None = None

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        net = _net(v)
        if net.prefixlen < APPROVED_MIN_PREFIX[net.version]:
            raise ValueError(
                f"Ranges wider than /{APPROVED_MIN_PREFIX[net.version]} can't be blocked."
            )
        return str(net)


class BlockOut(Model):
    id: uuid.UUID
    sensor_id: uuid.UUID
    sensor_name: str
    target: str
    tier: str
    reason: str
    approved_by: str | None
    alert_id: uuid.UUID | None
    created_at: datetime
    expires_at: datetime
    applied_at: datetime | None
    removed_at: datetime | None
    lifted_at: datetime | None
    lifted_by: str | None
    lifted_reason: str
    status: Literal["pending", "active", "lifting", "lifted", "expired"]


class IntrusionAlertOut(Model):
    id: uuid.UUID
    sensor_id: uuid.UUID
    sensor_name: str
    scenario: str
    category: str
    severity: str
    source: str
    count: int
    event_time: datetime
    last_event_time: datetime
    ingested_at: datetime
    state: str
    acknowledged_at: datetime | None
    block_ids: list[uuid.UUID]


class IntrusionOut(Model):
    generated_at: datetime
    sensors: list[SensorOut]
    authorization: ResponseAuthorizationOut | None  # the live one, if any
    settings: SettingsOut
    automatic_active: bool  # a live authorization and the kill switch off
    allowlist: list[AllowlistOut]
    blocks: list[BlockOut]  # live ones and the last 7 days
    alerts: list[IntrusionAlertOut]  # open ones and the last 7 days
    blocks_24h: int
    sensors_offline: int
    approved_max_seconds: int
    host_alerts_open: int  # SHIELD v4, all sensors


class _Names:
    """Email for user ids, loaded once per request."""

    def __init__(self, db: Session) -> None:
        self.db, self.cache = db, dict[uuid.UUID, str]()

    def __call__(self, uid: uuid.UUID | None) -> str | None:
        if uid is None:
            return None
        if uid not in self.cache:
            self.cache[uid] = self.db.scalar(select(User.email).where(User.id == uid)) or "?"
        return self.cache[uid]


def _sensor_out(s: ShieldSensor, names: _Names, now: datetime) -> SensorOut:
    return SensorOut(
        id=s.id,
        name=s.name,
        key_prefix=s.key_prefix,
        created_by=names(s.created_by_user_id) or "?",
        created_at=s.created_at,
        last_seen_at=s.last_seen_at,
        online=s.revoked_at is None
        and s.last_seen_at is not None
        and now - s.last_seen_at <= SENSOR_OFFLINE,
        agent_version=s.agent_version,
        revoked_at=s.revoked_at,
        revoked_reason=s.revoked_reason,
    )


def _auth_out(
    a: ShieldResponseAuthorization, names: _Names, now: datetime
) -> ResponseAuthorizationOut:
    return ResponseAuthorizationOut(
        id=a.id,
        sensor_ids=list(a.sensor_ids),
        actions=list(a.actions),
        max_block_seconds=a.max_block_seconds,
        default_block_seconds=a.default_block_seconds,
        per_hour_cap=a.per_hour_cap,
        authorized_by=names(a.authorized_by_user_id) or "?",
        authorized_at=a.authorized_at,
        expires_at=a.expires_at,
        ended_at=a.ended_at,
        ended_reason=a.ended_reason,
        live=a.ended_at is None and a.expires_at > now,
    )


def _settings(db: Session, ws: uuid.UUID) -> ShieldResponseSettings | None:
    return db.get(ShieldResponseSettings, ws)


def _settings_out(st: ShieldResponseSettings | None, names: _Names) -> SettingsOut:
    if st is None:
        return SettingsOut(automatic_paused=False, paused_by=None, paused_at=None, pause_reason="")
    return SettingsOut(
        automatic_paused=st.automatic_paused,
        paused_by=names(st.paused_by_user_id),
        paused_at=st.paused_at,
        pause_reason=st.pause_reason,
    )


def _status(
    b: ShieldBlock, now: datetime
) -> Literal["pending", "active", "lifting", "lifted", "expired"]:
    if b.lifted_at is not None:
        return (
            "lifting"
            if b.applied_at is not None and b.removed_at is None and b.expires_at > now
            else "lifted"
        )
    if b.expires_at <= now or b.removed_at is not None:
        return "expired"
    return "active" if b.applied_at is not None else "pending"


def _block_out(
    b: ShieldBlock, sensor_names: dict[uuid.UUID, str], names: _Names, now: datetime
) -> BlockOut:
    return BlockOut(
        id=b.id,
        sensor_id=b.sensor_id,
        sensor_name=sensor_names.get(b.sensor_id, "?"),
        target=str(b.target),
        tier=b.tier,
        reason=b.reason,
        approved_by=names(b.approved_by_user_id),
        alert_id=b.alert_id,
        created_at=b.created_at,
        expires_at=b.expires_at,
        applied_at=b.applied_at,
        removed_at=b.removed_at,
        lifted_at=b.lifted_at,
        lifted_by=names(b.lifted_by_user_id),
        lifted_reason=b.lifted_reason,
        status=_status(b, now),
    )


def _audit(
    db: Session, ctx: WorkspaceContext, action: str, entity: str, eid: uuid.UUID, **data: Any
) -> None:
    record(db, action, entity_type=entity, entity_id=eid, data=data, **ctx.audit_kwargs())


def _sensor(db: Session, ctx: WorkspaceContext, sensor_id: uuid.UUID) -> ShieldSensor:
    s = db.get(ShieldSensor, sensor_id)
    if s is None or s.workspace_id != ctx.workspace_id:
        raise not_found("Sensor not found.")
    return s


def _live_sensor_ids(db: Session, ctx: WorkspaceContext, ids: list[uuid.UUID]) -> list[uuid.UUID]:
    if len(set(ids)) != len(ids):
        raise api_error(422, "duplicate_sensor", "Each sensor may be listed once.")
    found = set(
        db.scalars(
            select(ShieldSensor.id).where(
                ShieldSensor.id.in_(ids),
                ShieldSensor.workspace_id == ctx.workspace_id,
                ShieldSensor.revoked_at.is_(None),
            )
        )
    )
    if found != set(ids):
        raise api_error(422, "unknown_sensor", "A sensor wasn't found or has been revoked.")
    return ids


@router.get("/intrusion", response_model=IntrusionOut)
def intrusion(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> IntrusionOut:
    now = utcnow()
    names = _Names(db)
    week = now - timedelta(days=7)
    ws = ctx.workspace_id
    sensors = db.scalars(
        select(ShieldSensor)
        .where(ShieldSensor.workspace_id == ws)
        .order_by(ShieldSensor.created_at)
    ).all()
    sensor_names = {s.id: s.name for s in sensors}
    auth = guard.live_authorization(db, ws, now)
    st = _settings(db, ws)
    allow = db.scalars(
        select(ShieldBlockAllowlistEntry)
        .where(
            ShieldBlockAllowlistEntry.workspace_id == ws,
            ShieldBlockAllowlistEntry.removed_at.is_(None),
        )
        .order_by(ShieldBlockAllowlistEntry.added_at)
    ).all()
    blocks = db.scalars(
        select(ShieldBlock)
        .where(
            ShieldBlock.workspace_id == ws,
            or_(ShieldBlock.expires_at > now, ShieldBlock.created_at > week),
        )
        .order_by(ShieldBlock.created_at.desc())
        .limit(500)
    ).all()
    alerts = db.scalars(
        select(ShieldIntrusionAlert)
        .where(
            ShieldIntrusionAlert.workspace_id == ws,
            or_(ShieldIntrusionAlert.state == "open", ShieldIntrusionAlert.last_event_time > week),
        )
        .order_by(ShieldIntrusionAlert.last_event_time.desc())
        .limit(500)
    ).all()
    by_alert: dict[uuid.UUID, list[uuid.UUID]] = {}
    for b in blocks:
        if b.alert_id:
            by_alert.setdefault(b.alert_id, []).append(b.id)
    sensor_out = [_sensor_out(s, names, now) for s in sensors]
    open_host = dict(
        db.execute(
            select(ShieldHostAlert.sensor_id, func.count())
            .where(ShieldHostAlert.workspace_id == ws, ShieldHostAlert.state == "open")
            .group_by(ShieldHostAlert.sensor_id)
        ).all()
    )
    for so in sensor_out:
        so.open_host_alerts = int(open_host.get(so.id, 0))
    return IntrusionOut(
        generated_at=now,
        sensors=sensor_out,
        authorization=_auth_out(auth, names, now) if auth else None,
        settings=_settings_out(st, names),
        automatic_active=auth is not None and not (st and st.automatic_paused),
        allowlist=[
            AllowlistOut(
                id=e.id,
                cidr=str(e.cidr),
                note=e.note,
                added_by=names(e.added_by_user_id) or "?",
                added_at=e.added_at,
            )
            for e in allow
        ],
        blocks=[_block_out(b, sensor_names, names, now) for b in blocks],
        alerts=[
            IntrusionAlertOut(
                id=a.id,
                sensor_id=a.sensor_id,
                sensor_name=sensor_names.get(a.sensor_id, "?"),
                scenario=a.scenario,
                category=a.category,
                severity=a.severity.value,
                source=str(a.source),
                count=a.count,
                event_time=a.event_time,
                last_event_time=a.last_event_time,
                ingested_at=a.ingested_at,
                state=a.state,
                acknowledged_at=a.acknowledged_at,
                block_ids=by_alert.get(a.id, []),
            )  # fmt: skip
            for a in alerts
        ],
        blocks_24h=sum(b.created_at > now - timedelta(hours=24) for b in blocks),
        sensors_offline=sum(1 for s in sensor_out if s.revoked_at is None and not s.online),
        approved_max_seconds=APPROVED_MAX_SECONDS,
        host_alerts_open=int(sum(open_host.values())),
    )


# Sensors


@router.post("/sensors", response_model=SensorCreatedOut, status_code=201)
def register_sensor(
    body: SensorIn, db: DB, ctx: WorkspaceContext = ws_permission(OWNER, fresh_mfa=True)
) -> SensorCreatedOut:
    """The key is returned once; JANUS keeps only its hash."""
    raw, _ = new_token()
    key = KEY_PREFIX + raw
    s = ShieldSensor(
        workspace_id=ctx.workspace_id,
        name=body.name,
        key_prefix=key[:12],
        key_sha256=hash_token(key),
        created_by_user_id=ctx.user_id,
    )
    db.add(s)
    db.flush()
    db.refresh(s)
    _audit(db, ctx, "shield.sensor.registered", "shield_sensor", s.id, name=s.name)
    out = _sensor_out(s, _Names(db), utcnow())
    return SensorCreatedOut(**out.model_dump(), key=key)


@router.post("/sensors/{sensor_id}/revoke", response_model=SensorOut)
def revoke_sensor(
    sensor_id: uuid.UUID,
    body: RevokeIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(OWNER, fresh_mfa=True),
) -> SensorOut:
    s = _sensor(db, ctx, sensor_id)
    if s.revoked_at is not None:
        raise api_error(409, "revoked", "This sensor is already revoked.")
    s.revoked_at, s.revoked_by_user_id, s.revoked_reason = utcnow(), ctx.user_id, body.reason
    db.flush()
    _audit(db, ctx, "shield.sensor.revoked", "shield_sensor", s.id, reason=body.reason)
    return _sensor_out(s, _Names(db), utcnow())


# Standing response authorization (GUARD)


@router.post("/response-authorization", response_model=ResponseAuthorizationOut, status_code=201)
def authorize_response(
    body: ResponseAuthorizationIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(OWNER, fresh_mfa=True),
) -> ResponseAuthorizationOut:
    """Record the standing authorization for automatic blocks. Replaces any current one."""
    if body.default_block_seconds > body.max_block_seconds:
        raise api_error(422, "default_too_long", "The default block can't exceed the longest.")
    ids = _live_sensor_ids(db, ctx, body.sensor_ids)
    now = utcnow()
    old = db.scalar(
        select(ShieldResponseAuthorization).where(
            ShieldResponseAuthorization.workspace_id == ctx.workspace_id,
            ShieldResponseAuthorization.ended_at.is_(None),
        )
    )
    if old is not None:
        old.ended_at = now
        old.ended_reason = "superseded" if old.expires_at > now else "expired"
        db.flush()
    a = ShieldResponseAuthorization(
        workspace_id=ctx.workspace_id,
        sensor_ids=ids,
        actions=["block_ip"],
        max_block_seconds=body.max_block_seconds,
        default_block_seconds=body.default_block_seconds,
        per_hour_cap=body.per_hour_cap,
        authorized_by_user_id=ctx.user_id,
        authorized_at=now,
        expires_at=now + timedelta(days=body.days),
    )
    db.add(a)
    db.flush()
    _audit(
        db, ctx, "shield.response.authorized", "shield_response_authorization", a.id,
        sensor_ids=[str(i) for i in ids], max_block_seconds=a.max_block_seconds,
        default_block_seconds=a.default_block_seconds, per_hour_cap=a.per_hour_cap,
        expires_at=a.expires_at.isoformat(), replaces=str(old.id) if old else None,
    )  # fmt: skip
    return _auth_out(a, _Names(db), now)


@router.post("/response-authorization/end", response_model=ResponseAuthorizationOut)
def end_response_authorization(
    body: RevokeIn, db: DB, ctx: WorkspaceContext = ws_permission(ADMIN)
) -> ResponseAuthorizationOut:
    """GUARD stops creating blocks at once. Existing blocks run out (or a person lifts them)."""
    now = utcnow()
    a = guard.live_authorization(db, ctx.workspace_id, now)
    if a is None:
        raise api_error(409, "none_live", "There's no live response authorization.")
    a.ended_at, a.ended_reason = now, "revoked"
    db.flush()
    _audit(
        db, ctx, "shield.response.ended", "shield_response_authorization", a.id, reason=body.reason
    )
    return _auth_out(a, _Names(db), now)


# Kill switch


@router.post("/response/pause", response_model=SettingsOut)
def pause(body: PauseIn, db: DB, ctx: WorkspaceContext = ws_permission(ADMIN)) -> SettingsOut:
    now = utcnow()
    st = _settings(db, ctx.workspace_id)
    if st is None:
        st = ShieldResponseSettings(workspace_id=ctx.workspace_id)
        db.add(st)
    st.automatic_paused, st.paused_by_user_id, st.paused_at = True, ctx.user_id, now
    st.pause_reason, st.updated_at = body.reason, now
    db.flush()
    _audit(db, ctx, "shield.response.paused", "workspace", ctx.workspace_id, reason=body.reason)
    return _settings_out(st, _Names(db))


@router.post("/response/resume", response_model=SettingsOut)
def resume(db: DB, ctx: WorkspaceContext = ws_permission(OWNER, fresh_mfa=True)) -> SettingsOut:
    st = _settings(db, ctx.workspace_id)
    if st is None or not st.automatic_paused:
        raise api_error(409, "not_paused", "Automatic response isn't paused.")
    st.automatic_paused, st.paused_by_user_id, st.paused_at = False, None, None
    st.pause_reason, st.updated_at = "", utcnow()
    db.flush()
    _audit(db, ctx, "shield.response.resumed", "workspace", ctx.workspace_id)
    return _settings_out(st, _Names(db))


# Allow list


@router.post("/allowlist", response_model=AllowlistOut, status_code=201)
def add_allowlist(
    body: AllowlistIn, db: DB, ctx: WorkspaceContext = ws_permission(ADMIN)
) -> AllowlistOut:
    """Never block this address or range. Existing blocks on it are not lifted automatically."""
    e = ShieldBlockAllowlistEntry(
        workspace_id=ctx.workspace_id, cidr=body.cidr, note=body.note, added_by_user_id=ctx.user_id
    )
    db.add(e)
    db.flush()
    db.refresh(e)
    _audit(
        db,
        ctx,
        "shield.allowlist.added",
        "shield_block_allowlist",
        e.id,
        cidr=body.cidr,
        note=body.note,
    )
    return AllowlistOut(
        id=e.id, cidr=str(e.cidr), note=e.note, added_by=ctx.auth.user.email, added_at=e.added_at
    )


@router.post("/allowlist/{entry_id}/remove", status_code=204)
def remove_allowlist(
    entry_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(OWNER, fresh_mfa=True)
) -> None:
    e = db.get(ShieldBlockAllowlistEntry, entry_id)
    if e is None or e.workspace_id != ctx.workspace_id or e.removed_at is not None:
        raise not_found("Allow-list entry not found.")
    e.removed_at, e.removed_by_user_id = utcnow(), ctx.user_id
    db.flush()
    _audit(db, ctx, "shield.allowlist.removed", "shield_block_allowlist", e.id, cidr=str(e.cidr))


# Blocks


@router.post("/blocks", response_model=list[BlockOut], status_code=201)
def approve_block(
    body: BlockIn, db: DB, ctx: WorkspaceContext = ws_permission(ADMIN, fresh_mfa=True)
) -> list[BlockOut]:
    """The person-approved tier: a block of an address or range on the chosen sensors."""
    if why := guard.never_block(_net(body.target)):
        raise api_error(422, "never_block", why)
    ids = _live_sensor_ids(db, ctx, body.sensor_ids)
    if body.alert_id is not None:
        al = db.get(ShieldIntrusionAlert, body.alert_id)
        if al is None or al.workspace_id != ctx.workspace_id:
            raise not_found("Intrusion alert not found.")
    if guard.allowlisted(db, ctx.workspace_id, body.target):
        raise api_error(409, "allowlisted", f"{body.target} is on the allow list.")
    now = utcnow()
    blocks = [
        ShieldBlock(
            workspace_id=ctx.workspace_id,
            sensor_id=sid,
            target=body.target,
            tier="approved",
            action="block_ip",
            reason=body.reason,
            approved_by_user_id=ctx.user_id,
            alert_id=body.alert_id,
            created_at=now,
            expires_at=now + timedelta(seconds=body.seconds),
        )  # fmt: skip
        for sid in ids
    ]
    try:
        with db.begin_nested():
            db.add_all(blocks)
            db.flush()
    except DBAPIError as exc:
        raise api_error(409, "refused", "The database refused the block (allow list).") from exc
    for b in blocks:
        _audit(
            db, ctx, "shield.block.approved", "shield_block", b.id, target=body.target,
            sensor_id=str(b.sensor_id), seconds=body.seconds, reason=body.reason,
        )  # fmt: skip
    sensor_names = {
        s.id: s.name for s in db.scalars(select(ShieldSensor).where(ShieldSensor.id.in_(ids)))
    }
    names = _Names(db)
    return [_block_out(b, sensor_names, names, now) for b in blocks]


@router.post("/blocks/{block_id}/lift", response_model=BlockOut)
def lift_block(
    block_id: uuid.UUID, body: RevokeIn, db: DB, ctx: WorkspaceContext = ws_permission(ADMIN)
) -> BlockOut:
    """One click: the sensor removes the CrowdSec decision on its next poll."""
    b = db.get(ShieldBlock, block_id)
    if b is None or b.workspace_id != ctx.workspace_id:
        raise not_found("Block not found.")
    now = utcnow()
    if b.lifted_at is not None or b.expires_at <= now or b.removed_at is not None:
        raise api_error(409, "not_active", "This block isn't active.")
    b.lifted_at, b.lifted_by_user_id, b.lifted_reason = now, ctx.user_id, body.reason
    db.flush()
    _audit(
        db,
        ctx,
        "shield.block.lifted",
        "shield_block",
        b.id,
        target=str(b.target),
        reason=body.reason,
    )
    s = db.get(ShieldSensor, b.sensor_id)
    return _block_out(b, {b.sensor_id: s.name if s else "?"}, _Names(db), now)


# Intrusion alerts


def _intrusion_alert(
    db: Session, ctx: WorkspaceContext, alert_id: uuid.UUID
) -> ShieldIntrusionAlert:
    a = db.get(ShieldIntrusionAlert, alert_id)
    if a is None or a.workspace_id != ctx.workspace_id:
        raise not_found("Intrusion alert not found.")
    return a


@router.post("/intrusion-alerts/{alert_id}/{action}", status_code=204)
def update_intrusion_alert(
    alert_id: uuid.UUID,
    action: Literal["acknowledge", "resolve"],
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> None:
    a = _intrusion_alert(db, ctx, alert_id)
    target = "acknowledged" if action == "acknowledge" else "resolved"
    if a.state == target or a.state == "resolved":
        return
    a.state = target
    a.acknowledged_at = a.acknowledged_at or utcnow()
    db.flush()
    _audit(db, ctx, f"shield.intrusion_alert.{target}", "shield_intrusion_alert", a.id)
