"""SHIELD v1 API: standing monitor authorizations, alerts and the AEGIS overview.

* authorizations: the owner only (monitors.manage), with two-factor in the last 15
  minutes; at most 20 targets from the active, non-lab scope, checks from the fixed list,
  at most 30 days, and at most DAILY_CAP checks per workspace per day in total
* alerts: any member reads; analysts and above acknowledge and resolve
* agents have no route here
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import Field, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Alert,
    MonitorAuthorization,
    Operation,
    OperationStatus,
    Project,
    Scope,
    ScopeStatus,
    Severity,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.scope import normalize
from nightfall.scope.engine import evaluate
from nightfall.scope.normalize import NormalizationError
from nightfall.scope.repository import active_scope, snapshot
from nightfall.shield.control import ALLOWED_TOOLS
from nightfall.shield.rules import RECOMMEND, RULES
from nightfall.shield.scheduler import DAILY_CAP, WARN_BEFORE

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["shield"])
Check = Literal["ct", "dns", "tls", "headers"]
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]
SEVERITIES = ("critical", "high", "medium", "low", "info")


class MonitorAuthorizationIn(Model):
    targets: Annotated[
        list[Annotated[str, StringConstraints(max_length=253)]], Field(min_length=1, max_length=20)
    ]
    checks: Annotated[list[Check], Field(min_length=1, max_length=4)]
    days: int = Field(30, ge=1, le=30)


class MonitorRevokeIn(Model):
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class MonitorAuthorizationOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    scope_id: uuid.UUID
    scope_version: int
    targets: list[str]
    checks: list[str]
    cadence: str
    authorized_by: str
    authorized_at: datetime
    expires_at: datetime
    last_run_at: datetime | None
    ended_at: datetime | None
    ended_reason: str | None
    end_note: str
    live: bool
    expiring_soon: bool
    checks_per_day: int


class ShieldAlertOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    authorization_id: uuid.UUID | None
    kind: str
    severity: Severity
    title: str
    detail: str
    target: str
    recommendation: str
    evidence_ids: list[uuid.UUID]
    finding_id: uuid.UUID | None
    rules: str
    first_seen_at: datetime
    last_seen_at: datetime
    state: str
    acknowledged_by: str | None
    acknowledged_at: datetime | None
    resolved_by: str | None
    resolved_at: datetime | None
    note: str


class AlertResolveIn(Model):
    note: Note = ""


class ShieldQueuedCheck(Model):
    operation_id: uuid.UUID
    tool: str
    target: str
    queued_at: datetime
    hours_waiting: float


class ShieldOverviewOut(Model):
    generated_at: datetime
    open_alerts: dict[str, int]  # by severity
    alerts_needing_attention: list[ShieldAlertOut]
    authorizations_live: int
    authorizations_expiring: list[MonitorAuthorizationOut]
    checks_ran_24h: int
    checks_failed_24h: int
    checks_waiting: list[ShieldQueuedCheck]
    last_scheduled_at: datetime | None
    daily_cap: int
    checks_per_day_authorized: int
    projects_unmonitored: list[str]  # active, non-lab scope but no live authorization
    rules: str


# --- Helpers ---------------------------------------------------------------------------------


def _names(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    ids_ = {i for i in ids if i}
    if not ids_:
        return {}
    return {
        u: n for u, n in db.execute(select(User.id, User.display_name).where(User.id.in_(ids_)))
    }


def _live(a: MonitorAuthorization, now: datetime) -> bool:
    return a.ended_at is None and a.expires_at > now


def _auth_out(db: Session, a: MonitorAuthorization, now: datetime) -> MonitorAuthorizationOut:
    project = db.get(Project, a.project_id)
    scope = db.get(Scope, a.scope_id)
    names = _names(db, {a.authorized_by_user_id})
    return MonitorAuthorizationOut(
        id=a.id,
        project_id=a.project_id,
        project_name=project.name if project else "—",
        scope_id=a.scope_id,
        scope_version=scope.version if scope else 0,
        targets=list(a.targets),
        checks=list(a.checks),
        cadence=a.cadence,
        authorized_by=names.get(a.authorized_by_user_id, "Unknown"),
        authorized_at=a.authorized_at,
        expires_at=a.expires_at,
        last_run_at=a.last_run_at,
        ended_at=a.ended_at,
        ended_reason=a.ended_reason,
        end_note=a.end_note,
        live=_live(a, now),
        expiring_soon=_live(a, now) and a.expires_at - now <= WARN_BEFORE,
        checks_per_day=len(a.targets) * len(a.checks),
    )


def _alert_out(db: Session, al: Alert, names: dict[uuid.UUID, str]) -> ShieldAlertOut:
    project = db.get(Project, al.project_id)
    return ShieldAlertOut(
        id=al.id,
        project_id=al.project_id,
        project_name=project.name if project else "—",
        authorization_id=al.authorization_id,
        kind=al.kind,
        severity=al.severity,
        title=al.title,
        detail=al.detail,
        target=al.target,
        recommendation=RECOMMEND.get(al.kind, ""),
        evidence_ids=list(al.evidence_ids),
        finding_id=al.finding_id,
        rules=al.rules,
        first_seen_at=al.first_seen_at,
        last_seen_at=al.last_seen_at,
        state=al.state,
        acknowledged_by=names.get(al.acknowledged_by_user_id)
        if al.acknowledged_by_user_id
        else None,
        acknowledged_at=al.acknowledged_at,
        resolved_by=names.get(al.resolved_by_user_id) if al.resolved_by_user_id else None,
        resolved_at=al.resolved_at,
        note=al.note,
    )


def _alerts_out(db: Session, rows: list[Alert]) -> list[ShieldAlertOut]:
    names = _names(
        db, {r.acknowledged_by_user_id for r in rows} | {r.resolved_by_user_id for r in rows}
    )
    return [_alert_out(db, r, names) for r in rows]


def _authorized_per_day(
    db: Session, ws: uuid.UUID, now: datetime, skip: uuid.UUID | None = None
) -> int:
    live = db.scalars(
        select(MonitorAuthorization).where(
            MonitorAuthorization.workspace_id == ws,
            MonitorAuthorization.ended_at.is_(None),
            MonitorAuthorization.expires_at > now,
        )
    ).all()
    return sum(len(a.targets) * len(a.checks) for a in live if a.id != skip)


def _audit(
    db: Session, ctx: WorkspaceContext, action: str, a: MonitorAuthorization, **data: object
) -> None:
    record(
        db,
        action,
        entity_type="monitor_authorization",
        entity_id=a.id,
        data={"project_id": str(a.project_id), **data},
        **ctx.audit_kwargs(),
    )


def _create(
    db: Session,
    ctx: WorkspaceContext,
    project_id: uuid.UUID,
    targets: list[str],
    checks: list[str],
    days: int,
    renews: MonitorAuthorization | None = None,
) -> MonitorAuthorization:
    now = utcnow()
    scope = active_scope(db, project_id)
    if scope is None or scope.is_lab or scope.status is not ScopeStatus.ACTIVE:
        raise api_error(409, "no_scope", "Monitoring needs the project's active, non-lab scope.")
    snap = snapshot(db, scope)
    clean: list[str] = []
    for t in targets:
        try:
            host = normalize.hostname(t)
        except NormalizationError as exc:
            raise api_error(422, "invalid_target", f"{t}: {exc}") from exc
        decision = evaluate(snap, host, now)
        if not decision.allowed:
            raise api_error(422, "out_of_scope", f"{host}: {decision.reason}")
        if host not in clean:
            clean.append(host)
    wanted = list(dict.fromkeys(c for c in checks if c in ALLOWED_TOOLS))
    per_day = len(clean) * len(wanted)
    already = _authorized_per_day(db, ctx.workspace_id, now, renews.id if renews else None)
    if already + per_day > DAILY_CAP:
        raise api_error(
            409,
            "daily_cap",
            f"That's {per_day} checks a day; with the {already} already authorized it would pass "
            f"the limit of {DAILY_CAP} per workspace on the hosted platform.",
        )
    a = MonitorAuthorization(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        scope_id=scope.id,
        targets=clean,
        checks=wanted,
        authorized_by_user_id=ctx.user_id,
        authorized_at=now,
        expires_at=now + timedelta(days=days),
        renews_id=renews.id if renews else None,
    )
    db.add(a)
    db.flush()
    _audit(
        db, ctx, "monitor.authorized", a, targets=clean, checks=wanted,
        expires_at=a.expires_at.isoformat(), scope_version=scope.version,
        renews=str(renews.id) if renews else None,
    )  # fmt: skip
    return a


def _auth(db: Session, ctx: WorkspaceContext, auth_id: uuid.UUID) -> MonitorAuthorization:
    a = db.get(MonitorAuthorization, auth_id)
    if a is None or a.workspace_id != ctx.workspace_id:
        raise not_found("Authorization not found.")
    return a


# --- Authorizations --------------------------------------------------------------------------


@router.get("/monitor-authorizations", response_model=list[MonitorAuthorizationOut])
def list_authorizations(
    db: DB,
    project_id: uuid.UUID | None = None,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[MonitorAuthorizationOut]:
    q = select(MonitorAuthorization).where(MonitorAuthorization.workspace_id == ctx.workspace_id)
    if project_id:
        q = q.where(MonitorAuthorization.project_id == project_id)
    now = utcnow()
    rows = db.scalars(q.order_by(MonitorAuthorization.authorized_at.desc()).limit(200)).all()
    return [_auth_out(db, a, now) for a in rows]


@router.post(
    "/projects/{project_id}/monitor-authorizations",
    response_model=MonitorAuthorizationOut,
    status_code=201,
)
def authorize_monitoring(
    project_id: uuid.UUID,
    body: MonitorAuthorizationIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.MONITORS_MANAGE, fresh_mfa=True),
) -> MonitorAuthorizationOut:
    """A standing authorization for daily passive and low-risk checks (at most 30 days)."""
    project = db.get(Project, project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    a = _create(db, ctx, project_id, body.targets, list(body.checks), body.days)
    return _auth_out(db, a, utcnow())


@router.post(
    "/monitor-authorizations/{auth_id}/renew",
    response_model=MonitorAuthorizationOut,
    status_code=201,
)
def renew_monitoring(
    auth_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.MONITORS_MANAGE, fresh_mfa=True),
) -> MonitorAuthorizationOut:
    """A new 30-day authorization with the same contents; the old one ends ('renewed')."""
    old = _auth(db, ctx, auth_id)
    if old.ended_at is not None:
        raise api_error(409, "ended", "This authorization has ended; create a new one.")
    new = _create(db, ctx, old.project_id, list(old.targets), list(old.checks), 30, renews=old)
    old.ended_at, old.ended_reason, old.ended_by_user_id = utcnow(), "renewed", ctx.user_id
    old.end_note = f"Renewed as {new.id}."
    db.flush()
    return _auth_out(db, new, utcnow())


@router.post("/monitor-authorizations/{auth_id}/revoke", response_model=MonitorAuthorizationOut)
def revoke_monitoring(
    auth_id: uuid.UUID,
    body: MonitorRevokeIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.MONITORS_MANAGE, fresh_mfa=True),
) -> MonitorAuthorizationOut:
    """Queued scheduled checks under it are refused by the worker from now on."""
    a = _auth(db, ctx, auth_id)
    if a.ended_at is not None:
        raise api_error(409, "ended", "This authorization has already ended.")
    a.ended_at, a.ended_reason, a.ended_by_user_id, a.end_note = (
        utcnow(), "revoked", ctx.user_id, body.reason,
    )  # fmt: skip
    db.flush()
    _audit(db, ctx, "monitor.revoked", a, reason=body.reason)
    return _auth_out(db, a, utcnow())


# --- Alerts ----------------------------------------------------------------------------------


def _alert(db: Session, ctx: WorkspaceContext, alert_id: uuid.UUID) -> Alert:
    al = db.get(Alert, alert_id)
    if al is None or al.workspace_id != ctx.workspace_id:
        raise not_found("Alert not found.")
    return al


@router.get("/alerts", response_model=list[ShieldAlertOut])
def list_alerts(
    db: DB,
    state: Literal["open", "acknowledged", "resolved", "active"] | None = "active",
    project_id: uuid.UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[ShieldAlertOut]:
    q = select(Alert).where(Alert.workspace_id == ctx.workspace_id)
    if state == "active":
        q = q.where(Alert.state != "resolved")
    elif state:
        q = q.where(Alert.state == state)
    if project_id:
        q = q.where(Alert.project_id == project_id)
    rows = db.scalars(q.order_by(Alert.last_seen_at.desc()).limit(limit)).all()
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return _alerts_out(
        db, sorted(rows, key=lambda r: (order[r.severity.value], -r.last_seen_at.timestamp()))
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=ShieldAlertOut)
def acknowledge_alert(
    alert_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE)
) -> ShieldAlertOut:
    al = _alert(db, ctx, alert_id)
    if al.state != "open":
        raise api_error(409, "not_open", "Only an open alert can be acknowledged.")
    al.state, al.acknowledged_by_user_id, al.acknowledged_at = "acknowledged", ctx.user_id, utcnow()
    db.flush()
    record(
        db,
        "alert.acknowledged",
        entity_type="alert",
        entity_id=al.id,
        data={"project_id": str(al.project_id), "kind": al.kind},
        **ctx.audit_kwargs(),
    )
    return _alerts_out(db, [al])[0]


@router.post("/alerts/{alert_id}/resolve", response_model=ShieldAlertOut)
def resolve_alert(
    alert_id: uuid.UUID,
    body: AlertResolveIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> ShieldAlertOut:
    al = _alert(db, ctx, alert_id)
    if al.state == "resolved":
        raise api_error(409, "resolved", "This alert is already resolved.")
    al.state, al.resolved_by_user_id, al.resolved_at, al.note = (
        "resolved", ctx.user_id, utcnow(), body.note,
    )  # fmt: skip
    db.flush()
    record(
        db,
        "alert.resolved",
        entity_type="alert",
        entity_id=al.id,
        data={"project_id": str(al.project_id), "kind": al.kind, "note": body.note},
        **ctx.audit_kwargs(),
    )
    return _alerts_out(db, [al])[0]


# --- AEGIS overview --------------------------------------------------------------------------


@router.get("/shield/overview", response_model=ShieldOverviewOut)
def overview(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> ShieldOverviewOut:
    now = utcnow()
    ws = ctx.workspace_id
    counts = dict(
        db.execute(
            select(Alert.severity, func.count())
            .where(Alert.workspace_id == ws, Alert.state != "resolved")
            .group_by(Alert.severity)
        ).all()
    )
    attention = db.scalars(
        select(Alert)
        .where(Alert.workspace_id == ws, Alert.state == "open")
        .order_by(Alert.last_seen_at.desc())
        .limit(50)
    ).all()
    order = {s: i for i, s in enumerate(SEVERITIES)}
    attention = sorted(attention, key=lambda r: order[r.severity.value])[:10]
    auths = db.scalars(
        select(MonitorAuthorization).where(
            MonitorAuthorization.workspace_id == ws, MonitorAuthorization.ended_at.is_(None)
        )
    ).all()
    live = [a for a in auths if _live(a, now)]
    since = now - timedelta(hours=24)
    scheduled = Operation.monitor_authorization_id.is_not(None)
    ran = db.scalar(
        select(func.count()).select_from(Operation).where(
            Operation.workspace_id == ws, scheduled, Operation.finished_at >= since,
            Operation.status == OperationStatus.SUCCEEDED,
        )
    ) or 0  # fmt: skip
    failed = db.scalar(
        select(func.count()).select_from(Operation).where(
            Operation.workspace_id == ws, scheduled, Operation.finished_at >= since,
            Operation.status.in_([OperationStatus.FAILED, OperationStatus.DENIED]),
        )
    ) or 0  # fmt: skip
    waiting = db.scalars(
        select(Operation)
        .where(
            Operation.workspace_id == ws,
            scheduled,
            Operation.status.in_([OperationStatus.QUEUED, OperationStatus.RUNNING]),
        )
        .order_by(Operation.queued_at)
        .limit(50)
    ).all()
    monitored = {a.project_id for a in live}
    active_projects = db.execute(
        select(Project.id, Project.name)
        .join(Scope, Scope.project_id == Project.id)
        .where(
            Project.workspace_id == ws,
            Scope.status == ScopeStatus.ACTIVE,
            Scope.is_lab.is_(False),
        )
    ).all()
    return ShieldOverviewOut(
        generated_at=now,
        open_alerts={s: int(counts.get(Severity(s), 0)) for s in SEVERITIES},
        alerts_needing_attention=_alerts_out(db, list(attention)),
        authorizations_live=len(live),
        authorizations_expiring=[
            _auth_out(db, a, now) for a in live if a.expires_at - now <= WARN_BEFORE
        ],
        checks_ran_24h=int(ran),
        checks_failed_24h=int(failed),
        checks_waiting=[
            ShieldQueuedCheck(
                operation_id=o.id,
                tool=o.tool,
                target=o.target_value,
                queued_at=o.queued_at,
                hours_waiting=round((now - o.queued_at).total_seconds() / 3600, 1),
            )
            for o in waiting
        ],
        last_scheduled_at=max((a.last_run_at for a in auths if a.last_run_at), default=None),
        daily_cap=DAILY_CAP,
        checks_per_day_authorized=sum(len(a.targets) * len(a.checks) for a in live),
        projects_unmonitored=sorted({n for pid, n in active_projects if pid not in monitored}),
        rules=RULES,
    )
