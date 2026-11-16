"""SHIELD v2 API: incidents, with recovery and verification
(docs/designs/2026-11-shield-incident-response.md).

* any member reads
* analysts and above (findings.validate) open incidents, link items, add notes, record
  actions, change the checklist, move an incident to contained or recovering, and request
  verification
* admins and owners (incidents.manage) change severity or lead, cancel, close and reopen;
  closing without verification is an override that also needs two-factor in the last 15
  minutes
* agents have no route here

Nothing in this module performs a response action. "Action" entries are statements by a
named person about what they did outside JANUS.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Query
from pydantic import Field, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Alert,
    Asset,
    Finding,
    Incident,
    IncidentEntry,
    IncidentItem,
    Project,
    Severity,
    WorkspaceMember,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.shield import incidents as logic
from nightfall.shield.routes import SEVERITIES, _names

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["shield"])
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]
Short = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
Optional4k = Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000)]
WORK = Permission.FINDINGS_VALIDATE
MANAGE = Permission.INCIDENTS_MANAGE
_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


class IncidentIn(Model):
    title: Short
    summary: Optional4k = ""
    alert_ids: Annotated[list[uuid.UUID], Field(max_length=50)] = []
    finding_ids: Annotated[list[uuid.UUID], Field(max_length=50)] = []


class IncidentItemIn(Model):
    kind: Literal["alert", "finding", "asset"]
    item_id: uuid.UUID


class IncidentEntryIn(Model):
    kind: Literal["note", "action"]
    body: Text


class IncidentCheckIn(Model):
    """Tick or untick an item (key), or add one (text)."""

    key: Annotated[str, StringConstraints(max_length=100)] | None = None
    text: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None
    done: bool = False


class IncidentStateIn(Model):
    state: Literal["contained", "recovering"]
    note: Text


class IncidentSeverityIn(Model):
    severity: Severity
    reason: Reason


class IncidentLeadIn(Model):
    user_id: uuid.UUID


class IncidentReasonIn(Model):
    reason: Reason


class IncidentReview(Model):
    what_happened: Text
    cause: Optional4k = ""
    what_was_done: Text
    lessons: Optional4k = ""


class IncidentCloseIn(Model):
    review: IncidentReview
    override_reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class IncidentOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    title: str
    severity: Severity
    state: str
    lead: str
    lead_user_id: uuid.UUID
    opened_by: str
    opened_at: datetime
    closed_at: datetime | None
    alert_count: int


class IncidentItemOut(Model):
    id: uuid.UUID
    kind: str
    item_id: uuid.UUID
    label: str
    detail: str
    added_by: str
    added_at: datetime


class IncidentCheckOut(Model):
    key: str
    text: str
    done: bool
    source: str
    changed_by: str | None
    changed_at: datetime


class IncidentEntryOut(Model):
    id: uuid.UUID
    kind: str
    body: str
    data: dict[str, Any]
    actor: str | None  # None: written by the system (a verification result)
    created_at: datetime


class IncidentVerificationOut(Model):
    alert_id: uuid.UUID
    title: str
    target: str
    tool: str | None
    state: str
    detail: str
    operation_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    at: datetime | None
    counts: bool


class IncidentDetailOut(IncidentOut):
    summary: str
    severity_reason: str
    closed_by: str | None
    override_reason: str
    review: IncidentReview | None
    cancel_reason: str
    items: list[IncidentItemOut]
    checklist: list[IncidentCheckOut]
    verification: list[IncidentVerificationOut]
    timeline: list[IncidentEntryOut]
    close_blockers: list[str]


class IncidentVerifyOut(Model):
    queued: list[dict[str, str]]
    skipped: list[dict[str, str]]


# --- Helpers ---------------------------------------------------------------------------------


def _incident(db: Session, ctx: WorkspaceContext, incident_id: uuid.UUID) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None or inc.workspace_id != ctx.workspace_id:
        raise not_found("Incident not found.")
    return inc


def _in_progress(inc: Incident) -> None:
    if inc.state not in logic.IN_PROGRESS:
        raise api_error(409, "not_in_progress", f"This incident is {inc.state}.")


def _audit(db: Session, ctx: WorkspaceContext, action: str, inc: Incident, **data: Any) -> None:
    record(
        db,
        action,
        entity_type="incident",
        entity_id=inc.id,
        data={"project_id": str(inc.project_id), "title": inc.title, **data},
        **ctx.audit_kwargs(),
    )


def _alert_counts(db: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ids:
        return {}
    rows = db.execute(
        select(IncidentItem.incident_id, func.count())
        .where(
            IncidentItem.incident_id.in_(ids),
            IncidentItem.kind == "alert",
            IncidentItem.removed_at.is_(None),
        )
        .group_by(IncidentItem.incident_id)
    ).all()
    return {i: int(n) for i, n in rows}


def _out(db: Session, rows: list[Incident]) -> list[IncidentOut]:
    people: set[uuid.UUID | None] = {r.lead_user_id for r in rows}
    names = _names(db, people | {r.opened_by_user_id for r in rows})
    projects: dict[uuid.UUID, str] = dict(
        db.execute(
            select(Project.id, Project.name).where(Project.id.in_({r.project_id for r in rows}))
        )
        .tuples()
        .all()
    )
    counts = _alert_counts(db, [r.id for r in rows])
    return [
        IncidentOut(
            id=r.id,
            project_id=r.project_id,
            project_name=projects.get(r.project_id, "—"),
            title=r.title,
            severity=r.severity,
            state=r.state,
            lead=names.get(r.lead_user_id, "—"),
            lead_user_id=r.lead_user_id,
            opened_by=names.get(r.opened_by_user_id, "—"),
            opened_at=r.opened_at,
            closed_at=r.closed_at,
            alert_count=counts.get(r.id, 0),
        )
        for r in rows
    ]


def _item_label(db: Session, ws: uuid.UUID, kind: str, item_id: uuid.UUID) -> tuple[str, str]:
    """(label, detail) for a linked item; the tenant policy already hides other workspaces."""
    if kind == "alert":
        al = db.get(Alert, item_id)
        if al is not None and al.workspace_id == ws:
            return al.title, f"{al.severity.value} alert, {al.state}, {al.target}".rstrip(", ")
    elif kind == "finding":
        f = db.get(Finding, item_id)
        if f is not None and f.workspace_id == ws:
            return f.title, f"{f.severity.value} finding, {f.validation_status.value}"
    elif kind == "asset":
        a = db.get(Asset, item_id)
        if a is not None and a.workspace_id == ws:
            return a.value, f"{a.kind.value} asset"
    return "(no longer available)", kind


def _blockers(db: Session, inc: Incident) -> list[str]:
    """What stands between this incident and closing without an override."""
    out = []
    for v in logic.unverified(db, inc):
        why = {
            "not_requested": "not checked yet",
            "pending": "a check is waiting to run",
            "still_present": "still present at the last check",
            "undecided": "the last check couldn't decide",
            "failed": "the last check didn't run",
            "not_observed": "an action was recorded after the last check",
        }.get(v.state, v.state)
        out.append(f"{v.title}: {why}.")
    return out


def _detail(db: Session, inc: Incident) -> IncidentDetailOut:
    base = _out(db, [inc])[0]
    items = db.scalars(
        select(IncidentItem)
        .where(IncidentItem.incident_id == inc.id, IncidentItem.removed_at.is_(None))
        .order_by(IncidentItem.added_at, IncidentItem.id)
    ).all()
    entries = db.scalars(
        select(IncidentEntry)
        .where(IncidentEntry.incident_id == inc.id)
        .order_by(IncidentEntry.seq.desc())
        .limit(500)
    ).all()
    checks = logic.checklist(db, inc.id)
    names = _names(
        db,
        {i.added_by_user_id for i in items}
        | {e.actor_user_id for e in entries}
        | {c["changed_by_user_id"] for c in checks}
        | {inc.closed_by_user_id},
    )
    in_progress = inc.state in logic.IN_PROGRESS
    return IncidentDetailOut(
        **base.model_dump(),
        summary=inc.summary,
        severity_reason=inc.severity_reason,
        closed_by=names.get(inc.closed_by_user_id) if inc.closed_by_user_id else None,
        override_reason=inc.override_reason,
        review=IncidentReview(**inc.review) if inc.review else None,
        cancel_reason=inc.cancel_reason,
        items=[
            IncidentItemOut(
                id=i.id,
                kind=i.kind,
                item_id=i.item_id,
                label=label,
                detail=detail,
                added_by=names.get(i.added_by_user_id, "—"),
                added_at=i.added_at,
            )
            for i in items
            for label, detail in [_item_label(db, inc.workspace_id, i.kind, i.item_id)]
        ],
        checklist=[
            IncidentCheckOut(
                key=c["key"],
                text=c["text"],
                done=c["done"],
                source=c["source"],
                changed_by=names.get(c["changed_by_user_id"]),
                changed_at=c["changed_at"],
            )
            for c in checks
        ],
        verification=[IncidentVerificationOut(**v.__dict__) for v in logic.verification(db, inc)],
        timeline=[
            IncidentEntryOut(
                id=e.id,
                kind=e.kind,
                body=e.body,
                data=e.data,
                actor=names.get(e.actor_user_id) if e.actor_user_id else None,
                created_at=e.created_at,
            )
            for e in entries
        ],
        close_blockers=_blockers(db, inc) if in_progress else [],
    )


def _link(db: Session, ctx: WorkspaceContext, inc: Incident, kind: str, item_id: uuid.UUID) -> None:
    ws = ctx.workspace_id
    target: Alert | Finding | Asset | None
    if kind == "alert":
        target = db.get(Alert, item_id)
        if target is None or target.workspace_id != ws or target.project_id != inc.project_id:
            raise api_error(422, "unknown_item", "That alert isn't in this incident's project.")
        if target.state == "resolved":
            raise api_error(422, "resolved", "That alert is already resolved.")
    elif kind == "finding":
        target = db.get(Finding, item_id)
        if target is None or target.workspace_id != ws or target.project_id != inc.project_id:
            raise api_error(422, "unknown_item", "That finding isn't in this incident's project.")
    else:
        target = db.get(Asset, item_id)
        if target is None or target.workspace_id != ws:
            raise api_error(422, "unknown_item", "That asset wasn't found.")
    exists = db.scalar(
        select(IncidentItem.id).where(
            IncidentItem.incident_id == inc.id,
            IncidentItem.kind == kind,
            IncidentItem.item_id == item_id,
            IncidentItem.removed_at.is_(None),
        )
    )
    if exists is not None:
        return
    try:
        with db.begin_nested():
            db.add(
                IncidentItem(
                    workspace_id=ws,
                    incident_id=inc.id,
                    kind=kind,
                    item_id=item_id,
                    added_by_user_id=ctx.user_id,
                )
            )
            db.flush()
    except IntegrityError as exc:
        raise api_error(
            409, "in_another_incident", "That alert is already in another incident in progress."
        ) from exc
    label, _ = _item_label(db, ws, kind, item_id)
    logic.add_entry(
        db, inc, "event", f"Linked {kind}: {label}", {"kind": kind, "item_id": str(item_id)},
        ctx.user_id,
    )  # fmt: skip
    if isinstance(target, Alert):
        logic.seed_checklist(db, inc, target, ctx.user_id)


# --- Reading ---------------------------------------------------------------------------------


@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    db: DB,
    state: Annotated[Literal["in_progress", "closed", "all"], Query()] = "all",
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[IncidentOut]:
    q = select(Incident).where(Incident.workspace_id == ctx.workspace_id)
    if state == "in_progress":
        q = q.where(Incident.state.in_(logic.IN_PROGRESS))
    elif state == "closed":
        q = q.where(Incident.state.in_(("closed", "cancelled")))
    rows = list(db.scalars(q.order_by(Incident.opened_at.desc()).limit(200)).all())
    rows.sort(key=lambda r: (r.state not in logic.IN_PROGRESS, _ORDER[r.severity.value]))
    return _out(db, rows)


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def get_incident(
    incident_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> IncidentDetailOut:
    return _detail(db, _incident(db, ctx, incident_id))


@router.get("/incidents/{incident_id}/export")
def export_incident(
    incident_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> dict[str, Any]:
    """The incident's record as JSON. Actions are recorded statements, not things JANUS did."""
    inc = _incident(db, ctx, incident_id)
    d = _detail(db, inc).model_dump(mode="json")
    d["timeline"].reverse()  # oldest first, as a record reads
    return {
        "format": "janus-incident/1",
        "generated_at": utcnow().isoformat(),
        "note": "Actions are statements recorded by named people about work done outside "
        "JANUS. Verification results say what JANUS's own checks observed.",
        "incident": d,
    }


# --- Working an incident ---------------------------------------------------------------------


@router.post("/projects/{project_id}/incidents", response_model=IncidentDetailOut, status_code=201)
def open_incident(
    project_id: uuid.UUID,
    body: IncidentIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    project = db.get(Project, project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    alerts = [db.get(Alert, a) for a in dict.fromkeys(body.alert_ids)]
    severities = [
        a.severity.value for a in alerts if a is not None and a.workspace_id == ctx.workspace_id
    ]
    inc = Incident(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        title=body.title,
        summary=body.summary,
        severity=Severity(min(severities, key=_ORDER.__getitem__))
        if severities
        else Severity.MEDIUM,
        lead_user_id=ctx.user_id,
        opened_by_user_id=ctx.user_id,
    )
    db.add(inc)
    db.flush()
    logic.add_entry(db, inc, "event", "Incident opened.", {"state": "open"}, ctx.user_id)
    for a in dict.fromkeys(body.alert_ids):
        _link(db, ctx, inc, "alert", a)
    for f in dict.fromkeys(body.finding_ids):
        _link(db, ctx, inc, "finding", f)
    _audit(db, ctx, "incident.opened", inc, severity=inc.severity.value)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/items", response_model=IncidentDetailOut)
def link_item(
    incident_id: uuid.UUID,
    body: IncidentItemIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    _link(db, ctx, inc, body.kind, body.item_id)
    _audit(db, ctx, "incident.item_linked", inc, kind=body.kind, item_id=str(body.item_id))
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/items/{item_id}/remove", response_model=IncidentDetailOut)
def unlink_item(
    incident_id: uuid.UUID,
    item_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    item = db.get(IncidentItem, item_id)
    if item is None or item.incident_id != inc.id or item.removed_at is not None:
        raise not_found("Item not found.")
    label, _ = _item_label(db, inc.workspace_id, item.kind, item.item_id)
    item.removed_by_user_id, item.removed_at = ctx.user_id, utcnow()
    db.flush()
    logic.add_entry(
        db, inc, "event", f"Unlinked {item.kind}: {label}",
        {"kind": item.kind, "item_id": str(item.item_id)}, ctx.user_id,
    )  # fmt: skip
    _audit(db, ctx, "incident.item_unlinked", inc, kind=item.kind, item_id=str(item.item_id))
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/entries", response_model=IncidentDetailOut)
def add_incident_entry(
    incident_id: uuid.UUID,
    body: IncidentEntryIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    logic.add_entry(db, inc, body.kind, body.body, {}, ctx.user_id)
    _audit(db, ctx, f"incident.{body.kind}_added", inc)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/checklist", response_model=IncidentDetailOut)
def change_checklist(
    incident_id: uuid.UUID,
    body: IncidentCheckIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    items = {c["key"]: c for c in logic.checklist(db, inc.id)}
    if body.key is not None:
        item = items.get(body.key)
        if item is None:
            raise not_found("Checklist item not found.")
        if item["done"] != body.done:
            logic.add_entry(
                db, inc, "check",
                f"{'Done' if body.done else 'Not done'}: {item['text']}",
                {"key": body.key, "done": body.done}, ctx.user_id,
            )  # fmt: skip
    elif body.text:
        if len(items) >= 50:
            raise api_error(422, "too_many", "A checklist holds at most 50 items.")
        logic.add_entry(
            db, inc, "check", f"Checklist: {body.text}",
            {"key": f"added:{uuid.uuid4()}", "text": body.text, "done": False, "source": "added"},
            ctx.user_id,
        )  # fmt: skip
    else:
        raise api_error(422, "empty", "Give an item to change, or the text of a new one.")
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/state", response_model=IncidentDetailOut)
def move_incident(
    incident_id: uuid.UUID,
    body: IncidentStateIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    order = list(logic.IN_PROGRESS)
    if order.index(body.state) <= order.index(inc.state):
        raise api_error(409, "state", f"This incident is already {inc.state}.")
    was, inc.state = inc.state, body.state
    db.flush()
    logic.add_entry(
        db, inc, "event", f"Marked {body.state}: {body.note}",
        {"from": was, "state": body.state}, ctx.user_id,
    )  # fmt: skip
    _audit(db, ctx, f"incident.{body.state}", inc, note=body.note)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/verify", response_model=IncidentVerifyOut)
def verify_incident(
    incident_id: uuid.UUID,
    db: DB,
    background: BackgroundTasks,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentVerifyOut:
    """Queues the monitor's own check for each alert a check can look for again."""
    from nightfall.recon.routes import _drain_later

    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    req = logic.request_verification(db, inc, ctx.user_id, utcnow())
    if req.queued:
        logic.add_entry(
            db, inc, "event",
            "Verification requested: "
            + ", ".join(f"{q['tool']} check of {q['target']}" for q in req.queued),
            {"operations": [q["operation_id"] for q in req.queued]}, ctx.user_id,
        )  # fmt: skip
        _audit(db, ctx, "incident.verification_requested", inc, queued=req.queued)
        _drain_later(background)
    return IncidentVerifyOut(queued=req.queued, skipped=req.skipped)


# --- Admin and owner -------------------------------------------------------------------------


@router.post("/incidents/{incident_id}/severity", response_model=IncidentDetailOut)
def change_severity(
    incident_id: uuid.UUID,
    body: IncidentSeverityIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(MANAGE),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    was = inc.severity.value
    inc.severity, inc.severity_reason = body.severity, body.reason
    db.flush()
    logic.add_entry(
        db, inc, "event", f"Severity {was} → {body.severity.value}: {body.reason}",
        {"from": was, "severity": body.severity.value}, ctx.user_id,
    )  # fmt: skip
    _audit(db, ctx, "incident.severity_changed", inc, severity=body.severity.value)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/lead", response_model=IncidentDetailOut)
def change_lead(
    incident_id: uuid.UUID,
    body: IncidentLeadIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(MANAGE),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    member = db.scalar(
        select(WorkspaceMember.user_id).where(
            WorkspaceMember.workspace_id == ctx.workspace_id,
            WorkspaceMember.user_id == body.user_id,
        )
    )
    if member is None:
        raise api_error(422, "not_a_member", "The lead must be a member of this workspace.")
    inc.lead_user_id = body.user_id
    db.flush()
    name = _names(db, {body.user_id}).get(body.user_id, "—")
    logic.add_entry(db, inc, "event", f"Lead: {name}", {"lead": str(body.user_id)}, ctx.user_id)
    _audit(db, ctx, "incident.lead_changed", inc, lead=str(body.user_id))
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/cancel", response_model=IncidentDetailOut)
def cancel_incident(
    incident_id: uuid.UUID,
    body: IncidentReasonIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(MANAGE),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    logic.add_entry(
        db, inc, "event", f"Cancelled: {body.reason}", {"state": "cancelled"}, ctx.user_id
    )
    inc.state, inc.cancel_reason = "cancelled", body.reason
    db.flush()
    _audit(db, ctx, "incident.cancelled", inc, reason=body.reason)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/close", response_model=IncidentDetailOut)
def close_incident(
    incident_id: uuid.UUID,
    body: IncidentCloseIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(MANAGE),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    _in_progress(inc)
    blockers = _blockers(db, inc)
    if blockers and not body.override_reason:
        raise api_error(
            409, "not_verified",
            "Not verified: " + " ".join(blockers) + " Verify again, or close with an override "
            "and its reason.",
        )  # fmt: skip
    if blockers and not ctx.auth.mfa_fresh:
        raise api_error(
            403, "mfa_required",
            "Closing without verification needs your authenticator code from the last 15 minutes.",
        )  # fmt: skip
    override = body.override_reason if blockers else ""
    now = utcnow()
    review = body.review.model_dump()
    # The closing entry carries the review, so the record survives a later reopen.
    if override:
        how = f"Closed with an override: {override}."
    elif logic.verification(db, inc):
        how = "Closed, verified."
    else:
        how = "Closed on its review: no linked alert is one a check can look for again."
    logic.add_entry(
        db, inc, "event",
        how,
        {"state": "closed", "override": bool(override), "review": review, "unverified": blockers},
        ctx.user_id,
    )  # fmt: skip
    for al in logic.linked_alerts(db, inc.id):
        if al.state != "resolved":
            al.state, al.resolved_by_user_id, al.resolved_at = "resolved", ctx.user_id, now
            al.note = f"Closed with incident {inc.id}"[:1000]
            record(
                db, "alert.resolved", entity_type="alert", entity_id=al.id,
                data={"project_id": str(al.project_id), "kind": al.kind,
                      "note": al.note, "incident_id": str(inc.id)},
                **ctx.audit_kwargs(),
            )  # fmt: skip
    inc.state, inc.closed_by_user_id, inc.closed_at = "closed", ctx.user_id, now
    inc.review, inc.override_reason = review, override
    db.flush()
    _audit(db, ctx, "incident.closed", inc, override=bool(override), unverified=blockers)
    return _detail(db, inc)


@router.post("/incidents/{incident_id}/reopen", response_model=IncidentDetailOut)
def reopen_incident(
    incident_id: uuid.UUID,
    body: IncidentReasonIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(MANAGE),
) -> IncidentDetailOut:
    inc = _incident(db, ctx, incident_id)
    if inc.state != "closed":
        raise api_error(409, "not_closed", "Only a closed incident can be reopened.")
    inc.state, inc.closed_by_user_id, inc.closed_at = "open", None, None
    inc.review, inc.override_reason = None, ""
    db.flush()
    logic.add_entry(db, inc, "event", f"Reopened: {body.reason}", {"state": "open"}, ctx.user_id)
    _audit(db, ctx, "incident.reopened", inc, reason=body.reason)
    return _detail(db, inc)
