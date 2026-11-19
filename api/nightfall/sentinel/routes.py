"""SENTINEL step 3a: indicator list, indicator page and a person's assessment (design
docs/designs/2026-11-sentinel-indicator-store.md §5-6; migration 0028).

What JANUS observed (computed confidence, never above medium) is shown apart from what a person
assessed. Only 'malicious' makes the effective confidence high. 'benign' and 'false_positive'
suppress the indicator: new sightings are still recorded, nothing is deleted, a person can undo
it. Assessments go through nf_sentinel_assess (history in the same step, the assessor taken from
the session) and into the audit trail. Analysts and above assess; any member reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import StringConstraints
from sqlalchemy import or_, select, text
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Alert,
    IncidentEntry,
    IncidentItem,
    SentinelAssessment,
    SentinelIndicator,
    SentinelSighting,
    ShieldBlock,
    ShieldHostAlert,
    ShieldHostChange,
    ShieldIntrusionAlert,
    ShieldSensor,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.warpath.catalogue import techniques as attack_catalogue

router = APIRouter(prefix="/api/workspaces/{workspace_id}/sentinel", tags=["sentinel"])

Assessment = Literal["unreviewed", "malicious", "benign", "false_positive"]
Status = Literal["active", "expired", "suppressed"]


def status_of(ind: SentinelIndicator, now: datetime) -> Status:
    if ind.assessment in ("benign", "false_positive"):
        return "suppressed"
    if ind.expires_at is not None and ind.expires_at <= now:
        return "expired"
    return "active"


def effective_confidence(ind: SentinelIndicator) -> str:
    return "high" if ind.assessment == "malicious" else ind.computed_confidence.value


class IndicatorOut(Model):
    id: uuid.UUID
    type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    sighting_count: int
    computed_confidence: str  # what JANUS observed: low or medium
    confidence: str  # effective: high only when a person assessed it malicious
    assessment: str
    assessment_reason: str
    assessed_by: str | None
    assessed_at: datetime | None
    expires_at: datetime | None
    status: Status


class SightingOut(Model):
    id: uuid.UUID
    source_kind: str
    source_id: uuid.UUID
    description: str  # sensor-reported data, shown as text
    sensor_id: uuid.UUID | None
    sensor_name: str | None
    techniques: list[str]
    event_time: datetime
    ingested_at: datetime
    incident_id: uuid.UUID | None


class AssessmentOut(Model):
    from_assessment: str
    to_assessment: str
    reason: str
    by: str
    at: datetime


class TechniqueOut(Model):
    id: str
    name: str


class IndicatorDetailOut(IndicatorOut):
    sightings: list[SightingOut]  # newest first, at most 200
    machines: list[str]  # sensors that saw it
    techniques: list[TechniqueOut]
    history: list[AssessmentOut]
    incidents: list[uuid.UUID]


class AssessIn(Model):
    assessment: Assessment
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


def _email(db: Session, uid: uuid.UUID | None) -> str | None:
    return None if uid is None else db.scalar(select(User.email).where(User.id == uid))


def _out(db: Session, ind: SentinelIndicator, now: datetime) -> IndicatorOut:
    return IndicatorOut(
        id=ind.id, type=ind.type, value=ind.value, first_seen=ind.first_seen,
        last_seen=ind.last_seen, sighting_count=ind.sighting_count,
        computed_confidence=ind.computed_confidence.value, confidence=effective_confidence(ind),
        assessment=ind.assessment, assessment_reason=ind.assessment_reason,
        assessed_by=_email(db, ind.assessed_by_user_id), assessed_at=ind.assessed_at,
        expires_at=ind.expires_at, status=status_of(ind, now),
    )  # fmt: skip


def _describe(db: Session, s: SentinelSighting) -> tuple[str, uuid.UUID | None]:
    """A short description of the source row, and the incident it's linked to (if any)."""
    if s.source_kind == "intrusion_alert":
        a = db.get(ShieldIntrusionAlert, s.source_id)
        if a is not None:
            return f"{a.scenario} ({a.category}), {a.count} event(s)", a.incident_id
    elif s.source_kind == "block":
        b = db.get(ShieldBlock, s.source_id)
        if b is not None:
            return f"{'GUARD' if b.tier == 'automatic' else 'Approved'} block of {b.target}", None
    elif s.source_kind == "host_alert":
        h = db.get(ShieldHostAlert, s.source_id)
        if h is not None:
            return f"Host alert: {h.title}", None
    elif s.source_kind == "host_change":
        c = db.get(ShieldHostChange, s.source_id)
        if c is not None:
            return f"Watched file {c.action}: {c.item.get('path')}", None
        return "Watched file change (older than the 90-day host log)", None
    elif s.source_kind == "aegis_alert":
        al = db.get(Alert, s.source_id)
        if al is not None:
            inc = db.scalar(
                select(IncidentItem.incident_id)
                .where(IncidentItem.kind == "alert", IncidentItem.item_id == al.id,
                       IncidentItem.removed_at.is_(None))
                .order_by(IncidentItem.added_at)
                .limit(1)
            )  # fmt: skip
            return f"AEGIS: {al.title}", inc
    elif s.source_kind == "incident_entry":
        e = db.get(IncidentEntry, s.source_id)
        if e is not None:
            return "Entered by a person on an incident", e.incident_id
    return f"{s.source_kind} (source no longer available)", None


@router.get("/indicators", response_model=list[IndicatorOut])
def list_indicators(
    db: DB,
    type: Annotated[  # noqa: A002 - the API field name
        Literal["ip", "domain", "url", "sha256", "cert_sha256", "user_agent"] | None, Query()
    ] = None,
    status: Annotated[Literal["active", "all"], Query()] = "active",
    q: Annotated[str | None, Query(max_length=200)] = None,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[IndicatorOut]:
    now = utcnow()
    stmt = select(SentinelIndicator).where(SentinelIndicator.workspace_id == ctx.workspace_id)
    if type:
        stmt = stmt.where(SentinelIndicator.type == type)
    if q:
        stmt = stmt.where(SentinelIndicator.value.contains(q.strip().lower(), autoescape=True))
    if status == "active":
        stmt = stmt.where(
            SentinelIndicator.assessment.not_in(("benign", "false_positive")),
            or_(SentinelIndicator.expires_at.is_(None), SentinelIndicator.expires_at > now),
        )
    rows = db.scalars(stmt.order_by(SentinelIndicator.last_seen.desc()).limit(500)).all()
    return [_out(db, i, now) for i in rows]


def _indicator(db: Session, ctx: WorkspaceContext, indicator_id: uuid.UUID) -> SentinelIndicator:
    ind = db.get(SentinelIndicator, indicator_id)
    if ind is None or ind.workspace_id != ctx.workspace_id:
        raise not_found("Indicator not found.")
    return ind


def _detail(db: Session, ind: SentinelIndicator) -> IndicatorDetailOut:
    now = utcnow()
    sightings = db.scalars(
        select(SentinelSighting)
        .where(SentinelSighting.indicator_id == ind.id)
        .order_by(SentinelSighting.event_time.desc())
        .limit(200)
    ).all()
    names = {
        s.id: s.name
        for s in db.scalars(
            select(ShieldSensor).where(
                ShieldSensor.id.in_({x.sensor_id for x in sightings if x.sensor_id})
            )
        )
    }
    out, incidents, tags = [], [], []
    for s in sightings:
        desc, inc = _describe(db, s)
        if inc and inc not in incidents:
            incidents.append(inc)
        tags += [t for t in s.techniques if t not in tags]
        out.append(
            SightingOut(
                id=s.id,
                source_kind=s.source_kind,
                source_id=s.source_id,
                description=desc,
                sensor_id=s.sensor_id,
                sensor_name=names.get(s.sensor_id) if s.sensor_id else None,
                techniques=list(s.techniques),
                event_time=s.event_time,
                ingested_at=s.ingested_at,
                incident_id=inc,
            )  # fmt: skip
        )
    catalogue = attack_catalogue()
    history = db.scalars(
        select(SentinelAssessment)
        .where(SentinelAssessment.indicator_id == ind.id)
        .order_by(SentinelAssessment.at.desc())
    ).all()
    base = _out(db, ind, now)
    return IndicatorDetailOut(
        **base.model_dump(),
        sightings=out,
        machines=sorted(
            {n for n in (names.get(x.sensor_id) for x in sightings if x.sensor_id) if n}
        ),
        techniques=[
            TechniqueOut(id=t, name=catalogue[t].name if t in catalogue else t) for t in tags
        ],
        history=[
            AssessmentOut(
                from_assessment=h.from_assessment,
                to_assessment=h.to_assessment,
                reason=h.reason,
                by=_email(db, h.user_id) or "?",
                at=h.at,
            )  # fmt: skip
            for h in history
        ],
        incidents=incidents,
    )


@router.get("/indicators/{indicator_id}", response_model=IndicatorDetailOut)
def get_indicator(
    indicator_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> IndicatorDetailOut:
    return _detail(db, _indicator(db, ctx, indicator_id))


@router.post("/indicators/{indicator_id}/assess", response_model=IndicatorDetailOut)
def assess(
    indicator_id: uuid.UUID,
    body: AssessIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> IndicatorDetailOut:
    ind = _indicator(db, ctx, indicator_id)
    before = ind.assessment
    db.execute(
        text("SELECT nf_sentinel_assess(:i, :a, :r)"),
        {"i": ind.id, "a": body.assessment, "r": body.reason},
    )
    db.refresh(ind)
    record(
        db, "sentinel.assessed", entity_type="sentinel_indicator", entity_id=ind.id,
        data={"type": ind.type, "value": ind.value, "from": before, "to": body.assessment,
              "reason": body.reason},
        **ctx.audit_kwargs(),
    )  # fmt: skip
    return _detail(db, ind)
