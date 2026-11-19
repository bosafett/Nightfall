"""SENTINEL step 3b: correlation on an incident, and "knows versus suspects" (design
docs/designs/2026-11-sentinel-indicator-store.md §6). No migration; computed when read.

From the sensor alerts a person linked to the incident (decision 4 (c)):

* shared indicators: every indicator those alerts produced, with its sightings elsewhere;
* suggestions: other alerts that share an indicator, each with its reason. Adding one is the
  same manual action as decision 4 (c); nothing is attached automatically (owner decision 4);
* the technique sequence: ATT&CK techniques the linked alerts imply, in time order;
* knows versus suspects: what a person validated (assessed indicators, validated findings)
  apart from what JANUS inferred (computed confidence, the possible-compromise rule, unreviewed
  or AI findings, correlation) and the investigator's own list of unknowns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import StringConstraints
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Alert,
    Finding,
    FindingOrigin,
    Incident,
    IncidentEntry,
    IncidentItem,
    SentinelIndicator,
    SentinelSighting,
    ShieldHostAlert,
    ShieldIntrusionAlert,
    ShieldSensor,
    User,
    ValidationStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.sentinel import extract
from nightfall.sentinel.routes import IndicatorOut, _describe, _out
from nightfall.shield import incidents as logic
from nightfall.shield.incident_routes import WORK, _audit, _in_progress
from nightfall.warpath.catalogue import techniques as attack_catalogue

router = APIRouter(prefix="/api/workspaces/{workspace_id}/sentinel", tags=["sentinel"])

# The two alert kinds a person can link (decision 4 (c)), as sightings name them and as the
# escalation route names them.
LINKABLE = {"intrusion_alert": "intrusion-alerts", "host_alert": "host-alerts"}
# Step 3c: an AEGIS alert is added as an incident item (same project, not resolved).
AEGIS_LINK = "aegis-alerts"


class RelatedOut(Model):
    source_kind: str
    source_id: uuid.UUID
    description: str
    sensor_name: str | None
    event_time: datetime
    incident_id: uuid.UUID | None
    escalation_kind: str | None  # set when a person can add it to this incident
    reason: str


class SharedIndicatorOut(Model):
    indicator: IndicatorOut
    machines: list[str]
    elsewhere: list[RelatedOut]  # sightings not from this incident's linked alerts


class StepOut(Model):
    event_time: datetime
    technique_id: str
    technique_name: str
    description: str
    sensor_name: str | None


class StatementOut(Model):
    kind: str
    text: str
    by: str | None = None
    at: datetime | None = None


class CorrelationOut(Model):
    linked_alerts: int
    shared_indicators: list[SharedIndicatorOut]
    suggestions: list[RelatedOut]  # alerts a person may add, each with its reason
    sequence: list[StepOut]
    knows: list[StatementOut]  # validated by a person
    suspects: list[StatementOut]  # inferred by JANUS, or not yet reviewed
    unknowns: list[StatementOut]  # the investigator's own list (notes marked unknown)


def linked_sources(db: Session, inc: Incident) -> set[tuple[str, uuid.UUID]]:
    """Sensor alerts linked to the incident: from its timeline entries (decision 4 (c)) and
    from intrusion alerts that record it."""
    out: set[tuple[str, uuid.UUID]] = set()
    for data in db.scalars(
        select(IncidentEntry.data).where(
            IncidentEntry.incident_id == inc.id, IncidentEntry.data["alert_kind"].isnot(None)
        )
    ):
        kind = {"intrusion": "intrusion_alert", "host": "host_alert"}.get(
            str(data.get("alert_kind"))
        )
        try:
            if kind:
                out.add((kind, uuid.UUID(str(data.get("alert_id")))))
        except ValueError:
            continue
    for aid in db.scalars(
        select(ShieldIntrusionAlert.id).where(ShieldIntrusionAlert.incident_id == inc.id)
    ):
        out.add(("intrusion_alert", aid))
    for aid in db.scalars(
        select(IncidentItem.item_id).where(
            IncidentItem.incident_id == inc.id, IncidentItem.kind == "alert",
            IncidentItem.removed_at.is_(None),
        )
    ):  # fmt: skip
        out.add(("aegis_alert", aid))
    return out


def entered_sources(db: Session, inc: Incident) -> set[tuple[str, uuid.UUID]]:
    """Indicators a person entered on this incident (step 3c): their timeline entries."""
    return {
        ("incident_entry", eid)
        for eid in db.scalars(
            select(IncidentEntry.id).where(
                IncidentEntry.incident_id == inc.id,
                IncidentEntry.data["sentinel_indicator"].isnot(None),
            )
        )
    }


def _link_kind(
    db: Session, inc: Incident, o: SentinelSighting, other_inc: uuid.UUID | None
) -> str | None:
    """How a person would add this sighting's source to the incident, if they can."""
    if other_inc == inc.id:
        return None
    if o.source_kind == "aegis_alert":
        al = db.get(Alert, o.source_id)
        ok = al is not None and al.project_id == inc.project_id and al.state != "resolved"
        return AEGIS_LINK if ok else None
    return LINKABLE.get(o.source_kind)


def _email(db: Session, uid: uuid.UUID | None) -> str | None:
    return None if uid is None else db.scalar(select(User.email).where(User.id == uid))


def correlate(db: Session, inc: Incident) -> CorrelationOut:
    now = utcnow()
    linked = linked_sources(db, inc)
    mine = linked | entered_sources(db, inc)
    own: list[SentinelSighting] = (
        list(
            db.scalars(
                select(SentinelSighting).where(
                    tuple_(SentinelSighting.source_kind, SentinelSighting.source_id).in_(mine)
                )
            )
        )
        if mine
        else []
    )
    names = {s.id: s.name for s in db.scalars(select(ShieldSensor))}
    catalogue = attack_catalogue()

    # Shared indicators and suggestions.
    shared, suggestions, seen_suggestions = [], [], set()
    ind_ids = list(dict.fromkeys(s.indicator_id for s in own if s.indicator_id))
    for ind_id in ind_ids:
        ind = db.get(SentinelIndicator, ind_id)
        if ind is None:
            continue
        others = db.scalars(
            select(SentinelSighting)
            .where(SentinelSighting.indicator_id == ind.id)
            .order_by(SentinelSighting.event_time.desc())
            .limit(200)
        ).all()
        n_linked = sum((o.source_kind, o.source_id) in linked for o in others)
        reason = (
            f"Shares {ind.type} {ind.value} with {n_linked} linked alert(s)"
            if n_linked
            else f"Shares {ind.type} {ind.value}, entered on this incident"
        )
        elsewhere = []
        for o in others:
            if (o.source_kind, o.source_id) in mine:
                continue
            desc, other_inc = _describe(db, o)
            r = RelatedOut(
                source_kind=o.source_kind, source_id=o.source_id, description=desc,
                sensor_name=names.get(o.sensor_id) if o.sensor_id else None,
                event_time=o.event_time, incident_id=other_inc,
                escalation_kind=_link_kind(db, inc, o, other_inc),
                reason=reason,
            )  # fmt: skip
            elsewhere.append(r)
            key = (o.source_kind, o.source_id)
            suppressed = ind.assessment in ("benign", "false_positive")
            if r.escalation_kind and key not in seen_suggestions and not suppressed:
                seen_suggestions.add(key)
                suggestions.append(r)
        machines = sorted({names[o.sensor_id] for o in others if o.sensor_id in names})
        shared.append(SharedIndicatorOut(indicator=_out(db, ind, now), machines=machines,
                                         elsewhere=elsewhere))  # fmt: skip

    # Technique sequence, in time order.
    sequence = []
    for s in sorted(own, key=lambda x: x.event_time):
        desc, _ = _describe(db, s)
        for t in s.techniques:
            sequence.append(
                StepOut(
                    event_time=s.event_time,
                    technique_id=t,
                    technique_name=catalogue[t].name if t in catalogue else t,
                    description=desc,
                    sensor_name=names.get(s.sensor_id) if s.sensor_id else None,
                )  # fmt: skip
            )

    # Knows versus suspects.
    knows: list[StatementOut] = []
    suspects: list[StatementOut] = []
    for sh in shared:
        i = sh.indicator
        if i.assessment == "unreviewed":
            suspects.append(StatementOut(
                kind="indicator_unreviewed",
                text=f"{i.type} {i.value}: {i.computed_confidence} confidence from "
                     f"{i.sighting_count} sighting(s), not yet assessed by a person"))  # fmt: skip
        else:
            label = {"malicious": "malicious", "benign": "benign",
                     "false_positive": "a false positive"}[i.assessment]  # fmt: skip
            knows.append(StatementOut(kind="indicator_assessed",
                                      text=f"{i.type} {i.value} assessed as {label}: "
                                           f"{i.assessment_reason}",
                                      by=i.assessed_by, at=i.assessed_at))  # fmt: skip
    host_ids = [sid for kind, sid in linked if kind == "host_alert"]
    for h in (
        db.scalars(select(ShieldHostAlert).where(ShieldHostAlert.id.in_(host_ids)))
        if host_ids
        else []
    ):
        if h.correlated_alert_id:
            suspects.append(StatementOut(
                kind="possible_compromise",
                text=f"Possible compromise, unconfirmed: {h.title} on "
                     f"{names.get(h.sensor_id, '?')}, within the hour after an attack on the "
                     "same machine",
                at=h.observed_at))  # fmt: skip
    if suggestions:
        suspects.append(StatementOut(
            kind="correlation",
            text=f"{len(suggestions)} other alert(s) share an indicator with this incident "
                 "(correlation, not confirmed as the same activity)"))  # fmt: skip
    finding_ids = db.scalars(
        select(IncidentItem.item_id).where(
            IncidentItem.incident_id == inc.id, IncidentItem.kind == "finding",
            IncidentItem.removed_at.is_(None),
        )
    ).all()  # fmt: skip
    for f in db.scalars(select(Finding).where(Finding.id.in_(finding_ids))) if finding_ids else []:
        vs = f.validation_status
        if vs in (ValidationStatus.VALIDATED, ValidationStatus.REMEDIATED):
            knows.append(StatementOut(kind="finding_validated",
                                      text=f"Finding {f.title}: {vs.value} by a person",
                                      by=_email(db, f.validated_by_user_id),
                                      at=f.validated_at))  # fmt: skip
        elif vs is ValidationStatus.FALSE_POSITIVE:
            knows.append(StatementOut(kind="finding_ruled_out",
                                      text=f"Finding {f.title}: ruled out (false positive)",
                                      by=_email(db, f.validated_by_user_id),
                                      at=f.validated_at))  # fmt: skip
        else:
            who = (
                "an AI agent"
                if f.origin is FindingOrigin.AGENT
                else "a rule"
                if (f.origin is FindingOrigin.DETERMINISTIC_CHECK)
                else "a person"
            )
            suspects.append(StatementOut(kind="finding_unvalidated",
                                         text=f"Finding {f.title}: {vs.value}, proposed by {who}, "
                                              "not validated"))  # fmt: skip
    unknowns = [
        StatementOut(kind="unknown", text=e.body, by=_email(db, e.actor_user_id), at=e.created_at)
        for e in db.scalars(
            select(IncidentEntry)
            .where(
                IncidentEntry.incident_id == inc.id,
                IncidentEntry.kind == "note",
                IncidentEntry.data["unknown"].astext == "true",
            )  # fmt: skip
            .order_by(IncidentEntry.created_at)
        )
    ]
    return CorrelationOut(
        linked_alerts=len(linked), shared_indicators=shared, suggestions=suggestions,
        sequence=sequence, knows=knows, suspects=suspects, unknowns=unknowns,
    )  # fmt: skip


@router.get("/incidents/{incident_id}/correlation", response_model=CorrelationOut)
def incident_correlation(
    incident_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> CorrelationOut:
    inc = db.get(Incident, incident_id)
    if inc is None or inc.workspace_id != ctx.workspace_id:
        raise not_found("Incident not found.")
    return correlate(db, inc)


class IndicatorEntryIn(Model):
    type: Literal["ip", "domain", "url", "sha256", "cert_sha256", "user_agent"]
    value: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] = ""


@router.post("/incidents/{incident_id}/indicators", response_model=IndicatorOut, status_code=201)
def enter_indicator(
    incident_id: uuid.UUID,
    body: IndicatorEntryIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IndicatorOut:
    """Step 3c: a person records an indicator from an investigation. It's a sighting of an
    unreviewed indicator (computed confidence as usual); assessing it is a separate step."""
    inc = db.get(Incident, incident_id)
    if inc is None or inc.workspace_id != ctx.workspace_id:
        raise not_found("Incident not found.")
    _in_progress(inc)
    try:
        value = extract.entered_value(db, ctx.workspace_id, body.type, body.value)
    except ValueError as exc:
        raise api_error(422, "invalid_indicator", str(exc)) from exc
    label = f"Indicator added: {body.type} {value}" + (f". {body.note}" if body.note else "")
    entry = logic.add_entry(
        db, inc, "event", label,
        {"sentinel_indicator": {"type": body.type, "value": value}}, ctx.user_id,
    )  # fmt: skip
    ind_id = extract.from_incident_entry(db, entry, body.type, value, utcnow())
    db.flush()
    _audit(db, ctx, "sentinel.indicator_entered", inc, type=body.type, value=value[:300])
    ind = db.get_one(SentinelIndicator, ind_id)
    db.refresh(ind)
    return _out(db, ind, utcnow())
