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

from fastapi import APIRouter
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
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
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.sentinel.routes import IndicatorOut, _describe, _out
from nightfall.warpath.catalogue import techniques as attack_catalogue

router = APIRouter(prefix="/api/workspaces/{workspace_id}/sentinel", tags=["sentinel"])

# The two alert kinds a person can link (decision 4 (c)), as sightings name them and as the
# escalation route names them.
LINKABLE = {"intrusion_alert": "intrusion-alerts", "host_alert": "host-alerts"}


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
    return out


def _email(db: Session, uid: uuid.UUID | None) -> str | None:
    return None if uid is None else db.scalar(select(User.email).where(User.id == uid))


def correlate(db: Session, inc: Incident) -> CorrelationOut:
    now = utcnow()
    linked = linked_sources(db, inc)
    own: list[SentinelSighting] = (
        list(
            db.scalars(
                select(SentinelSighting).where(
                    tuple_(SentinelSighting.source_kind, SentinelSighting.source_id).in_(linked)
                )
            )
        )
        if linked
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
        elsewhere = []
        for o in others:
            if (o.source_kind, o.source_id) in linked:
                continue
            desc, other_inc = _describe(db, o)
            reason = f"Shares {ind.type} {ind.value} with {n_linked} linked alert(s)"
            r = RelatedOut(
                source_kind=o.source_kind, source_id=o.source_id, description=desc,
                sensor_name=names.get(o.sensor_id) if o.sensor_id else None,
                event_time=o.event_time, incident_id=other_inc,
                escalation_kind=LINKABLE.get(o.source_kind) if other_inc != inc.id else None,
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
