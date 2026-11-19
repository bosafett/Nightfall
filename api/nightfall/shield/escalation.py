"""SHIELD: a person turns a sensor alert into incident work (v3 decision 4, option c: owner
2026-11-19). No migration.

Incidents belong to a project; sensors and their alerts belong to the workspace, so nothing
opens or joins an incident automatically. From an intrusion alert (CrowdSec) or a host alert
(osquery), a person with the incident-work permission either opens a new incident in a project
they choose, or adds the alert to an incident in progress. The alert is written to the incident
timeline as an event (what, where, when, and that it came from a sensor); an intrusion alert
also records the incident in its existing incident_id column. Host alerts have no such column,
so their link is the timeline entry and the audit trail.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter
from pydantic import model_validator
from sqlalchemy.orm import Session

from nightfall.core.db.models import (
    Incident,
    Project,
    Severity,
    ShieldHostAlert,
    ShieldIntrusionAlert,
    ShieldSensor,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.shield import incidents as logic
from nightfall.shield.incident_routes import WORK, IncidentDetailOut, _audit, _detail
from nightfall.shield.incident_routes import Short as IncidentTitle

router = APIRouter(prefix="/api/workspaces/{workspace_id}/shield", tags=["shield"])


class EscalateIn(Model):
    """Exactly one: open a new incident in project_id, or add to incident_id."""

    project_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    title: IncidentTitle | None = None  # new incidents only; defaults to the alert's title

    @model_validator(mode="after")
    def _one(self) -> EscalateIn:
        if (self.project_id is None) == (self.incident_id is None):
            raise ValueError("Give either project_id (new incident) or incident_id (existing).")
        return self


def _target(
    db: Session, ctx: WorkspaceContext, body: EscalateIn, title: str, sev: Severity
) -> Incident:
    if body.incident_id is not None:
        inc = db.get(Incident, body.incident_id)
        if inc is None or inc.workspace_id != ctx.workspace_id:
            raise not_found("Incident not found.")
        if inc.state not in logic.IN_PROGRESS:
            raise api_error(409, "incident_ended", "That incident is closed or cancelled.")
        return inc
    project = db.get(Project, body.project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    inc = Incident(
        workspace_id=ctx.workspace_id, project_id=project.id, title=(body.title or title)[:200],
        summary="Opened from a SHIELD sensor alert.", severity=sev,
        lead_user_id=ctx.user_id, opened_by_user_id=ctx.user_id,
    )  # fmt: skip
    db.add(inc)
    db.flush()
    logic.add_entry(db, inc, "event", "Incident opened.", {"state": "open"}, ctx.user_id)
    _audit(db, ctx, "incident.opened", inc, severity=inc.severity.value, from_sensor_alert=True)
    return inc


def _record(
    db: Session, ctx: WorkspaceContext, inc: Incident, text: str, data: dict[str, Any]
) -> IncidentDetailOut:
    logic.add_entry(db, inc, "event", text[:4000], data, ctx.user_id)
    _audit(db, ctx, "incident.sensor_alert_added", inc, **data)
    return _detail(db, inc)


@router.post("/escalations/{kind}/{alert_id}", response_model=IncidentDetailOut, status_code=201)
def escalate(
    kind: Literal["intrusion-alerts", "host-alerts"],
    alert_id: uuid.UUID,
    body: EscalateIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(WORK),
) -> IncidentDetailOut:
    if kind == "intrusion-alerts":
        a = db.get(ShieldIntrusionAlert, alert_id)
        if a is None or a.workspace_id != ctx.workspace_id:
            raise not_found("Intrusion alert not found.")
        sensor = db.get(ShieldSensor, a.sensor_id)
        title = f"{a.scenario} from {a.source}"
        inc = _target(db, ctx, body, title, a.severity)
        a.incident_id = inc.id
        text = (
            f"Sensor alert added: {a.scenario} ({a.category}) from {a.source} on "
            f"{sensor.name if sensor else '?'}, {a.count} event(s), "
            f"{a.event_time:%Y-%m-%d %H:%M} to {a.last_event_time:%Y-%m-%d %H:%M} UTC. "
            "Reported by the sensor: untrusted data, not verified."
        )
        data: dict[str, Any] = {
            "alert_kind": "intrusion", "alert_id": str(a.id), "sensor_id": str(a.sensor_id),
            "source": str(a.source), "category": a.category,
        }  # fmt: skip
    else:
        h = db.get(ShieldHostAlert, alert_id)
        if h is None or h.workspace_id != ctx.workspace_id:
            raise not_found("Host alert not found.")
        sensor = db.get(ShieldSensor, h.sensor_id)
        inc = _target(db, ctx, body, h.title, h.severity)
        hypothesis = (
            " Marked possible compromise (an attack on the same machine within the hour before): "
            "a hypothesis, unconfirmed."
            if h.correlated_alert_id
            else ""
        )
        text = (
            f"Host alert added: {h.title} on {sensor.name if sensor else '?'}, observed "
            f"{h.observed_at:%Y-%m-%d %H:%M} UTC. Reported by the machine's osquery: what the "
            f"machine showed, not proof.{hypothesis}"
        )
        corr = str(h.correlated_alert_id) if h.correlated_alert_id else None
        data = {"alert_kind": "host", "alert_id": str(h.id), "sensor_id": str(h.sensor_id),
                "category": h.category, "correlated_alert_id": corr}  # fmt: skip
    return _record(db, ctx, inc, text, data)
