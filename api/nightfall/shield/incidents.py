"""SHIELD v2 incidents: the timeline, the checklist and verification
(docs/designs/2026-11-shield-incident-response.md).

An incident is a record and a workflow. Actions are statements by named people about what
they did outside JANUS; nothing here performs one. Verification re-runs the check that
raised an alert, as an ordinary operation under that alert's live monitor authorization, so
every rule of scheduled monitoring applies (scope version, target, tool, risk, expiry, the
daily cap) and the worker re-checks them. It can't run anything the monitor couldn't.

What JANUS says after a verification run is "not observed in this check" or "still
present". Only a person closes an incident.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nightfall.core.db.models import (
    Alert,
    Evidence,
    Incident,
    IncidentEntry,
    IncidentItem,
    MonitorAuthorization,
    Operation,
    OperationStatus,
)
from nightfall.shield import rules

IN_PROGRESS = ("open", "contained", "recovering")
PENDING = (OperationStatus.QUEUED, OperationStatus.RUNNING, OperationStatus.AWAITING_APPROVAL)


def add_entry(
    db: Session,
    incident: Incident,
    kind: str,
    body: str,
    data: dict[str, Any] | None = None,
    actor: uuid.UUID | None = None,
) -> IncidentEntry:
    e = IncidentEntry(
        workspace_id=incident.workspace_id,
        incident_id=incident.id,
        kind=kind,
        body=body[:4000],
        data=data or {},
        actor_user_id=actor,
    )
    db.add(e)
    db.flush()
    return e


def linked_alerts(db: Session, incident_id: uuid.UUID) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentItem, IncidentItem.item_id == Alert.id)
            .where(
                IncidentItem.incident_id == incident_id,
                IncidentItem.kind == "alert",
                IncidentItem.removed_at.is_(None),
            )
            .order_by(Alert.first_seen_at)
        ).all()
    )


def verify_tool(db: Session, alert: Alert) -> str | None:
    """The check that can look for this alert's condition again, or None."""
    if alert.kind not in rules.VERIFY_TOOL:
        return None
    tool = rules.VERIFY_TOOL[alert.kind] or (alert.data or {}).get("tool")
    if tool is None and alert.evidence_ids:
        # finding.reopened raised before the tool was kept: the check behind its evidence.
        tool = db.scalar(
            select(Operation.tool)
            .join(Evidence, Evidence.operation_id == Operation.id)
            .where(Evidence.id == alert.evidence_ids[-1])
        )
    return str(tool) if tool else None


# --- Checklist -------------------------------------------------------------------------------


def checklist(db: Session, incident_id: uuid.UUID) -> list[dict[str, Any]]:
    """Current state of each checklist item: the latest 'check' entry per key, in the order
    the items were first added."""
    rows = db.scalars(
        select(IncidentEntry)
        .where(IncidentEntry.incident_id == incident_id, IncidentEntry.kind == "check")
        .order_by(IncidentEntry.seq)
    ).all()
    items: dict[str, dict[str, Any]] = {}
    for e in rows:
        key = str(e.data.get("key"))
        prev = items.get(key)
        items[key] = {
            "key": key,
            "text": str(e.data.get("text") or (prev or {}).get("text") or ""),
            "done": bool(e.data.get("done")),
            "source": str(e.data.get("source") or (prev or {}).get("source") or "added"),
            "changed_by_user_id": e.actor_user_id,
            "changed_at": e.created_at,
        }
    return list(items.values())


def seed_checklist(db: Session, incident: Incident, alert: Alert, actor: uuid.UUID) -> None:
    """The alert's recommended fix becomes a checklist item (recommendation only)."""
    text = rules.RECOMMEND.get(alert.kind)
    key = f"alert:{alert.id}"
    if not text or any(i["key"] == key for i in checklist(db, incident.id)):
        return
    add_entry(
        db, incident, "check", f"Checklist: {text}",
        {"key": key, "text": f"{alert.target or alert.title}: {text}", "done": False,
         "source": "recommendation"},
        actor,
    )  # fmt: skip


# --- Verification ----------------------------------------------------------------------------


@dataclass
class Verification:
    alert_id: uuid.UUID
    title: str
    target: str
    tool: str | None
    state: str  # not_requested | pending | not_observed | still_present | undecided | failed
    detail: str
    operation_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    at: datetime | None = None
    counts: bool = False  # "not observed" in a check made after the last recorded action


def last_action_seq(db: Session, incident_id: uuid.UUID) -> int | None:
    return db.scalar(
        select(func.max(IncidentEntry.seq)).where(
            IncidentEntry.incident_id == incident_id, IncidentEntry.kind == "action"
        )
    )


def verification(db: Session, incident: Incident) -> list[Verification]:
    """One line per linked alert that a check can look for again."""
    out: list[Verification] = []
    after = last_action_seq(db, incident.id)
    results = db.scalars(
        select(IncidentEntry)
        .where(IncidentEntry.incident_id == incident.id, IncidentEntry.kind == "verification")
        .order_by(IncidentEntry.seq.desc())
    ).all()
    latest: dict[str, IncidentEntry] = {}
    for e in results:
        latest.setdefault(str(e.data.get("alert_id")), e)
    for al in linked_alerts(db, incident.id):
        tool = verify_tool(db, al)
        if al.kind not in rules.VERIFY_TOOL:
            continue
        v = Verification(al.id, al.title, al.target, tool, "not_requested", "Not checked yet.")
        pending = tool is not None and db.scalar(
            select(Operation.id).where(
                Operation.incident_id == incident.id,
                Operation.tool == tool,
                Operation.target_value == al.target,
                Operation.status.in_(PENDING),
            )
        )
        last = latest.get(str(al.id))
        if pending:
            v.state, v.detail, v.operation_id = "pending", "A check is waiting to run.", pending
        elif last is not None:
            e = last
            v.state = str(e.data.get("result"))
            v.detail = e.body
            v.at = e.created_at
            op_id, ev_id = e.data.get("operation_id"), e.data.get("evidence_id")
            v.operation_id = uuid.UUID(op_id) if op_id else None
            v.evidence_id = uuid.UUID(ev_id) if ev_id else None
            v.counts = v.state == "not_observed" and (after is None or e.seq > after)
            if v.state == "not_observed" and not v.counts:
                v.detail += " An action was recorded after this check: verify again."
        out.append(v)
    return out


def unverified(db: Session, incident: Incident) -> list[Verification]:
    return [v for v in verification(db, incident) if not v.counts]


@dataclass
class VerifyRequest:
    queued: list[dict[str, str]]
    skipped: list[dict[str, str]]


def request_verification(
    db: Session, incident: Incident, actor: uuid.UUID, now: datetime
) -> VerifyRequest:
    """Queues the monitor's own check for each verifiable alert. Never widens anything: no
    live authorization covering the alert's target and check means no run."""
    from nightfall.recon.collectors import TOOLS
    from nightfall.scope.engine import evaluate
    from nightfall.scope.repository import active_scope, snapshot
    from nightfall.shield.scheduler import DAILY_CAP

    req = VerifyRequest([], [])
    used = (
        db.scalar(
            select(func.count())
            .select_from(Operation)
            .where(
                Operation.workspace_id == incident.workspace_id,
                Operation.monitor_authorization_id.is_not(None),
                Operation.created_at >= now - timedelta(hours=24),
            )
        )
        or 0
    )
    current = active_scope(db, incident.project_id)
    snap = snapshot(db, current) if current is not None else None
    seen: set[tuple[str, str]] = set()

    def skip(al: Alert, why: str) -> None:
        req.skipped.append({"alert_id": str(al.id), "title": al.title, "reason": why})

    for al in linked_alerts(db, incident.id):
        if al.kind not in rules.VERIFY_TOOL:
            continue
        tool = verify_tool(db, al)
        if tool is None:
            skip(al, "JANUS can't tell which check raised this alert.")
            continue
        if (tool, al.target) in seen:
            continue  # one run answers every alert of that target and check
        a = db.get(MonitorAuthorization, al.authorization_id) if al.authorization_id else None
        if a is not None and (a.ended_at is not None or a.expires_at <= now):
            # A renewal replaces the authorization: use the project's live one that covers it.
            a = None
        if a is None:
            live = db.scalars(
                select(MonitorAuthorization).where(
                    MonitorAuthorization.project_id == incident.project_id,
                    MonitorAuthorization.ended_at.is_(None),
                    MonitorAuthorization.expires_at > now,
                )
            ).all()
            a = next((x for x in live if al.target in x.targets and tool in x.checks), None)
        if a is None or al.target not in a.targets or tool not in a.checks:
            skip(al, f"No live monitor authorization covers the {tool} check of {al.target}. "
                 "Renew monitoring, or close with an override.")  # fmt: skip
            continue
        if current is None or snap is None or current.id != a.scope_id or current.is_lab:
            skip(al, "The project's authorized scope changed since monitoring was authorized.")
            continue
        decision = evaluate(snap, al.target, now)
        if not decision.allowed:
            skip(al, decision.reason)
            continue
        if used + len(req.queued) >= DAILY_CAP:
            skip(al, f"The daily cap of {DAILY_CAP} monitoring checks is reached. Try tomorrow.")
            continue
        busy = db.scalar(
            select(Operation.id).where(
                Operation.project_id == incident.project_id,
                Operation.tool == tool,
                Operation.target_value == decision.target,
                Operation.status.in_(PENDING),
            )
        )
        if busy is not None:
            skip(al, "A check of this target is already waiting to run. Try again when it ends.")
            continue
        label, risk = TOOLS[tool]
        op = Operation(
            workspace_id=incident.workspace_id,
            project_id=incident.project_id,
            scope_id=a.scope_id,
            tool=tool,
            risk_class=risk,
            target_value=decision.target,
            params={"method": label, "scheduled": True, "verification": True},
            requested_by_user_id=actor,
            monitor_authorization_id=a.id,
            incident_id=incident.id,
            status=OperationStatus.QUEUED,
        )
        db.add(op)
        db.flush()
        seen.add((tool, al.target))
        req.queued.append({"operation_id": str(op.id), "tool": tool, "target": decision.target})
    return req


def _targets(db: Session, op: Operation) -> list[Alert]:
    """Linked alerts this verification run can answer: same target, and this is their check."""
    if op.incident_id is None:
        return []
    return [
        al
        for al in linked_alerts(db, op.incident_id)
        if al.kind in rules.VERIFY_TOOL
        and al.target == op.target_value
        and verify_tool(db, al) == op.tool
    ]


def record_verification(
    db: Session,
    op: Operation,
    cur: dict[str, Any],
    finding_changes: list[dict[str, object]],
    evidence_id: uuid.UUID,
    now: datetime,
) -> None:
    """Worker, after a verification run succeeded: one result per alert it answers."""
    incident = db.get(Incident, op.incident_id)
    if incident is None:
        return
    observed = {str(ch.get("finding_id")) for ch in finding_changes}
    for al in _targets(db, op):
        present = rules.still_present(
            al.kind, al.data or {}, cur, now, str(al.finding_id) in observed
        )
        result = "undecided" if present is None else "still_present" if present else "not_observed"
        body = {
            "still_present": f"Still present: {al.title}",
            "not_observed": f"Not observed in this check: {al.title}",
            "undecided": f"This check couldn't decide: {al.title} (the alert was raised before "
            "JANUS kept the facts it needs).",
        }[result]
        add_entry(
            db, incident, "verification", body,
            {"alert_id": str(al.id), "operation_id": str(op.id), "evidence_id": str(evidence_id),
             "result": result, "tool": op.tool, "target": op.target_value},
        )  # fmt: skip


def record_verification_failed(db: Session, op: Operation, reason: str) -> None:
    incident = db.get(Incident, op.incident_id)
    if incident is None:
        return
    for al in _targets(db, op):
        add_entry(
            db, incident, "verification",
            f"The check didn't run: {reason[:500] or 'it failed'}",
            {"alert_id": str(al.id), "operation_id": str(op.id), "result": "failed",
             "tool": op.tool, "target": op.target_value},
        )  # fmt: skip
