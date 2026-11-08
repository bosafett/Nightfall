"""Raising alerts (worker side): one open alert per condition, updated when seen again."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.db.models import ActorType, Alert, Operation, Severity
from nightfall.shield import rules
from nightfall.shield.rules import AlertDraft


def raise_alert(
    db: Session,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    authorization_id: uuid.UUID | None,
    draft: AlertDraft,
    target: str,
    now: datetime,
    evidence_ids: list[uuid.UUID] | None = None,
    finding_id: uuid.UUID | None = None,
) -> Alert:
    existing = db.scalar(
        select(Alert).where(
            Alert.workspace_id == workspace_id,
            Alert.dedupe_key == draft.key,
            Alert.state != "resolved",
        )
    )
    if existing is not None:
        existing.last_seen_at = now
        existing.severity, existing.title, existing.detail = (
            draft.severity, draft.title, draft.detail,
        )  # fmt: skip
        if evidence_ids:
            existing.evidence_ids = list(dict.fromkeys([*existing.evidence_ids, *evidence_ids]))[
                -20:
            ]
        db.flush()
        return existing
    alert = Alert(
        workspace_id=workspace_id,
        project_id=project_id,
        authorization_id=authorization_id,
        kind=draft.kind,
        severity=draft.severity,
        title=draft.title[:300],
        detail=draft.detail[:4000],
        target=target[:300],
        dedupe_key=draft.key[:500],
        evidence_ids=evidence_ids or [],
        finding_id=finding_id,
        rules=rules.RULES,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(alert)
    db.flush()
    record(
        db,
        "alert.raised",
        actor_type=ActorType.SYSTEM,
        workspace_id=workspace_id,
        entity_type="alert",
        entity_id=alert.id,
        data={
            "project_id": str(project_id),
            "kind": draft.kind,
            "severity": draft.severity.value,
            "title": draft.title[:300],
            "target": target,
        },
    )
    return alert


def previous_snapshot(db: Session, op: Operation) -> dict[str, Any] | None:
    """The last successful scheduled run of the same project, target and check."""
    from nightfall.core.db.models import OperationStatus

    prev = db.scalar(
        select(Operation)
        .where(
            Operation.project_id == op.project_id,
            Operation.tool == op.tool,
            Operation.target_value == op.target_value,
            Operation.monitor_authorization_id.is_not(None),
            Operation.status == OperationStatus.SUCCEEDED,
            Operation.id != op.id,
        )
        .order_by(Operation.finished_at.desc())
        .limit(1)
    )
    if prev is None or not isinstance(prev.result_summary, dict):
        return None
    snap = prev.result_summary.get("monitor")
    return snap if isinstance(snap, dict) else None


def after_run(
    db: Session,
    op: Operation,
    result: Any,
    finding_changes: list[dict[str, object]],
    evidence_id: uuid.UUID,
    in_scope: Any,
    now: datetime,
) -> dict[str, Any] | None:
    """Called by the worker after a scheduled check succeeded. Returns the snapshot to keep
    with the operation, and raises alerts for what changed."""
    from nightfall.blackice.finding_rules import from_posture

    header_fail = (
        [d.check_id for d in from_posture(result.posture, now)] if op.tool == "headers" else []
    )
    cur = rules.snapshot(op.tool, result, header_fail)
    if cur is None:
        return None
    prev = previous_snapshot(db, op)
    for draft in rules.compare(op.tool, op.target_value, prev, cur, now, in_scope):
        raise_alert(
            db, op.workspace_id, op.project_id, op.monitor_authorization_id, draft,
            op.target_value, now, [evidence_id],
        )  # fmt: skip
    for ch in finding_changes:
        if ch.get("change") == "reopened":
            fid = uuid.UUID(str(ch["finding_id"]))
            raise_alert(
                db, op.workspace_id, op.project_id, op.monitor_authorization_id,
                AlertDraft(
                    "finding.reopened", Severity.HIGH,
                    f"A remediated finding is back on {op.target_value}",
                    f"The check {ch.get('check_id')} observed the problem again after it was "
                    "marked remediated. BLACK ICE reopened the finding as unverified.",
                    f"finding.reopened:{fid}",
                ),
                op.target_value, now, [evidence_id], fid,
            )  # fmt: skip
    return cur


def failed_run(db: Session, op: Operation, reason: str, now: datetime) -> None:
    raise_alert(
        db, op.workspace_id, op.project_id, op.monitor_authorization_id,
        AlertDraft(
            "monitor.failed", Severity.MEDIUM,
            f"Scheduled {op.tool} check of {op.target_value} didn't run",
            reason[:1000] or "The check failed.",
            f"monitor.failed:{op.monitor_authorization_id}:{op.tool}:{op.target_value}",
        ),
        op.target_value, now,
    )  # fmt: skip
