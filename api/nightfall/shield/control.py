"""CONTROL for scheduled checks: the one other way (besides a per-operation approval) that a
low-risk operation may run. The worker calls this at the moment it would run the check."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from nightfall.core.db.models import MonitorAuthorization, Operation, RiskClass

ALLOWED_TOOLS = ("ct", "dns", "tls", "headers")


def monitor_problem(db: Session, op: Operation, now: datetime) -> str | None:
    """None when a live standing authorization covers exactly this operation."""
    a = db.get(MonitorAuthorization, op.monitor_authorization_id)
    if a is None or a.workspace_id != op.workspace_id:
        return "The monitor authorization wasn't found."
    if a.ended_at is not None:
        return f"The monitor authorization ended ({a.ended_reason})."
    if a.expires_at <= now:
        return "The monitor authorization has expired. Renew it to continue."
    if a.scope_id != op.scope_id:
        return "The scope changed since monitoring was authorized."
    if op.target_value not in a.targets or op.tool not in a.checks or op.tool not in ALLOWED_TOOLS:
        return "This check isn't covered by the monitor authorization."
    if op.risk_class not in (RiskClass.PASSIVE, RiskClass.LOW) or op.is_lab:
        return "Monitoring covers passive and low-risk checks on live scopes only."
    if op.playbook_run_id is not None or op.proposed_by_task_id is not None:
        return "Playbook steps and agent proposals can't run under a monitor authorization."
    return None
