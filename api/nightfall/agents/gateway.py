"""Tool Gateway (review §6): the only path from an agent's answer to the database.

Deterministic code; nothing here trusts the model. For every proposal:
  * collections: the tool must be in the agent's allowlist; the target must normalize and
    be inside the active, in-window scope and outside its exclusions; then by risk class:
    passive -> queued, low -> awaiting a person's approval (never the person who started
    the agent), moderate/high -> refused.
  * findings: recorded only as hypotheses with low confidence, only when they cite
    evidence the agent was actually shown from this project; each one gets an independent
    Guardian review.
  * reviews: stored as advice on the finding; never change its status.
Every refusal is audited with the reason.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from nightfall.agents.registry import (
    AGENTS,
    PROMPT_VERSION,
    GuardianOutput,
    HunterOutput,
    ScoutOutput,
)
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    AgentTask,
    AgentTaskStatus,
    Asset,
    Confidence,
    Finding,
    FindingEvidence,
    FindingOrigin,
    Operation,
    OperationStatus,
    Project,
    RiskClass,
    Severity,
    ValidationStatus,
)
from nightfall.scope.engine import evaluate
from nightfall.scope.normalize import NormalizationError
from nightfall.scope.repository import active_scope, snapshot

MAX_SCOUT_PROPOSALS = 10
MAX_HUNTER_CANDIDATES = 8
PENDING = (OperationStatus.AWAITING_APPROVAL, OperationStatus.QUEUED, OperationStatus.RUNNING)


@dataclass
class Applied:
    accepted: list[dict[str, Any]] = field(default_factory=list)
    refused: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "refused": self.refused}


def _clip(text: str, n: int) -> str:
    return " ".join(text.split())[:n]


def _refuse(
    db: Session, task: AgentTask, applied: Applied, item: dict[str, Any], reason: str
) -> None:
    applied.refused.append({**item, "reason": reason})
    record(
        db,
        "agent.proposal_refused",
        actor_type=ActorType.AGENT,
        workspace_id=task.workspace_id,
        entity_type="agent_task",
        entity_id=task.id,
        data={"agent": task.agent, **item, "reason": reason},
    )


def apply_scout(db: Session, task: AgentTask, out: ScoutOutput) -> Applied:
    from nightfall.recon.collectors import TOOLS

    spec = AGENTS["scout"]
    applied = Applied()
    scope = active_scope(db, task.project_id)
    snap = snapshot(db, scope) if scope is not None else None
    now = utcnow()
    for i, p in enumerate(out.proposals):
        item = {"tool": str(p.tool)[:20], "target": str(p.target)[:300]}
        if i >= MAX_SCOUT_PROPOSALS:
            _refuse(db, task, applied, item, f"More than {MAX_SCOUT_PROPOSALS} proposals.")
            continue
        if p.tool not in spec.allowed_tools or p.tool not in TOOLS:
            _refuse(db, task, applied, item, "Tool not allowed for this agent.")
            continue
        label, risk = TOOLS[p.tool]
        if risk not in (RiskClass.PASSIVE, RiskClass.LOW):
            _refuse(db, task, applied, item, f"Risk class {risk.value} can't be proposed.")
            continue
        try:
            decision = evaluate(snap, p.target, now)
        except NormalizationError as exc:  # pragma: no cover - evaluate handles it
            _refuse(db, task, applied, item, f"Invalid target: {exc}")
            continue
        if scope is None or not decision.allowed:
            _refuse(db, task, applied, item, decision.reason)
            continue
        target = decision.target
        if p.tool == "ct" and target.count(".") < 1:
            _refuse(db, task, applied, item, "Certificate search needs a domain.")
            continue
        pending = db.scalar(
            select(Operation.id).where(
                Operation.project_id == task.project_id,
                Operation.tool == p.tool,
                Operation.target_value == target,
                Operation.status.in_(PENDING),
            )
        )
        if pending is not None:
            applied.accepted.append(
                {**item, "target": target, "operation_id": str(pending), "note": "already pending"}
            )
            continue
        op = Operation(
            workspace_id=task.workspace_id,
            project_id=task.project_id,
            scope_id=scope.id,
            tool=p.tool,
            risk_class=risk,
            target_value=target,
            params={"method": label, "purpose": _clip(p.purpose, 300), "proposed_by": "scout"},
            requested_by_user_id=task.requested_by_user_id,
            proposed_by_task_id=task.id,
            status=OperationStatus.QUEUED
            if risk is RiskClass.PASSIVE
            else OperationStatus.AWAITING_APPROVAL,
        )
        db.add(op)
        db.flush()
        record(
            db,
            "operation.requested",
            actor_type=ActorType.AGENT,
            workspace_id=task.workspace_id,
            entity_type="operation",
            entity_id=op.id,
            data={
                "tool": p.tool,
                "target": target,
                "risk_class": risk.value,
                "scope_version": scope.version,
                "agent_task_id": str(task.id),
            },
        )
        applied.accepted.append(
            {**item, "target": target, "operation_id": str(op.id), "status": op.status.value}
        )
    return applied


def _asset_for(db: Session, task: AgentTask, value: str) -> uuid.UUID | None:
    from nightfall.scope.engine import parse_target

    try:
        host, addr = parse_target(value)
    except NormalizationError:
        return None
    org = db.scalar(select(Project.organization_id).where(Project.id == task.project_id))
    normalized = host if host is not None else str(addr)
    return db.scalar(
        select(Asset.id).where(Asset.organization_id == org, Asset.value == normalized)
    )


def apply_hunter(
    db: Session, task: AgentTask, out: HunterOutput, shown_evidence: set[uuid.UUID]
) -> Applied:
    applied = Applied()
    for i, c in enumerate(out.candidates):
        item = {"title": _clip(c.title, 200)}
        if i >= MAX_HUNTER_CANDIDATES:
            _refuse(db, task, applied, item, f"More than {MAX_HUNTER_CANDIDATES} candidates.")
            continue
        cited: list[uuid.UUID] = []
        for raw in c.evidence_ids[:20]:
            try:
                eid = uuid.UUID(str(raw))
            except ValueError:
                continue
            if eid in shown_evidence and eid not in cited:
                cited.append(eid)
        if not cited:
            _refuse(db, task, applied, item, "Cites no evidence the agent was shown.")
            continue
        try:
            severity = Severity(c.severity)
        except ValueError:
            _refuse(db, task, applied, item, "Unknown severity.")
            continue
        finding = Finding(
            workspace_id=task.workspace_id,
            project_id=task.project_id,
            asset_id=_asset_for(db, task, c.asset),
            title=item["title"] or "Untitled candidate",
            description=c.description[:4000],
            severity=severity,
            confidence=Confidence.LOW,  # LLM-originated claims are low confidence (§14)
            validation_status=ValidationStatus.HYPOTHESIS,
            origin=FindingOrigin.AGENT,
            check_id=None,
            rule_id=f"agent:hunter@{PROMPT_VERSION}",
            discovery_source=f"Hunter (AI agent), task {task.id}",
            impact=c.impact[:2000],
            remediation=c.remediation[:2000],
            proposed_by_task_id=task.id,
        )
        db.add(finding)
        db.flush()
        for eid in cited:
            db.execute(
                insert(FindingEvidence)
                .values(
                    workspace_id=task.workspace_id,
                    finding_id=finding.id,
                    evidence_id=eid,
                    linked_by=f"agent:hunter:{task.id}",
                )
                .on_conflict_do_nothing(index_elements=["finding_id", "evidence_id"])
            )
        review = AgentTask(
            workspace_id=task.workspace_id,
            project_id=task.project_id,
            agent="guardian",
            parent_task_id=task.id,
            subject_finding_id=finding.id,
            objective=f"Review the claim: {item['title']}",
            requested_by_user_id=task.requested_by_user_id,
        )
        db.add(review)
        record(
            db,
            "finding.proposed_by_agent",
            actor_type=ActorType.AGENT,
            workspace_id=task.workspace_id,
            entity_type="finding",
            entity_id=finding.id,
            data={"agent_task_id": str(task.id), "evidence": [str(e) for e in cited]},
        )
        applied.accepted.append({**item, "finding_id": str(finding.id), "evidence": len(cited)})
    return applied


def apply_guardian(db: Session, task: AgentTask, out: GuardianOutput, model: str) -> Applied:
    finding = db.get(Finding, task.subject_finding_id) if task.subject_finding_id else None
    if finding is None:
        return Applied(refused=[{"reason": "Finding no longer exists."}])
    finding.guardian_review = {
        "verdict": out.verdict,
        "severity_assessment": out.severity_assessment,
        "rationale": out.rationale[:3000],
        "task_id": str(task.id),
        "model": model,
        "reviewed_at": utcnow().isoformat(),
    }
    record(
        db,
        "finding.reviewed_by_agent",
        actor_type=ActorType.AGENT,
        workspace_id=task.workspace_id,
        entity_type="finding",
        entity_id=finding.id,
        data={"verdict": out.verdict, "agent_task_id": str(task.id)},
    )
    return Applied(accepted=[{"finding_id": str(finding.id), "verdict": out.verdict}])


__all__ = ["AgentTaskStatus", "Applied", "apply_guardian", "apply_hunter", "apply_scout"]
