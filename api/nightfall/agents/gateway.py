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
  * Director's subtasks: only for the agents it may delegate to (never itself or Guardian),
    at most 5, each a normal queued task (its objective is shown to the next agent as data).
  * Investigator's relationships: both assets must already be known in the organization,
    and each must cite evidence it was shown; recorded as hypotheses with low confidence.
  * Adversary's paths: every step must name a finding it was shown or a known asset, every
    path at least one finding; recorded as low-confidence hypotheses for a person to review.
  * Analyst's summary: kept on the task, labelled as AI-written; the counts shown beside it
    are computed from the records, and key risks must be findings it was shown.
Every refusal is audited with the reason.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.agents.registry import (
    AGENTS,
    DIRECTOR_DELEGATES,
    HOURLY_LIMIT,
    PROMPT_VERSION,
    AdversaryOutput,
    AnalystOutput,
    DirectorOutput,
    GuardianOutput,
    HunterOutput,
    InvestigatorOutput,
    ScoutOutput,
)
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    AgentTask,
    AgentTaskStatus,
    Asset,
    AssetRelationship,
    AttackPath,
    AttackPathStatus,
    AttackPathStep,
    Confidence,
    Finding,
    FindingEvidence,
    FindingOrigin,
    Operation,
    OperationStatus,
    Project,
    RelationshipStatus,
    RelationshipType,
    RiskClass,
    Severity,
    ValidationStatus,
)
from nightfall.scope.engine import evaluate
from nightfall.scope.normalize import NormalizationError
from nightfall.scope.repository import active_scope, snapshot

MAX_SCOUT_PROPOSALS = 10
MAX_HUNTER_CANDIDATES = 8
MAX_SUBTASKS = 5
MAX_RELATIONSHIPS = 8
MAX_PATHS = 3
MIN_STEPS, MAX_STEPS = 2, 8
MAX_KEY_RISKS = 5
OPEN_TASK = (AgentTaskStatus.QUEUED, AgentTaskStatus.RUNNING)
PENDING = (OperationStatus.AWAITING_APPROVAL, OperationStatus.QUEUED, OperationStatus.RUNNING)


@dataclass
class Applied:
    accepted: list[dict[str, Any]] = field(default_factory=list)
    refused: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {**self.extra, "accepted": self.accepted, "refused": self.refused}


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


def _uuid(raw: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw).strip())
    except ValueError:
        return None


def _shown_cited(raw_ids: list[str], shown: set[uuid.UUID]) -> list[uuid.UUID]:
    cited: list[uuid.UUID] = []
    for raw in raw_ids[:20]:
        eid = _uuid(raw)
        if eid is not None and eid in shown and eid not in cited:
            cited.append(eid)
    return cited


def _runs_last_hour(db: Session, task: AgentTask) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(AgentTask)
            .where(
                AgentTask.workspace_id == task.workspace_id,
                AgentTask.agent != "guardian",
                AgentTask.created_at >= utcnow() - timedelta(hours=1),
            )
        )
        or 0
    )


def apply_director(db: Session, task: AgentTask, out: DirectorOutput) -> Applied:
    applied = Applied()
    budget = HOURLY_LIMIT - _runs_last_hour(db, task)
    for i, sub in enumerate(out.subtasks):
        item = {"agent": str(sub.agent)[:20], "objective": _clip(sub.objective, 300)}
        if i >= MAX_SUBTASKS:
            _refuse(db, task, applied, item, f"More than {MAX_SUBTASKS} subtasks.")
            continue
        if sub.agent not in DIRECTOR_DELEGATES:
            _refuse(db, task, applied, item, "The Director can't assign work to this agent.")
            continue
        if not item["objective"]:
            _refuse(db, task, applied, item, "Empty objective.")
            continue
        asset_id = None
        if sub.agent == "investigator":
            asset_id = _asset_for(db, task, sub.asset)
            item["asset"] = _clip(sub.asset, 300)
            if asset_id is None:
                _refuse(db, task, applied, item, "Not a known asset in this organization.")
                continue
        open_run = db.scalar(
            select(AgentTask.id).where(
                AgentTask.project_id == task.project_id,
                AgentTask.agent == sub.agent,
                AgentTask.status.in_(OPEN_TASK),
                AgentTask.subject_asset_id == asset_id
                if asset_id is not None
                else AgentTask.subject_asset_id.is_(None),
                AgentTask.subject_finding_id.is_(None),
            )
        )
        if open_run is not None:
            applied.accepted.append({**item, "task_id": str(open_run), "note": "already queued"})
            continue
        if budget <= 0:
            _refuse(db, task, applied, item, f"Hourly agent limit ({HOURLY_LIMIT}) reached.")
            continue
        budget -= 1
        child = AgentTask(
            workspace_id=task.workspace_id,
            project_id=task.project_id,
            agent=sub.agent,
            parent_task_id=task.id,
            subject_asset_id=asset_id,
            objective=item["objective"],
            context={"assigned_by": "director"},
            requested_by_user_id=task.requested_by_user_id,
        )
        try:
            with db.begin_nested():
                db.add(child)
                db.flush()
        except IntegrityError:  # raced with a run someone just started
            _refuse(db, task, applied, item, "This agent is already running for the project.")
            continue
        record(
            db,
            "agent_task.requested",
            actor_type=ActorType.AGENT,
            workspace_id=task.workspace_id,
            entity_type="agent_task",
            entity_id=child.id,
            data={"agent": sub.agent, "parent_task_id": str(task.id)},
        )
        applied.accepted.append({**item, "task_id": str(child.id)})
    return applied


def apply_investigator(
    db: Session, task: AgentTask, out: InvestigatorOutput, shown_evidence: set[uuid.UUID]
) -> Applied:
    applied = Applied(
        extra={
            "summary": _clip(out.summary, 3000),
            "open_questions": [_clip(q, 300) for q in out.open_questions[:5]],
        }
    )
    subject = task.subject_asset_id
    for i, r in enumerate(out.relationships):
        item = {"to_asset": _clip(r.to_asset, 300), "rel_type": str(r.rel_type)[:20]}
        if i >= MAX_RELATIONSHIPS:
            _refuse(db, task, applied, item, f"More than {MAX_RELATIONSHIPS} relationships.")
            continue
        try:
            rel_type = RelationshipType(r.rel_type)
        except ValueError:
            _refuse(db, task, applied, item, "Unknown relationship type.")
            continue
        other = _asset_for(db, task, r.to_asset)
        if subject is None or other is None:
            _refuse(db, task, applied, item, "Not a known asset in this organization.")
            continue
        if other == subject:
            _refuse(db, task, applied, item, "An asset can't relate to itself.")
            continue
        cited = _shown_cited(r.evidence_ids, shown_evidence)
        if not cited:
            _refuse(db, task, applied, item, "Cites no evidence the agent was shown.")
            continue
        row = db.execute(
            insert(AssetRelationship)
            .values(
                workspace_id=task.workspace_id,
                from_asset_id=subject,
                to_asset_id=other,
                rel_type=rel_type,
                status=RelationshipStatus.HYPOTHESIS,
                confidence=Confidence.LOW,
                evidence_id=cited[0],
                rule_id=f"agent:investigator@{PROMPT_VERSION}",
                proposed_by_task_id=task.id,
            )
            .on_conflict_do_nothing(index_elements=["from_asset_id", "to_asset_id", "rel_type"])
            .returning(AssetRelationship.id)
        ).first()
        if row is None:
            applied.accepted.append({**item, "note": "already recorded"})
            continue
        record(
            db,
            "relationship.proposed_by_agent",
            actor_type=ActorType.AGENT,
            workspace_id=task.workspace_id,
            entity_type="asset_relationship",
            entity_id=row.id,
            data={
                "agent_task_id": str(task.id),
                "rel_type": rel_type.value,
                "rationale": _clip(r.rationale, 500),
            },
        )
        applied.accepted.append({**item, "relationship_id": str(row.id), "status": "hypothesis"})
    return applied


def apply_adversary(
    db: Session, task: AgentTask, out: AdversaryOutput, shown_findings: set[uuid.UUID]
) -> Applied:
    applied = Applied()
    for i, p in enumerate(out.paths):
        item: dict[str, Any] = {"title": _clip(p.title, 200)}
        if i >= MAX_PATHS:
            _refuse(db, task, applied, item, f"More than {MAX_PATHS} paths.")
            continue
        if not MIN_STEPS <= len(p.steps) <= MAX_STEPS:
            _refuse(db, task, applied, item, f"A path needs {MIN_STEPS} to {MAX_STEPS} steps.")
            continue
        steps: list[tuple[uuid.UUID | None, uuid.UUID | None, str]] = []
        problem = None
        for n, st in enumerate(p.steps, start=1):
            fid = _uuid(st.finding_id) if st.finding_id.strip() else None
            if st.finding_id.strip() and (fid is None or fid not in shown_findings):
                problem = f"Step {n} names a finding the agent wasn't shown."
                break
            aid = _asset_for(db, task, st.asset) if st.asset.strip() else None
            if st.asset.strip() and aid is None:
                problem = f"Step {n} names an asset that isn't known in this organization."
                break
            desc = _clip(st.description, 2000)
            if (fid is None and aid is None) or not desc:
                problem = f"Step {n} needs a finding or an asset, and a description."
                break
            steps.append((fid, aid, desc))
        if problem is None and not any(f for f, _, _ in steps):
            problem = "A path must rest on at least one recorded finding."
        if problem is not None:
            _refuse(db, task, applied, item, problem)
            continue
        path = AttackPath(
            workspace_id=task.workspace_id,
            project_id=task.project_id,
            title=item["title"] or "Untitled path",
            narrative=p.narrative[:20000],
            status=AttackPathStatus.HYPOTHESIS,
            confidence=Confidence.LOW,
            proposed_by_task_id=task.id,
        )
        db.add(path)
        db.flush()
        for n, (fid, aid, desc) in enumerate(steps, start=1):
            db.add(
                AttackPathStep(
                    workspace_id=task.workspace_id,
                    attack_path_id=path.id,
                    ordinal=n,
                    asset_id=aid,
                    finding_id=fid,
                    description=desc,
                )
            )
        db.flush()
        record(
            db,
            "attack_path.proposed_by_agent",
            actor_type=ActorType.AGENT,
            workspace_id=task.workspace_id,
            entity_type="attack_path",
            entity_id=path.id,
            data={"agent_task_id": str(task.id), "steps": len(steps)},
        )
        applied.accepted.append({**item, "attack_path_id": str(path.id), "steps": len(steps)})
    return applied


def apply_analyst(
    db: Session,
    task: AgentTask,
    out: AnalystOutput,
    shown_findings: set[uuid.UUID],
    facts: dict[str, Any],
) -> Applied:
    applied = Applied(
        extra={
            "summary": out.summary.strip()[:6000],
            "next_steps": [_clip(s, 400) for s in out.next_steps[:5]],
            "counts": facts,  # from the records, not the model
        }
    )
    risks: list[dict[str, Any]] = []
    for i, k in enumerate(out.key_risks):
        item = {"finding_id": str(k.finding_id)[:40]}
        if i >= MAX_KEY_RISKS:
            _refuse(db, task, applied, item, f"More than {MAX_KEY_RISKS} key risks.")
            continue
        fid = _uuid(k.finding_id)
        if fid is None or fid not in shown_findings:
            _refuse(db, task, applied, item, "Not a finding the agent was shown.")
            continue
        f = db.get(Finding, fid)
        if f is None:  # pragma: no cover - shown in this run
            continue
        risks.append(
            {
                "finding_id": str(fid),
                "title": f.title,
                "severity": f.severity.value,
                "status": f.validation_status.value,
                "why": _clip(k.why, 600),
            }
        )
    applied.extra["key_risks"] = risks
    applied.accepted = [{"finding_id": r["finding_id"], "title": r["title"]} for r in risks]
    return applied


__all__ = [
    "AgentTaskStatus",
    "Applied",
    "apply_adversary",
    "apply_analyst",
    "apply_director",
    "apply_guardian",
    "apply_hunter",
    "apply_investigator",
    "apply_scout",
]
