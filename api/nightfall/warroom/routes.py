"""War Room (Phase 6a): everything waiting on a person, in one place.

  * awaiting: operations that need an approval. can_decide is false for lab work (decided in
    BLACKSITE) and for the requester, unless the single-operator policy lets the owner decide
    their own (D1). Otherwise it is false for the requester
    (no self-approval) and for roles without the approve permission; the decision itself
    still goes through the operation's approve/reject routes, which re-check both.
  * in_flight: operations and agent tasks that are queued or running.
  * to_review: what agents proposed that only a person can settle (findings, attack paths,
    relationships still marked hypothesis).
  * decisions: the decision trail from audit_events. Only listed actions and listed data
    fields are shown, never IPs or user agents.
Every value is read from stored records.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter
from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased

from nightfall.agents.registry import AGENTS
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    ActorType,
    AgentTask,
    AgentTaskStatus,
    Asset,
    AssetRelationship,
    AttackPath,
    AttackPathStatus,
    AuditEvent,
    Finding,
    FindingOrigin,
    Operation,
    OperationStatus,
    Organization,
    Project,
    RelationshipStatus,
    RiskClass,
    Scope,
    User,
    ValidationStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, may_approve_own, ws_permission
from nightfall.core.tenancy.permissions import ROLE_PERMISSIONS, Permission
from nightfall.findings.routes import ref

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["war-room"])

LIMIT = 50
DECISION_ACTIONS = (
    "operation.approved",
    "operation.rejected",
    "operation.denied",
    "scope.authorized",
    "finding.status_changed",
    "attack_path.reviewed",
    "agent.proposal_refused",
    "agent_task.requested",
    "agent_task.cancelled",
    "report.generated",
)
SAFE_FIELDS = (
    "tool",
    "target",
    "risk_class",
    "reason",
    "agent",
    "from",
    "to",
    "note",
    "version",
    "title",
    "at",
)


class AwaitingOp(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    organization_name: str
    tool: str
    risk_class: RiskClass
    target: str
    purpose: str
    scope_version: int
    requested_by: str | None
    proposed_by_task_id: uuid.UUID | None
    queued_at: datetime
    can_decide: bool
    why_not: str | None


class InFlight(Model):
    kind: Literal["operation", "agent_task"]
    id: uuid.UUID
    label: str
    detail: str
    status: str
    since: datetime


class ReviewItem(Model):
    kind: Literal["finding", "attack_path", "relationship"]
    id: uuid.UUID
    label: str
    detail: str
    proposed_by_task_id: uuid.UUID | None
    link_id: uuid.UUID  # finding id, project id (paths) or asset id (relationships)
    created_at: datetime


class ReviewCounts(Model):
    findings: int
    attack_paths: int
    relationships: int


class Decision(Model):
    id: uuid.UUID
    action: str
    actor: str
    actor_type: str
    entity_type: str | None
    entity_id: uuid.UUID | None
    details: dict[str, Any]
    occurred_at: datetime


class WarRoomOut(Model):
    generated_at: datetime
    awaiting: list[AwaitingOp]
    in_flight: list[InFlight]
    to_review: list[ReviewItem]
    review_counts: ReviewCounts
    decisions: list[Decision]


def _names(db: DB, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return dict(db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).all())


@router.get("/war-room", response_model=WarRoomOut)
def war_room(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> WarRoomOut:
    ws = ctx.workspace_id
    can_approve = Permission.OPERATIONS_APPROVE in ROLE_PERMISSIONS[ctx.member.role]

    rows = db.execute(
        select(Operation, Project.name, Organization.name, Scope.version)
        .join(Project, Project.id == Operation.project_id)
        .join(Organization, Organization.id == Project.organization_id)
        .join(Scope, Scope.id == Operation.scope_id)
        .where(
            Operation.workspace_id == ws,
            Operation.status == OperationStatus.AWAITING_APPROVAL,
        )
        .order_by(Operation.queued_at)
        .limit(LIMIT)
    ).all()
    names = _names(db, {o.requested_by_user_id for o, *_ in rows if o.requested_by_user_id})

    own_ok = may_approve_own(db, ctx)

    def why_not(op: Operation) -> str | None:
        if not can_approve:
            return "Your role can't approve operations."
        if op.is_lab:
            return "Lab work is decided in BLACKSITE on the lab machine."
        if op.requested_by_user_id == ctx.user_id and not own_ok:
            return "You requested this (or started the agent that proposed it)."
        return None

    awaiting = [
        AwaitingOp(
            id=o.id,
            project_id=o.project_id,
            project_name=pname,
            organization_name=oname,
            tool=o.tool,
            risk_class=o.risk_class,
            target=o.target_value,
            purpose=str(o.params.get("purpose", ""))[:300],
            scope_version=version,
            requested_by=names.get(o.requested_by_user_id) if o.requested_by_user_id else None,
            proposed_by_task_id=o.proposed_by_task_id,
            queued_at=o.queued_at,
            can_decide=why_not(o) is None,
            why_not=why_not(o),
        )
        for o, pname, oname, version in rows
    ]

    open_ops = db.scalars(
        select(Operation)
        .where(
            Operation.workspace_id == ws,
            Operation.status.in_([OperationStatus.QUEUED, OperationStatus.RUNNING]),
        )
        .order_by(Operation.queued_at)
        .limit(LIMIT)
    ).all()
    open_tasks = db.scalars(
        select(AgentTask)
        .where(
            AgentTask.workspace_id == ws,
            AgentTask.status.in_([AgentTaskStatus.QUEUED, AgentTaskStatus.RUNNING]),
        )
        .order_by(AgentTask.queued_at)
        .limit(LIMIT)
    ).all()
    in_flight = sorted(
        [
            InFlight(
                kind="operation",
                id=o.id,
                label=o.tool,
                detail=o.target_value,
                status=o.status.value,
                since=o.started_at or o.queued_at,
            )
            for o in open_ops
        ]
        + [
            InFlight(
                kind="agent_task",
                id=t.id,
                label=AGENTS[t.agent].label if t.agent in AGENTS else t.agent,
                detail=t.objective[:200],
                status=t.status.value,
                since=t.started_at or t.queued_at,
            )
            for t in open_tasks
        ],
        key=lambda x: x.since,
    )

    agent_findings = (
        Finding.workspace_id == ws,
        Finding.origin == FindingOrigin.AGENT,
        Finding.validation_status == ValidationStatus.HYPOTHESIS,
    )
    agent_paths = (
        AttackPath.workspace_id == ws,
        AttackPath.proposed_by_task_id.is_not(None),
        AttackPath.status == AttackPathStatus.HYPOTHESIS,
    )
    agent_rels = (
        AssetRelationship.workspace_id == ws,
        AssetRelationship.proposed_by_task_id.is_not(None),
        AssetRelationship.status == RelationshipStatus.HYPOTHESIS,
    )
    counts = ReviewCounts(
        findings=db.scalar(select(func.count()).select_from(Finding).where(*agent_findings)) or 0,
        attack_paths=db.scalar(select(func.count()).select_from(AttackPath).where(*agent_paths))
        or 0,
        relationships=db.scalar(
            select(func.count()).select_from(AssetRelationship).where(*agent_rels)
        )
        or 0,
    )
    review: list[ReviewItem] = []
    recent_findings = select(Finding).where(*agent_findings).order_by(Finding.created_at.desc())
    for f in db.scalars(recent_findings.limit(20)):
        verdict = (f.guardian_review or {}).get("verdict")
        review.append(
            ReviewItem(
                kind="finding",
                id=f.id,
                label=f"{ref(f.number)} {f.title}",
                detail=f"{f.severity.value} · Guardian: {verdict.replace('_', ' ')}"
                if verdict
                else f"{f.severity.value} · Guardian review pending",
                proposed_by_task_id=f.proposed_by_task_id,
                link_id=f.id,
                created_at=f.created_at,
            )
        )
    recent_paths = select(AttackPath).where(*agent_paths).order_by(AttackPath.created_at.desc())
    for p in db.scalars(recent_paths.limit(20)):
        review.append(
            ReviewItem(
                kind="attack_path",
                id=p.id,
                label=p.title,
                detail="Attack path · hypothesis",
                proposed_by_task_id=p.proposed_by_task_id,
                link_id=p.project_id,
                created_at=p.created_at,
            )
        )
    a, b = aliased(Asset), aliased(Asset)
    for r, fv, tv in db.execute(
        select(AssetRelationship, a.value, b.value)
        .join(a, a.id == AssetRelationship.from_asset_id)
        .join(b, b.id == AssetRelationship.to_asset_id)
        .where(*agent_rels)
        .order_by(AssetRelationship.first_seen_at.desc())
        .limit(20)
    ).all():
        review.append(
            ReviewItem(
                kind="relationship",
                id=r.id,
                label=f"{fv} {r.rel_type.value.replace('_', ' ')} {tv}",
                detail="Relationship · hypothesis",
                proposed_by_task_id=r.proposed_by_task_id,
                link_id=r.from_asset_id,
                created_at=r.first_seen_at,
            )
        )
    review.sort(key=lambda x: x.created_at, reverse=True)

    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.workspace_id == ws, AuditEvent.action.in_(DECISION_ACTIONS))
        .order_by(AuditEvent.occurred_at.desc())
        .limit(LIMIT)
    ).all()
    actors = _names(
        db, {e.actor_id for e in events if e.actor_id and e.actor_type is ActorType.USER}
    )
    decisions = [
        Decision(
            id=e.id,
            action=e.action,
            actor=actors.get(e.actor_id, "A former member")
            if e.actor_type is ActorType.USER and e.actor_id
            else ("Agent" if e.actor_type is ActorType.AGENT else "System"),
            actor_type=e.actor_type.value,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            details={k: e.data[k] for k in SAFE_FIELDS if e.data.get(k) not in (None, "")},
            occurred_at=e.occurred_at,
        )
        for e in events
    ]

    return WarRoomOut(
        generated_at=utcnow(),
        awaiting=awaiting,
        in_flight=in_flight,
        to_review=review,
        review_counts=counts,
        decisions=decisions,
    )


class WarRoomSummary(Model):
    awaiting_you: int  # operations you may approve (not yours, and your role allows it)
    awaiting_total: int


@router.get("/war-room/summary", response_model=WarRoomSummary)
def war_room_summary(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> WarRoomSummary:
    """For the header's approvals bell: cheap counts, same rules as the War Room."""
    waiting = (
        Operation.workspace_id == ctx.workspace_id,
        Operation.status == OperationStatus.AWAITING_APPROVAL,
    )
    total = db.scalar(select(func.count()).select_from(Operation).where(*waiting)) or 0
    yours = 0
    if Permission.OPERATIONS_APPROVE in ROLE_PERMISSIONS[ctx.member.role]:
        own = (
            []
            if may_approve_own(db, ctx)
            else [
                or_(
                    Operation.requested_by_user_id.is_(None),
                    Operation.requested_by_user_id != ctx.user_id,
                )
            ]
        )
        yours = (
            db.scalar(
                select(func.count())
                .select_from(Operation)
                .where(*waiting, Operation.is_lab.is_(False), *own)
            )
            or 0
        )
    return WarRoomSummary(awaiting_you=yours, awaiting_total=total)
