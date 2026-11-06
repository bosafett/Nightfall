"""Passive collection requests, discovery history and evidence.

A request is accepted only if the target is inside the project's active, in-window scope.
Out-of-scope requests are refused with the reason and recorded in the audit log; nothing
is queued. Passive collectors run without further approval (review §8.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Query, Response
from pydantic import StringConstraints
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record, record_detached
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Approval,
    ApprovalDecision,
    Evidence,
    Operation,
    OperationStatus,
    Organization,
    Project,
    RiskClass,
    Scope,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.evidence_store import EvidenceStore, IntegrityError, read_from
from nightfall.core.schemas import Model, OkOut
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.recon.collectors import LAB_TOOLS, TOOLS
from nightfall.registry.assets import EvidenceSummary, evidence_summary
from nightfall.scope.engine import evaluate
from nightfall.scope.repository import active_scope, snapshot

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["recon"])

HOURLY_LIMIT = 120  # collection requests per workspace per hour
PENDING = (OperationStatus.AWAITING_APPROVAL, OperationStatus.QUEUED, OperationStatus.RUNNING)


class CollectionIn(Model):
    tool: Literal["ct", "dns", "http", "nuclei"]
    target: Annotated[str, StringConstraints(max_length=300)]


class ToolOut(Model):
    key: str
    label: str
    risk_class: RiskClass


class OperationOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    organization_id: uuid.UUID
    organization_name: str
    scope_version: int
    tool: str
    tool_label: str
    risk_class: RiskClass
    target: str
    is_lab: bool
    status: OperationStatus
    requested_by: str | None
    requested_by_user_id: uuid.UUID | None
    denial_reason: str | None
    error: str | None
    result_summary: dict[str, Any]
    attempts: int
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ApprovalOut(Model):
    decision: ApprovalDecision
    decided_by: str
    reason: str
    decided_at: datetime


class DecisionIn(Model):
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] = ""


class OperationDetail(OperationOut):
    approval: ApprovalOut | None
    evidence: list[EvidenceSummary]


class EvidenceDetail(EvidenceSummary):
    project_id: uuid.UUID
    asset_id: uuid.UUID | None
    content_type: str
    input_params: dict[str, Any]
    summary: dict[str, Any]
    is_simulation: bool


def _query() -> Select[Operation, str, uuid.UUID, str, int, str]:
    return (
        select(
            Operation,
            Project.name,
            Organization.id,
            Organization.name,
            Scope.version,
            User.display_name,
        )
        .join(Project, Project.id == Operation.project_id)
        .join(Organization, Organization.id == Project.organization_id)
        .join(Scope, Scope.id == Operation.scope_id)
        .outerjoin(User, User.id == Operation.requested_by_user_id)
    )


def _out(row: Any) -> OperationOut:
    op, pname, oid, oname, version, requester = row
    return OperationOut(
        id=op.id,
        project_id=op.project_id,
        project_name=pname,
        organization_id=oid,
        organization_name=oname,
        scope_version=version,
        tool=op.tool,
        tool_label=TOOLS.get(op.tool, (op.tool, op.risk_class))[0],
        risk_class=op.risk_class,
        target=op.target_value,
        is_lab=op.is_lab,
        status=op.status,
        requested_by=requester,
        requested_by_user_id=op.requested_by_user_id,
        denial_reason=op.denial_reason,
        error=op.error,
        result_summary=op.result_summary,
        attempts=op.attempts,
        queued_at=op.queued_at,
        started_at=op.started_at,
        finished_at=op.finished_at,
    )


def _get_op(db: Session, ctx: WorkspaceContext, op_id: uuid.UUID) -> Any:
    row = db.execute(
        _query().where(Operation.id == op_id, Operation.workspace_id == ctx.workspace_id)
    ).first()
    if row is None:
        raise not_found("Operation not found.")
    return row


@router.get("/recon/tools", response_model=list[ToolOut])
def list_tools(ctx: WorkspaceContext = ws_permission(Permission.READ)) -> list[ToolOut]:
    return [ToolOut(key=k, label=label, risk_class=risk) for k, (label, risk) in TOOLS.items()]


def _drain_later(background: BackgroundTasks) -> None:
    """Serverless hosting: run the queue after the response (the request's transaction
    commits before the response is sent, so the job is visible)."""
    if get_settings().on_demand_worker:
        from nightfall.serverless import drain

        background.add_task(drain)


class DrainOut(Model):
    processed: int


@router.post("/worker/run", response_model=DrainOut)
def run_queued_jobs(ctx: WorkspaceContext = ws_permission(Permission.READ)) -> DrainOut:
    """Serverless hosting only: processes queued jobs now (any member may nudge the queue;
    every job was already authorized when it was queued, and is re-checked when it runs)."""
    if not get_settings().on_demand_worker:
        raise not_found()
    from nightfall.serverless import drain

    return DrainOut(processed=drain())


@router.post("/projects/{project_id}/collections", response_model=OperationOut, status_code=202)
def request_collection(
    project_id: uuid.UUID,
    body: CollectionIn,
    response: Response,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE),
) -> OperationOut:
    project = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if project is None:
        raise not_found("Project not found.")
    label, risk = TOOLS[body.tool]
    scope = active_scope(db, project_id)
    is_lab = scope is not None and scope.is_lab
    # High risk never; moderate only against the isolated lab (DB CHECK too, migration 0010).
    if risk is RiskClass.HIGH or (risk is RiskClass.MODERATE and not is_lab):
        raise api_error(403, "not_available", "This tool isn't available.")
    if is_lab and body.tool not in LAB_TOOLS:
        raise api_error(
            422, "not_in_lab", "That tool isn't available in the lab (it needs public records)."
        )

    decision = evaluate(snapshot(db, scope) if scope else None, body.target, utcnow())
    if not decision.allowed or scope is None:
        record_detached(
            "operation.denied",
            data={
                "project_id": str(project_id),
                "tool": body.tool,
                "target": body.target[:300],
                "reason": decision.reason,
            },
            **ctx.audit_kwargs(),
        )
        raise api_error(422, "out_of_scope", decision.reason)
    if body.tool == "ct" and decision.target.count(".") < 1:
        raise api_error(422, "invalid_value", "Search certificate logs by domain.")

    pending = db.execute(
        _query().where(
            Operation.project_id == project_id,
            Operation.tool == body.tool,
            Operation.target_value == decision.target,
            Operation.status.in_(PENDING),
        )
    ).first()
    if pending is not None:
        response.status_code = 200  # already queued: return it rather than duplicate
        return _out(pending)

    since = utcnow() - timedelta(hours=1)
    recent = (
        db.scalar(
            select(func.count())
            .select_from(Operation)
            .where(Operation.workspace_id == ctx.workspace_id, Operation.created_at >= since)
        )
        or 0
    )
    if recent >= HOURLY_LIMIT:
        raise api_error(
            429, "rate_limited", f"Collection is limited to {HOURLY_LIMIT} requests per hour."
        )

    op = Operation(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        scope_id=scope.id,
        tool=body.tool,
        risk_class=risk,
        target_value=decision.target,
        params={"method": label},
        requested_by_user_id=ctx.user_id,
        is_lab=is_lab,
        # Passive runs within scope; anything above passive, and every lab run, waits for
        # a second person.
        status=OperationStatus.QUEUED
        if risk is RiskClass.PASSIVE and not is_lab
        else OperationStatus.AWAITING_APPROVAL,
    )
    db.add(op)
    db.flush()
    record(
        db,
        "operation.requested",
        entity_type="operation",
        entity_id=op.id,
        data={
            "tool": body.tool,
            "target": decision.target,
            "risk_class": risk.value,
            "scope_version": scope.version,
        },
        **ctx.audit_kwargs(),
    )
    if op.status is OperationStatus.QUEUED:
        _drain_later(background)
    return _out(_get_op(db, ctx, op.id))


@router.get("/operations", response_model=list[OperationOut])
def list_operations(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    project_id: Annotated[uuid.UUID | None, Query()] = None,
    status: Annotated[OperationStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[OperationOut]:
    q = _query().where(Operation.workspace_id == ctx.workspace_id)
    if project_id is not None:
        q = q.where(Operation.project_id == project_id)
    if status is not None:
        q = q.where(Operation.status == status)
    return [_out(r) for r in db.execute(q.order_by(Operation.queued_at.desc()).limit(limit))]


@router.get("/operations/{op_id}", response_model=OperationDetail)
def get_operation(
    op_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> OperationDetail:
    row = _get_op(db, ctx, op_id)
    ev = db.scalars(
        select(Evidence).where(Evidence.operation_id == op_id).order_by(Evidence.collected_at)
    ).all()
    return OperationDetail(
        **_out(row).model_dump(),
        evidence=[evidence_summary(e) for e in ev],
        approval=_approval(db, op_id),
    )


@router.post("/operations/{op_id}/cancel", response_model=OkOut)
def cancel_operation(
    op_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE)
) -> OkOut:
    op = db.scalar(
        select(Operation)
        .where(Operation.id == op_id, Operation.workspace_id == ctx.workspace_id)
        .with_for_update()
    )
    if op is None:
        raise not_found("Operation not found.")
    if op.status not in (OperationStatus.QUEUED, OperationStatus.AWAITING_APPROVAL):
        raise api_error(409, "not_queued", "Only queued or unapproved operations can be cancelled.")
    op.status = OperationStatus.CANCELLED
    op.finished_at = utcnow()
    record(
        db, "operation.cancelled", entity_type="operation", entity_id=op.id, **ctx.audit_kwargs()
    )
    return OkOut()


def _evidence(db: Session, ctx: WorkspaceContext, evidence_id: uuid.UUID) -> Evidence:
    e = db.scalar(
        select(Evidence).where(
            Evidence.id == evidence_id, Evidence.workspace_id == ctx.workspace_id
        )
    )
    if e is None:
        raise not_found("Evidence not found.")
    return e


@router.get("/evidence/{evidence_id}", response_model=EvidenceDetail)
def get_evidence(
    evidence_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> EvidenceDetail:
    e = _evidence(db, ctx, evidence_id)
    return EvidenceDetail(
        **evidence_summary(e).model_dump(),
        project_id=e.project_id,
        asset_id=e.asset_id,
        content_type=e.content_type,
        input_params=e.input_params,
        summary=e.summary,
        is_simulation=e.is_simulation,
    )


@router.get("/evidence/{evidence_id}/content")
def get_evidence_content(
    evidence_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> Response:
    """Raw stored content, verified against its SHA-256. Always served as a download so
    attacker-controlled content can't render in the app's origin."""
    e = _evidence(db, ctx, evidence_id)
    try:
        s = get_settings()
        if s.evidence_backend == "postgres":
            data = read_from(db, e.content_sha256)
        else:
            data = EvidenceStore(s.evidence_dir).get(e.content_sha256)
    except IntegrityError as exc:
        record_detached(
            "evidence.integrity_failed",
            entity_type="evidence",
            entity_id=e.id,
            **ctx.audit_kwargs(),
        )
        raise api_error(500, "integrity_failed", str(exc)) from exc
    ext = "json" if e.content_type == "application/json" else "bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{e.id}.{ext}"',
            "X-Evidence-SHA256": e.content_sha256.hex(),
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


def _approval(db: Session, op_id: uuid.UUID) -> ApprovalOut | None:
    row = db.execute(
        select(Approval, User.display_name)
        .join(User, User.id == Approval.approver_user_id)
        .where(Approval.operation_id == op_id)
    ).first()
    if row is None:
        return None
    a, name = row
    return ApprovalOut(
        decision=a.decision, decided_by=name, reason=a.reason, decided_at=a.decided_at
    )


def _awaiting(db: Session, ctx: WorkspaceContext, op_id: uuid.UUID) -> Operation:
    op = db.scalar(
        select(Operation)
        .where(Operation.id == op_id, Operation.workspace_id == ctx.workspace_id)
        .with_for_update()
    )
    if op is None:
        raise not_found("Operation not found.")
    if op.status is not OperationStatus.AWAITING_APPROVAL:
        raise api_error(409, "not_awaiting", "This operation isn't waiting for a decision.")
    if op.requested_by_user_id == ctx.user_id:
        raise api_error(
            409,
            "self_approval",
            "You requested this operation, so someone else has to decide on it.",
        )
    return op


def approve_locked(db: Session, ctx: WorkspaceContext, op: Operation, reason: str) -> bool:
    """Approves an operation the caller has locked and checked with _awaiting. The approval is
    only meaningful against the scope it was requested under: if that changed, or the target
    is no longer in scope, the operation is denied instead. Returns whether it was approved."""
    current = active_scope(db, op.project_id)
    decision = (
        evaluate(snapshot(db, current), op.target_value, utcnow())
        if current is not None and current.id == op.scope_id
        else None
    )
    if decision is None or not decision.allowed:
        op.status = OperationStatus.DENIED
        op.finished_at = utcnow()
        op.denial_reason = (
            "The scope changed after this was requested. Request it again."
            if decision is None
            else decision.reason
        )
        record(
            db,
            "operation.denied",
            entity_type="operation",
            entity_id=op.id,
            data={"reason": op.denial_reason, "at": "approval"},
            **ctx.audit_kwargs(),
        )
        return False
    db.add(
        Approval(
            workspace_id=ctx.workspace_id,
            operation_id=op.id,
            approver_user_id=ctx.user_id,
            decision=ApprovalDecision.APPROVED,
            reason=reason,
            scope_id_at_decision=op.scope_id,
        )
    )
    op.status = OperationStatus.QUEUED
    op.queued_at = utcnow()
    record(
        db,
        "operation.approved",
        entity_type="operation",
        entity_id=op.id,
        data={
            "tool": op.tool,
            "target": op.target_value,
            "risk_class": op.risk_class.value,
            "reason": reason,
        },
        **ctx.audit_kwargs(),
    )
    return True


def reject_locked(db: Session, ctx: WorkspaceContext, op: Operation, reason: str) -> None:
    db.add(
        Approval(
            workspace_id=ctx.workspace_id,
            operation_id=op.id,
            approver_user_id=ctx.user_id,
            decision=ApprovalDecision.REJECTED,
            reason=reason,
            scope_id_at_decision=op.scope_id,
        )
    )
    op.status = OperationStatus.REJECTED
    op.finished_at = utcnow()
    record(
        db,
        "operation.rejected",
        entity_type="operation",
        entity_id=op.id,
        data={"reason": reason},
        **ctx.audit_kwargs(),
    )


@router.post("/operations/{op_id}/approve", response_model=OperationDetail)
def approve_operation(
    op_id: uuid.UUID,
    body: DecisionIn,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_APPROVE),
) -> OperationDetail:
    op = _awaiting(db, ctx, op_id)
    approved = approve_locked(db, ctx, op, body.reason)
    db.flush()
    if approved:
        _drain_later(background)
    return get_operation(op_id, db, ctx)


@router.post("/operations/{op_id}/reject", response_model=OperationDetail)
def reject_operation(
    op_id: uuid.UUID,
    body: DecisionIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_APPROVE),
) -> OperationDetail:
    op = _awaiting(db, ctx, op_id)
    reject_locked(db, ctx, op, body.reason)
    db.flush()
    return get_operation(op_id, db, ctx)
