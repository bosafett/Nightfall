"""BLACKSITE probe deck API (mounted only in the host-only BLACKSITE app).

Execution path (review §16.3, lab profile):
  1. Resolve the target from the registry by asset id. No free-form host, URL or IP.
  2. Active lab scope of the project; the asset must be in it and not excluded.
  3. Validate the probe spec and its ports against that target entry's bounds.
  4. Rate (max_rps) and daily budget, counted in Postgres under an advisory lock; at most
     one probe pending per target (database unique index).
  5. Write the operation and an audit event. It waits for an explicit approval, which the
     owner can give in the same request (single operator, D1). State-changing methods also
     need confirm_state_change.
  6-7. The lab worker re-checks scope, approval and bounds, then runs it (probes.Probe).
Every refusal is audited.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, BackgroundTasks, Query, Request
from pydantic import StringConstraints
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.blacksite.boundary import lab_boundary
from nightfall.blacksite.probes import (
    Probe,
    ProbeRejected,
    ProbeSpec,
    check_ports,
    diff,
    target_bounds,
)
from nightfall.core.audit.writer import record, record_detached
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Asset,
    Evidence,
    Operation,
    OperationStatus,
    Project,
    ScopeTarget,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import (
    WorkspaceContext,
    is_blacksite,
    may_approve_own,
    ws_permission,
)
from nightfall.core.tenancy.permissions import Permission
from nightfall.recon.routes import OperationOut, _get_op, _out, _query, approve_locked
from nightfall.scope.engine import evaluate
from nightfall.scope.repository import active_scope, snapshot

router = APIRouter(prefix="/api/workspaces/{workspace_id}/blacksite/probes", tags=["blacksite"])

Reason = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]


class ProbeIn(Model):
    project_id: uuid.UUID
    asset_id: uuid.UUID
    spec: ProbeSpec
    approve: bool = False  # owner approves in the same request (single operator)
    confirm_state_change: bool = False
    reason: Reason = ""


class DecideIn(Model):
    approve: bool = False
    confirm_state_change: bool = False
    reason: Reason = ""


class CompareOut(Model):
    a: uuid.UUID
    b: uuid.UUID
    target: str
    differences: dict[str, Any]


def _deny(
    ctx: WorkspaceContext, status: int, code: str, message: str, data: dict[str, Any]
) -> NoReturn:
    record_detached("probe.denied", data={"code": code, **data}, **ctx.audit_kwargs())
    raise api_error(status, code, message)


def create_probe(
    db: Session, ctx: WorkspaceContext, request: Request, body: ProbeIn, replay_of: uuid.UUID | None
) -> Operation:
    if not is_blacksite(request):  # also unreachable: the router is only in the BLACKSITE app
        raise not_found()
    info: dict[str, Any] = {"asset_id": str(body.asset_id), "type": body.spec.type}
    project = db.scalar(
        select(Project).where(
            Project.id == body.project_id, Project.workspace_id == ctx.workspace_id
        )
    )
    asset = db.scalar(
        select(Asset).where(Asset.id == body.asset_id, Asset.workspace_id == ctx.workspace_id)
    )
    if project is None or asset is None or asset.organization_id != project.organization_id:
        _deny(
            ctx,
            404,
            "unregistered_target",
            "No registered lab asset with that id in this project.",
            info,
        )
    scope = active_scope(db, project.id)
    lab_boundary(request, ctx, scope is not None and scope.is_lab, "probe.request", executes=True)
    if scope is None:  # unreachable: lab_boundary refuses a missing scope in BLACKSITE
        raise not_found()
    target = asset.value
    info["target"] = target
    decision = evaluate(snapshot(db, scope), target, utcnow())
    if not decision.allowed:
        _deny(ctx, 422, "out_of_scope", decision.reason, info)
    entries = db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id == scope.id)).all()
    bounds = target_bounds(entries, target)
    if bounds is None:
        _deny(ctx, 422, "out_of_scope", "No scope entry gives this target probe bounds.", info)
    try:
        check_ports(body.spec, bounds)
    except ProbeRejected as exc:
        _deny(ctx, 422, "probe_rejected", str(exc), info)
    if body.spec.state_changing and not body.confirm_state_change:
        _deny(
            ctx,
            422,
            "confirm_required",
            f"{body.spec.method} can change state on the target; confirm it explicitly.",
            info,
        )
    if body.approve and not may_approve_own(db, ctx):
        _deny(ctx, 409, "self_approval", "The approval policy doesn't let you approve this.", info)

    # Rate and budget, serialized per target so concurrent requests can't both pass.
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
        {"k": f"probe:{scope.id}:{target}"},
    )
    now = utcnow()

    def count(since: timedelta) -> int:
        return (
            db.scalar(
                select(func.count())
                .select_from(Operation)
                .where(
                    Operation.project_id == project.id,
                    Operation.tool == Probe.key,
                    Operation.target_value == target,
                    Operation.created_at > now - since,
                )
            )
            or 0
        )

    if count(timedelta(days=1)) >= bounds.daily_budget:
        _deny(
            ctx,
            429,
            "budget_exhausted",
            f"Daily budget of {bounds.daily_budget} probes used.",
            info,
        )
    if count(timedelta(seconds=1)) >= bounds.max_rps:
        _deny(ctx, 429, "rate_limited", f"At most {bounds.max_rps} probe(s) per second.", info)

    op = Operation(
        workspace_id=ctx.workspace_id,
        project_id=project.id,
        scope_id=scope.id,
        tool=Probe.key,
        risk_class=body.spec.risk,
        target_value=target,
        params={
            "method": Probe.label,
            "probe": body.spec.model_dump(),
            "asset_id": str(asset.id),
            **({"replay_of": str(replay_of)} if replay_of else {}),
        },
        requested_by_user_id=ctx.user_id,
        is_lab=True,
        status=OperationStatus.AWAITING_APPROVAL,
    )
    try:
        with db.begin_nested():
            db.add(op)
            db.flush()
    except IntegrityError:
        _deny(ctx, 409, "probe_pending", "A probe is already pending for this target.", info)
    record(
        db,
        "probe.requested",
        entity_type="operation",
        entity_id=op.id,
        data={
            **info,
            "method": body.spec.method,
            "risk_class": op.risk_class.value,
            "replay_of": str(replay_of) if replay_of else None,
        },  # fmt: skip
        **ctx.audit_kwargs(),
    )
    if body.approve:
        approve_locked(db, ctx, op, body.reason or "Approved at request (single operator).")
    db.flush()
    return op


@router.post("", response_model=OperationOut, status_code=201)
def request_probe(
    body: ProbeIn,
    request: Request,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE, fresh_mfa=True),
) -> OperationOut:
    op = create_probe(db, ctx, request, body, None)
    return _out(_get_op(db, ctx, op.id))


@router.get("", response_model=list[OperationOut])
def list_probes(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[OperationOut]:
    q = _query().where(Operation.workspace_id == ctx.workspace_id, Operation.tool == Probe.key)
    if asset_id is not None:
        q = q.where(Operation.params["asset_id"].astext == str(asset_id))
    return [_out(r) for r in db.execute(q.order_by(Operation.queued_at.desc()).limit(limit))]


def _probe_op(db: Session, ctx: WorkspaceContext, op_id: uuid.UUID) -> Operation:
    op = db.scalar(
        select(Operation).where(
            Operation.id == op_id,
            Operation.workspace_id == ctx.workspace_id,
            Operation.tool == Probe.key,
        )
    )
    if op is None:
        raise not_found("Probe not found.")
    return op


@router.post("/{op_id}/replay", response_model=OperationOut, status_code=201)
def replay_probe(
    op_id: uuid.UUID,
    body: DecideIn,
    request: Request,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE, fresh_mfa=True),
) -> OperationOut:
    """A new operation with the same parameters, checked again in full. The earlier
    approval is never reused."""
    old = _probe_op(db, ctx, op_id)
    new = create_probe(
        db,
        ctx,
        request,
        ProbeIn(
            project_id=old.project_id,
            asset_id=uuid.UUID(str(old.params["asset_id"])),
            spec=ProbeSpec.model_validate(old.params["probe"]),
            approve=body.approve,
            confirm_state_change=body.confirm_state_change,
            reason=body.reason,
        ),
        old.id,
    )
    return _out(_get_op(db, ctx, new.id))


@router.get("/compare", response_model=CompareOut)
def compare_probes(
    a: uuid.UUID,
    b: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> CompareOut:
    ops = [_probe_op(db, ctx, x) for x in (a, b)]
    if ops[0].target_value != ops[1].target_value:
        raise api_error(422, "different_targets", "Compare probes of the same target.")
    records = []
    for op in ops:
        ev = db.scalar(select(Evidence).where(Evidence.operation_id == op.id))
        if ev is None or not ev.summary.get("probe"):
            raise api_error(409, "no_result", "Both probes need a stored result.")
        records.append(ev.summary["probe"])
    return CompareOut(
        a=a, b=b, target=ops[0].target_value, differences=diff(records[0], records[1])
    )
