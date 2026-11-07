"""NEXUS API: workflow definitions, runs, and the actions people take on steps.

Who may do what:
  * see definitions and runs: any member (READ)
  * start a run, start or retry a step, cancel: operations.propose with two-factor in the
    last 15 minutes. Starting a run also requires the permissions its executing steps need
    (a playbook step needs playbooks.run), checked again when each step starts
  * complete a review step: findings.validate
  * answer a checkpoint: operations.approve, with fresh two-factor (owner decision D5)
Agents have no route here: they can suggest a workflow in text, never start one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Query, Request
from pydantic import StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Finding,
    Project,
    User,
    ValidationStatus,
    WorkflowRun,
    WorkflowRunState,
    WorkflowStep,
    WorkflowStepEvent,
    WorkflowStepState,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission, has_permission
from nightfall.findings.routes import ref
from nightfall.nexus import engine
from nightfall.nexus.definitions import EXECUTING, UNAVAILABLE, WORKFLOWS, WorkflowDef
from nightfall.scope.engine import evaluate
from nightfall.scope.repository import active_scope, snapshot

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["nexus"])
S = WorkflowStepState
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]


# --- Schemas ---------------------------------------------------------------------------------


class WorkflowStepDefOut(Model):
    key: str
    label: str
    kind: str
    description: str
    depends_on: list[str]
    when: str
    retries: int
    timeout_hours: float
    starts: Literal["person", "automatic"]


class WorkflowDefOut(Model):
    id: str
    name: str
    version: str
    sha256: str
    summary: str
    starts_from: str
    deadline_days: float
    steps: list[WorkflowStepDefOut]
    tests: list[str]


class WorkflowsOut(Model):
    workflows: list[WorkflowDefOut]
    unavailable_step_kinds: list[str]


class WorkflowStartIn(Model):
    workflow_id: Annotated[str, StringConstraints(max_length=100)]
    target: Annotated[str, StringConstraints(max_length=300)] | None = None
    finding_id: uuid.UUID | None = None


class WorkflowRunOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    workflow_id: str
    workflow_name: str
    version: str
    subject: str
    state: WorkflowRunState
    started_by: str
    started_at: datetime
    deadline: datetime
    finished_at: datetime | None
    current: str | None  # label of the first step that isn't finished


class WorkflowStepOut(Model):
    key: str
    label: str
    kind: str
    description: str
    state: WorkflowStepState
    attempt: int
    retries: int
    depends_on: list[str]
    started_by: str | None
    started_at: datetime | None
    deadline: datetime | None
    finished_at: datetime | None
    detail: str
    outputs: dict[str, Any]
    can_retry: bool


class WorkflowTrackedFinding(Model):
    id: uuid.UUID
    ref: str
    title: str
    severity: str
    status: ValidationStatus


class WorkflowStepEventOut(Model):
    step_key: str
    from_state: WorkflowStepState | None
    to_state: WorkflowStepState
    actor: str
    detail: str
    occurred_at: datetime


class WorkflowRunDetail(WorkflowRunOut):
    organization_id: uuid.UUID
    definition_sha256: str
    cancel_reason: str
    steps: list[WorkflowStepOut]
    tracked: list[WorkflowTrackedFinding]
    events: list[WorkflowStepEventOut]


class WorkflowCompleteIn(Model):
    note: Note = ""


class WorkflowAnswerIn(Model):
    answer: Literal["continue", "stop"]
    note: Note = ""


class WorkflowCancelIn(Model):
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


# --- Helpers ---------------------------------------------------------------------------------


def _def_out(w: WorkflowDef) -> WorkflowDefOut:
    return WorkflowDefOut(
        id=w.id,
        name=w.name,
        version=w.version,
        sha256=w.sha256,
        summary=w.summary,
        starts_from=w.starts_from,
        deadline_days=w.deadline.total_seconds() / 86400,
        steps=[
            WorkflowStepDefOut(
                key=s.key,
                label=s.label,
                kind=s.kind,
                description=s.description,
                depends_on=list(s.depends_on),
                when=s.when,
                retries=s.retries,
                timeout_hours=s.deadline.total_seconds() / 3600,
                starts="person" if s.kind in EXECUTING else "automatic",
            )
            for s in w.steps
        ],
        tests=list(w.tests),
    )


def _names(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    ids_ = {i for i in ids if i}
    if not ids_:
        return {}
    return {
        r[0]: r[1] for r in db.execute(select(User.id, User.display_name).where(User.id.in_(ids_)))
    }


def _subject(run: WorkflowRun, db: Session) -> str:
    if run.inputs.get("target"):
        return str(run.inputs["target"])
    ids = run.inputs.get("finding_ids") or []
    f = db.get(Finding, uuid.UUID(ids[0])) if ids else None
    return f"{ref(f.number)} {f.title}" if f else "—"


def _run_out(
    db: Session, run: WorkflowRun, steps: list[WorkflowStep] | None = None
) -> WorkflowRunOut:
    steps = steps if steps is not None else engine.steps_of(db, run)
    project = db.get(Project, run.project_id)
    wf = WORKFLOWS.get(run.definition_id)
    current = next((s for s in steps if s.state not in engine.FINAL), None)
    names = _names(db, {run.started_by_user_id})
    return WorkflowRunOut(
        id=run.id,
        project_id=run.project_id,
        project_name=project.name if project else "—",
        workflow_id=run.definition_id,
        workflow_name=wf.name if wf else run.definition_id,
        version=run.definition_version,
        subject=_subject(run, db),
        state=run.state,
        started_by=names.get(run.started_by_user_id, "Unknown"),
        started_at=run.started_at,
        deadline=run.deadline,
        finished_at=run.finished_at,
        current=(wf.step(current.key).label if wf else current.key) if current else None,
    )


def _detail(db: Session, run: WorkflowRun) -> WorkflowRunDetail:
    steps = engine.steps_of(db, run)
    wf = engine.definition(run)
    events = db.scalars(
        select(WorkflowStepEvent)
        .where(WorkflowStepEvent.run_id == run.id)
        .order_by(WorkflowStepEvent.occurred_at, WorkflowStepEvent.id)
    ).all()
    names = _names(db, {s.started_by_user_id for s in steps} | {e.actor_user_id for e in events})
    project = db.get(Project, run.project_id)
    if project is None:
        raise not_found("Project not found.")
    return WorkflowRunDetail(
        **_run_out(db, run, steps).model_dump(),
        organization_id=project.organization_id,
        definition_sha256=run.definition_sha256,
        cancel_reason=run.cancel_reason,
        steps=[
            WorkflowStepOut(
                key=s.key,
                label=wf.step(s.key).label,
                kind=s.kind,
                description=wf.step(s.key).description,
                state=s.state,
                attempt=s.attempt,
                retries=wf.step(s.key).retries,
                depends_on=s.depends_on,
                started_by=names.get(s.started_by_user_id) if s.started_by_user_id else None,
                started_at=s.started_at,
                deadline=s.deadline,
                finished_at=s.finished_at,
                detail=s.detail,
                outputs=s.outputs,
                can_retry=run.state is WorkflowRunState.RUNNING
                and s.state in (S.FAILED, S.TIMED_OUT)
                and s.attempt <= wf.step(s.key).retries,
            )
            for s in steps
        ],
        tracked=[
            WorkflowTrackedFinding(
                id=f.id,
                ref=ref(f.number),
                title=f.title,
                severity=f.severity.value,
                status=f.validation_status,
            )
            for f in engine.tracked(db, run, steps)
        ],
        events=[
            WorkflowStepEventOut(
                step_key=e.step_key,
                from_state=e.from_state,
                to_state=e.to_state,
                actor=names.get(e.actor_user_id, "Unknown") if e.actor_user_id else "NEXUS",
                detail=e.detail,
                occurred_at=e.occurred_at,
            )
            for e in events
        ],
    )


def _run(db: Session, ctx: WorkspaceContext, run_id: uuid.UUID) -> WorkflowRun:
    run = db.get(WorkflowRun, run_id)
    if run is None or run.workspace_id != ctx.workspace_id:
        raise not_found("Workflow run not found.")
    return run


def _step(db: Session, run: WorkflowRun, key: str) -> WorkflowStep:
    step = db.scalar(
        select(WorkflowStep).where(WorkflowStep.run_id == run.id, WorkflowStep.key == key)
    )
    if step is None:
        raise not_found("Step not found.")
    return step


def _audit(db: Session, ctx: WorkspaceContext, action: str, run: WorkflowRun, **data: Any) -> None:
    record(
        db,
        action,
        entity_type="workflow_run",
        entity_id=run.id,
        data={"project_id": str(run.project_id), "workflow": run.definition_id, **data},
        **ctx.audit_kwargs(),
    )


def _running(run: WorkflowRun) -> None:
    if run.state is not WorkflowRunState.RUNNING:
        raise api_error(409, "run_finished", "This workflow run has finished.")


def _needed_permissions(w: WorkflowDef) -> list[Permission]:
    need = [Permission.OPERATIONS_PROPOSE]
    if any(s.kind == "playbook" for s in w.steps) or any(s.kind == "rerun" for s in w.steps):
        need.append(Permission.PLAYBOOKS_RUN)  # re-runs may relaunch a playbook
    if any(s.kind == "review" for s in w.steps):
        need.append(Permission.FINDINGS_VALIDATE)
    return need


# --- Routes ----------------------------------------------------------------------------------


@router.get("/nexus/workflows", response_model=WorkflowsOut)
def list_workflows(ctx: WorkspaceContext = ws_permission(Permission.READ)) -> WorkflowsOut:
    return WorkflowsOut(
        workflows=[_def_out(w) for w in WORKFLOWS.values()],
        unavailable_step_kinds=list(UNAVAILABLE),
    )


@router.post("/projects/{project_id}/workflows", response_model=WorkflowRunDetail, status_code=201)
def start_workflow(
    project_id: uuid.UUID,
    body: WorkflowStartIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE, fresh_mfa=True),
) -> WorkflowRunDetail:
    """Starting a run approves nothing: each step that contacts a target is started by a
    person and approved through the normal flow when it's due."""
    project = db.get(Project, project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    w = WORKFLOWS.get(body.workflow_id)
    if w is None:
        raise not_found("Workflow not found.")
    missing = [p for p in _needed_permissions(w) if not has_permission(ctx.role, p)]
    if missing:
        raise api_error(
            403, "forbidden", f"Your role can't run every step of this workflow ({missing[0]})."
        )
    now = utcnow()
    inputs: dict[str, Any]
    if w.starts_from == "target":
        scope = active_scope(db, project_id)
        if scope is None or scope.is_lab:
            raise api_error(409, "no_scope", "This workflow needs an active, non-lab scope.")
        decision = evaluate(snapshot(db, scope), body.target or "", now)
        if not decision.allowed:
            raise api_error(422, "out_of_scope", decision.reason)
        inputs = {"target": decision.target}
        same = WorkflowRun.inputs["target"].astext == decision.target
    else:
        f = db.get(Finding, body.finding_id) if body.finding_id else None
        if f is None or f.project_id != project_id:
            raise not_found("Finding not found.")
        if f.validation_status is not ValidationStatus.REMEDIATED:
            raise api_error(409, "not_remediated", "Only a remediated finding can be reassessed.")
        inputs = {"finding_ids": [str(f.id)]}
        same = WorkflowRun.inputs["finding_ids"].astext == f'["{f.id}"]'
    dup = db.scalar(
        select(WorkflowRun.id).where(
            WorkflowRun.project_id == project_id,
            WorkflowRun.definition_id == w.id,
            WorkflowRun.state == WorkflowRunState.RUNNING,
            same,
        )
    )
    if dup is not None:
        raise api_error(409, "already_running", "This workflow is already running for that.")
    run = WorkflowRun(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        definition_id=w.id,
        definition_version=w.version,
        definition_sha256=w.sha256,
        inputs=inputs,
        started_by_user_id=ctx.user_id,
        started_at=now,
        deadline=now + w.deadline,
    )
    db.add(run)
    db.flush()
    for i, s in enumerate(w.steps, start=1):
        db.add(
            WorkflowStep(
                workspace_id=ctx.workspace_id,
                run_id=run.id,
                key=s.key,
                kind=s.kind,
                position=i,
                depends_on=list(s.depends_on),
            )
        )
    db.flush()
    _audit(db, ctx, "workflow.started", run, version=w.version, sha256=w.sha256, **inputs)
    engine.advance(db, run.id, ctx)
    return _detail(db, run)


@router.get("/workflow-runs", response_model=list[WorkflowRunOut])
def list_runs(
    db: DB,
    project_id: uuid.UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[WorkflowRunOut]:
    q = select(WorkflowRun).where(WorkflowRun.workspace_id == ctx.workspace_id)
    if project_id is not None:
        q = q.where(WorkflowRun.project_id == project_id)
    runs = db.scalars(q.order_by(WorkflowRun.started_at.desc()).limit(limit)).all()
    for r in runs:
        if r.state is WorkflowRunState.RUNNING:
            engine.advance(db, r.id, ctx)
    return [_run_out(db, r) for r in runs]


@router.get("/workflow-runs/{run_id}", response_model=WorkflowRunDetail)
def get_workflow_run(
    run_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> WorkflowRunDetail:
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    return _detail(db, run)


@router.post("/workflow-runs/{run_id}/steps/{key}/start", response_model=WorkflowRunDetail)
def start_step(
    run_id: uuid.UUID,
    key: str,
    request: Request,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE, fresh_mfa=True),
) -> WorkflowRunDetail:
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    _running(run)
    step = _step(db, run, key)
    if step.kind not in EXECUTING:
        raise api_error(409, "not_startable", "This step starts by itself.")
    if step.state not in (S.READY, S.BLOCKED):
        raise api_error(409, "not_ready", "This step isn't ready to start.")
    try:
        if not has_permission(ctx.role, Permission.PLAYBOOKS_RUN):
            raise engine.StepRefused("Your role can't launch playbooks.")
        engine.start_step(db, ctx, run, step, request, background)
    except engine.StepRefused as exc:
        step.state, step.detail = S.BLOCKED, f"Couldn't start: {exc}"[:2000]
        db.flush()
        _audit(db, ctx, "workflow.step_blocked", run, step=key, reason=str(exc)[:300])
    else:
        _audit(
            db,
            ctx,
            "workflow.step_started",
            run,
            step=key,
            attempt=step.attempt,
            operations=len(step.outputs.get("operation_ids", [])),
        )
    engine.advance(db, run.id, ctx)
    return _detail(db, run)


@router.post("/workflow-runs/{run_id}/steps/{key}/retry", response_model=WorkflowRunDetail)
def retry_step(
    run_id: uuid.UUID,
    key: str,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE, fresh_mfa=True),
) -> WorkflowRunDetail:
    """Puts a failed step back to ready. A person still starts it, and its new operations
    need their own approvals: nothing is re-used."""
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    _running(run)
    step = _step(db, run, key)
    d = engine.definition(run).step(key)
    if step.state not in (S.FAILED, S.TIMED_OUT) or step.attempt > d.retries:
        raise api_error(409, "no_retry", "This step can't be retried.")
    step.state, step.detail = S.READY, "Retry requested."
    db.flush()
    _audit(db, ctx, "workflow.step_retried", run, step=key, attempt=step.attempt)
    return _detail(db, run)


@router.post("/workflow-runs/{run_id}/steps/{key}/complete", response_model=WorkflowRunDetail)
def complete_review(
    run_id: uuid.UUID,
    key: str,
    body: WorkflowCompleteIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> WorkflowRunDetail:
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    _running(run)
    step = _step(db, run, key)
    if step.kind != "review" or step.state != S.RUNNING:
        raise api_error(409, "not_waiting", "This step isn't waiting for a review.")
    step.state, step.finished_at = S.SUCCEEDED, utcnow()
    step.detail = f"Reviewed{': ' + body.note if body.note else '.'}"[:2000]
    step.outputs = {**step.outputs, "note": body.note, "by": str(ctx.user_id)}
    db.flush()
    _audit(db, ctx, "workflow.review_completed", run, step=key, note=body.note)
    engine.advance(db, run.id, ctx)
    return _detail(db, run)


@router.post("/workflow-runs/{run_id}/steps/{key}/answer", response_model=WorkflowRunDetail)
def answer_checkpoint(
    run_id: uuid.UUID,
    key: str,
    body: WorkflowAnswerIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_APPROVE, fresh_mfa=True),
) -> WorkflowRunDetail:
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    _running(run)
    step = _step(db, run, key)
    if step.kind != "checkpoint" or step.state != S.RUNNING:
        raise api_error(409, "not_waiting", "This checkpoint isn't waiting for an answer.")
    step.state, step.finished_at = S.SUCCEEDED, utcnow()
    word = "Continue" if body.answer == "continue" else "Stop"
    step.detail = f"{word}{': ' + body.note if body.note else '.'}"[:2000]
    step.outputs = {**step.outputs, "answer": body.answer, "note": body.note}
    db.flush()
    _audit(db, ctx, "workflow.checkpoint_answered", run, step=key, answer=body.answer)
    engine.advance(db, run.id, ctx)
    return _detail(db, run)


@router.post("/workflow-runs/{run_id}/cancel", response_model=WorkflowRunDetail)
def cancel_run(
    run_id: uuid.UUID,
    body: WorkflowCancelIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE),
) -> WorkflowRunDetail:
    """Queued operations are cancelled; running ones finish and their evidence is kept."""
    run = _run(db, ctx, run_id)
    engine.advance(db, run.id, ctx)
    _running(run)
    now = utcnow()
    steps = engine.steps_of(db, run)
    engine.end_open_steps(db, run, steps, f"Cancelled: {body.reason}", now)
    run.state, run.finished_at = WorkflowRunState.CANCELLED, now
    run.cancelled_by_user_id, run.cancel_reason = ctx.user_id, body.reason
    db.flush()
    _audit(db, ctx, "workflow.cancelled", run, reason=body.reason)
    return _detail(db, run)
