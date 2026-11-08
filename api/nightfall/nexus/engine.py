"""NEXUS engine: advancing runs, and the actions people take on steps.

Advancing is bookkeeping only. It recomputes which steps are ready, evaluates the fixed
predicates, notices finished operations and expired deadlines, and changes nothing but the
workflow tables (and cancels a timed-out step's queued operations, as a person could). It
never starts anything that contacts a target: a person does that (owner decision D3), and
starting a step calls the same functions a person would use directly (playbook launch,
collection request), with that person's identity and every one of their checks, at that
moment. NEXUS has no permissions of its own and never re-uses an approval.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from fastapi import BackgroundTasks, HTTPException, Request, Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    OPEN_STATUSES,
    ActorType,
    Evidence,
    Finding,
    FindingEvidence,
    Operation,
    OperationStatus,
    PlaybookRun,
    ValidationStatus,
    WorkflowRun,
    WorkflowRunState,
    WorkflowStep,
    WorkflowStepState,
)
from nightfall.core.tenancy.deps import WorkspaceContext
from nightfall.nexus.definitions import (
    EXECUTING,
    WARPATH_ID,
    WORKFLOWS,
    StepDef,
    WorkflowDef,
    warpath_definition,
)

S = WorkflowStepState
DONE = (S.SUCCEEDED, S.SKIPPED)
FINAL = (S.SUCCEEDED, S.SKIPPED, S.CANCELLED)
OP_BAD = (
    OperationStatus.FAILED,
    OperationStatus.DENIED,
    OperationStatus.REJECTED,
    OperationStatus.CANCELLED,
)
OP_PENDING = (OperationStatus.QUEUED, OperationStatus.AWAITING_APPROVAL)
COLLECTION_TOOLS = ("ct", "dns", "http", "nuclei")


class StepRefused(Exception):
    """A step couldn't start. The message is safe to show and is recorded."""


def definition(run: WorkflowRun) -> WorkflowDef:
    if run.definition_id == WARPATH_ID:  # plan-driven: rules in code, sequence from the plan
        return warpath_definition(run.inputs["plan"], run.inputs["plan_sha256"])
    return WORKFLOWS[run.definition_id]


@contextmanager
def as_system(db: Session, ctx: WorkspaceContext | None) -> Iterator[None]:
    """Automatic transitions are recorded without a person (the step-event trigger reads
    app.user_id), then the person's context is restored for whatever they do next."""
    db.flush()
    db.execute(text("SELECT set_config('app.user_id', '', true)"))
    try:
        yield
        db.flush()
    finally:
        if ctx is not None:
            db.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(ctx.user_id)})


def steps_of(db: Session, run: WorkflowRun) -> list[WorkflowStep]:
    return list(
        db.scalars(
            select(WorkflowStep)
            .where(WorkflowStep.run_id == run.id)
            .order_by(WorkflowStep.position)
        )
    )


# --- Tracked findings and predicates -------------------------------------------------------


def tracked_ids(run: WorkflowRun, steps: list[WorkflowStep]) -> list[uuid.UUID]:
    """The findings a run follows: given at start, or found by its first executing step."""
    ids: list[str] = run.inputs.get("finding_ids") or next(
        (s.outputs["tracked"] for s in steps if "tracked" in s.outputs), []
    )
    return [uuid.UUID(str(i)) for i in ids]


def tracked(db: Session, run: WorkflowRun, steps: list[WorkflowStep]) -> list[Finding]:
    ids = tracked_ids(run, steps)
    if not ids:
        return []
    return list(db.scalars(select(Finding).where(Finding.id.in_(ids)).order_by(Finding.number)))


def predicate(
    name: str, db: Session, run: WorkflowRun, step: StepDef, steps: list[WorkflowStep]
) -> bool:
    if name == "always":
        return True
    if name == "continue":
        by_key = {s.key: s for s in steps}
        return any(
            definition(run).step(d).kind == "checkpoint"
            and by_key[d].outputs.get("answer") == "continue"
            for d in step.depends_on
        )
    found = tracked(db, run, steps)
    if name == "tracked_open":
        return any(f.validation_status in OPEN_STATUSES for f in found)
    if name == "tracked_closed":
        return not any(f.validation_status in OPEN_STATUSES for f in found)
    if name == "any_remediated":
        return any(f.validation_status is ValidationStatus.REMEDIATED for f in found)
    raise ValueError(f"unknown predicate {name}")  # definitions are validated at import


def findings_from_operations(db: Session, op_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    """Open findings linked to evidence that these operations produced."""
    if not op_ids:
        return []
    rows = db.scalars(
        select(Finding.id)
        .join(FindingEvidence, FindingEvidence.finding_id == Finding.id)
        .join(Evidence, Evidence.id == FindingEvidence.evidence_id)
        .where(Evidence.operation_id.in_(op_ids), Finding.validation_status.in_(OPEN_STATUSES))
        .distinct()
    )
    return list(rows)


# --- Advancing -------------------------------------------------------------------------------


def _set(step: WorkflowStep, state: WorkflowStepState, detail: str, now: datetime) -> None:
    step.state = state
    step.detail = detail[:2000]
    if state in (S.SUCCEEDED, S.FAILED, S.TIMED_OUT, S.SKIPPED, S.CANCELLED):
        step.finished_at = now


def _cancel_pending_ops(db: Session, run: WorkflowRun, step: WorkflowStep, now: datetime) -> int:
    ids = [uuid.UUID(i) for i in step.outputs.get("operation_ids", [])]
    if not ids:
        return 0
    ops = db.scalars(
        select(Operation).where(Operation.id.in_(ids), Operation.status.in_(OP_PENDING))
    ).all()
    for op in ops:
        op.status, op.finished_at = OperationStatus.CANCELLED, now
        record(
            db,
            "operation.cancelled",
            actor_type=ActorType.SYSTEM,
            workspace_id=run.workspace_id,
            entity_type="operation",
            entity_id=op.id,
            data={"reason": f"Workflow step {step.key} ended", "workflow_run_id": str(run.id)},
        )
    return len(ops)


def _executing_progress(db: Session, step: WorkflowStep) -> tuple[WorkflowStepState, str] | None:
    ids = [uuid.UUID(i) for i in step.outputs.get("operation_ids", [])]
    if not ids:
        return S.FAILED, "No operations were recorded for this step."
    statuses = dict(
        db.execute(select(Operation.id, Operation.status).where(Operation.id.in_(ids))).all()
    )
    bad = [s for s in statuses.values() if s in OP_BAD]
    if bad:
        return S.FAILED, f"An operation ended as {bad[0].value.replace('_', ' ')}."
    if all(s is OperationStatus.SUCCEEDED for s in statuses.values()):
        return S.SUCCEEDED, f"{len(ids)} operation(s) succeeded."
    return None


def _finish(db: Session, run: WorkflowRun, state: WorkflowRunState, now: datetime) -> None:
    run.state, run.finished_at = state, now
    record(
        db,
        "workflow.finished",
        actor_type=ActorType.SYSTEM,
        workspace_id=run.workspace_id,
        entity_type="workflow_run",
        entity_id=run.id,
        data={"project_id": str(run.project_id), "workflow": run.definition_id, "status": state},
    )


def end_open_steps(
    db: Session, run: WorkflowRun, steps: list[WorkflowStep], reason: str, now: datetime
) -> None:
    for s in steps:
        if s.state in FINAL:
            continue
        if s.kind in EXECUTING and s.state == S.RUNNING:
            _cancel_pending_ops(db, run, s, now)
        _set(s, S.CANCELLED, reason, now)


def advance(
    db: Session, run_id: uuid.UUID, ctx: WorkspaceContext | None, now: datetime | None = None
) -> WorkflowRun:
    """Idempotent; serialised per run by a row lock."""
    now = now or utcnow()
    run = db.scalar(select(WorkflowRun).where(WorkflowRun.id == run_id).with_for_update())
    if run is None:
        raise LookupError("workflow run not found")
    if run.state is not WorkflowRunState.RUNNING:
        return run
    wf = definition(run)
    steps = steps_of(db, run)
    by_key = {s.key: s for s in steps}
    with as_system(db, ctx):
        if now >= run.deadline:
            end_open_steps(db, run, steps, "The workflow's deadline passed.", now)
            _finish(db, run, WorkflowRunState.TIMED_OUT, now)
            return run
        changed = True
        while changed:
            changed = False
            for s in steps:
                d = wf.step(s.key)
                if s.state == S.PENDING:
                    deps = [by_key[k] for k in d.depends_on]
                    if not all(x.state in DONE for x in deps):
                        continue
                    if any(x.state == S.SKIPPED for x in deps):
                        _set(s, S.SKIPPED, "A step it depends on was skipped.", now)
                    elif not predicate(d.when, db, run, d, steps):
                        _set(s, S.SKIPPED, f"Not needed: condition '{d.when}' wasn't met.", now)
                    elif s.kind in EXECUTING:
                        _set(s, S.READY, "Ready for a person to start.", now)
                    else:
                        _set(s, S.READY, "Ready.", now)
                        db.flush()  # pending → ready → running: both recorded
                        s.state, s.started_at, s.deadline = S.RUNNING, now, now + d.deadline
                        s.detail = "Waiting for a person." if s.kind != "wait" else "Waiting."
                    changed = True
                elif s.state == S.RUNNING:
                    if s.deadline is not None and now >= s.deadline:
                        if s.kind in EXECUTING:
                            _cancel_pending_ops(db, run, s, now)
                        _set(s, S.TIMED_OUT, "The step's deadline passed.", now)
                        changed = True
                    elif s.kind in EXECUTING:
                        progress = _executing_progress(db, s)
                        if progress is not None:
                            if progress[0] == S.SUCCEEDED and not tracked_ids(run, steps):
                                ops = [uuid.UUID(i) for i in s.outputs.get("operation_ids", [])]
                                found = findings_from_operations(db, ops)
                                s.outputs = {**s.outputs, "tracked": [str(i) for i in found]}
                            _set(s, progress[0], progress[1], now)
                            changed = True
                    elif s.kind == "wait" and predicate(d.params["until"], db, run, d, steps):
                        _set(s, S.SUCCEEDED, "The condition is met.", now)
                        changed = True
        # Finished?
        if all(s.state in DONE for s in steps):
            _finish(db, run, WorkflowRunState.SUCCEEDED, now)
        else:
            stuck = [
                s
                for s in steps
                if s.state in (S.FAILED, S.TIMED_OUT) and s.attempt > wf.step(s.key).retries
            ]
            if stuck:
                end_open_steps(
                    db, run, steps, f"Step '{stuck[0].key}' failed with no retries left.", now
                )
                _finish(db, run, WorkflowRunState.FAILED, now)
    return run


# --- Starting executing steps ----------------------------------------------------------------


def _launch_playbook(
    db: Session,
    ctx: WorkspaceContext,
    run: WorkflowRun,
    playbook_id: str,
    target: str,
    request: Request,
    background: BackgroundTasks,
) -> tuple[str, list[uuid.UUID]]:
    from nightfall.blackops.catalog import PLAYBOOKS
    from nightfall.blackops.routes import LaunchIn, launch_run

    p = PLAYBOOKS[playbook_id]
    body = LaunchIn(playbook_id=p.id, target=target, version=p.version, definition_sha256=p.sha256)
    detail = launch_run(run.project_id, body, request, background, db, ctx)
    ops = db.scalars(select(Operation.id).where(Operation.playbook_run_id == detail.id)).all()
    return str(detail.id), list(ops)


def _request_collection(
    db: Session,
    ctx: WorkspaceContext,
    run: WorkflowRun,
    tool: str,
    target: str,
    request: Request,
    background: BackgroundTasks,
) -> uuid.UUID:
    from nightfall.recon.routes import CollectionIn, request_collection

    out = request_collection(
        run.project_id,
        CollectionIn(tool=tool, target=target),  # type: ignore[arg-type]
        request,
        Response(),
        background,
        db,
        ctx,
    )
    return out.id


def rerun_plan(db: Session, run: WorkflowRun, steps: list[WorkflowStep]) -> list[dict[str, str]]:
    """What produced each remediated tracked finding, de-duplicated: the playbook it came
    from (on the same target) or the collector. Computed by this code, never supplied."""
    plan: dict[tuple[str, str, str], dict[str, str]] = {}
    for f in tracked(db, run, steps):
        if f.validation_status is not ValidationStatus.REMEDIATED:
            continue
        op = db.scalar(
            select(Operation)
            .join(Evidence, Evidence.operation_id == Operation.id)
            .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
            .where(FindingEvidence.finding_id == f.id)
            .order_by(Evidence.collected_at.desc())
            .limit(1)
        )
        if op is None:
            raise StepRefused(f"Finding {f.title!r} has no collected evidence to re-run.")
        if op.playbook_run_id is not None:
            pr = db.get(PlaybookRun, op.playbook_run_id)
            if pr is None:
                raise StepRefused(f"The playbook run behind {f.title!r} wasn't found.")
            plan[("playbook", pr.playbook_id, pr.target_value)] = {
                "via": "playbook",
                "playbook_id": pr.playbook_id,
                "target": pr.target_value,
            }
        elif op.tool in COLLECTION_TOOLS:
            plan[("collection", op.tool, op.target_value)] = {
                "via": "collection",
                "tool": op.tool,
                "target": op.target_value,
            }
        else:
            raise StepRefused(f"The {op.tool} check that found {f.title!r} can't be re-run here.")
    if not plan:
        raise StepRefused("No remediated finding to reassess.")
    return list(plan.values())


def start_step(
    db: Session,
    ctx: WorkspaceContext,
    run: WorkflowRun,
    step: WorkflowStep,
    request: Request,
    background: BackgroundTasks,
) -> None:
    """Runs the step's real launch path as this person, in a savepoint: a refusal leaves no
    partial work (refusal audit events are written separately, as they are for people)."""
    from nightfall.blackops.catalog import PLAYBOOKS

    wf = definition(run)
    d = wf.step(step.key)
    steps = steps_of(db, run)
    now = utcnow()
    if run.definition_sha256 != wf.sha256:
        raise StepRefused("The workflow's definition changed since this run started.")
    try:
        with db.begin_nested():
            if step.kind == "playbook":
                pid = d.params["playbook_id"]
                if pid not in PLAYBOOKS:
                    raise StepRefused(f"Playbook {pid} isn't in the catalog.")
                pr_id, ops = _launch_playbook(
                    db,
                    ctx,
                    run,
                    pid,
                    d.params.get("target") or run.inputs["target"],
                    request,
                    background,
                )
                outputs: dict[str, Any] = {"playbook_run_ids": [pr_id]}
            else:
                plan = rerun_plan(db, run, steps)
                ops, runs = [], []
                for item in plan:
                    if item["via"] == "playbook":
                        pr_id, got = _launch_playbook(
                            db, ctx, run, item["playbook_id"], item["target"], request, background
                        )
                        ops += got
                        runs.append(pr_id)
                    else:
                        ops.append(
                            _request_collection(
                                db, ctx, run, item["tool"], item["target"], request, background
                            )
                        )
                outputs = {"playbook_run_ids": runs, "plan": plan}
            outputs["operation_ids"] = [str(o) for o in ops]
            if step.outputs.get("tracked"):
                outputs["tracked"] = step.outputs["tracked"]
    except HTTPException as exc:
        msg = exc.detail.get("message") if isinstance(exc.detail, dict) else str(exc.detail)
        raise StepRefused(str(msg or "Refused.")) from None
    step.state, step.attempt = S.RUNNING, step.attempt + 1
    step.started_by_user_id, step.started_at = ctx.user_id, now
    step.deadline, step.finished_at = now + d.deadline, None
    step.outputs, step.detail = outputs, f"Started: {len(outputs['operation_ids'])} operation(s)."
