"""WARPATH v1 API: purple-team exercise plans, runs (NEXUS, from BLACKSITE) and scores.

* plans: analysts and above draft them (findings.edit); the owner approves, with fresh
  two-factor, which freezes the plan and its SHA-256. Approval runs nothing.
* running: the owner starts an approved exercise, creating a NEXUS run of the
  plan-driven definition. Each attack step is started by a person and goes through the
  normal lab preflight and lab approval, which only BLACKSITE (host-only) can pass.
* scoring: findings.validate. A missed detection raises a SHIELD alert (medium); a
  partial one, a low one (owner decision 3).
* agents have no route here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Response
from pydantic import Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Alert,
    AttackPath,
    Project,
    Severity,
    User,
    WarpathExercise,
    WarpathScore,
    WorkflowRun,
    WorkflowRunState,
    WorkflowStep,
    WorkflowStepState,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.nexus import engine
from nightfall.nexus.definitions import WARPATH_ID, warpath_definition
from nightfall.scope.engine import evaluate
from nightfall.scope.repository import active_scope, snapshot
from nightfall.warpath.catalogue import MAPPING, MAX_STEPS, attack, plan_sha256, techniques

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["warpath"])
Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]


class WarpathPlanStep(Model):
    playbook_id: Annotated[str, StringConstraints(max_length=64)]
    target: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)]
    technique_id: Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
    expected_detection: Short = ""


class WarpathExerciseIn(Model):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    objective: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""
    source_path_id: uuid.UUID | None = None
    steps: Annotated[list[WarpathPlanStep], Field(min_length=1, max_length=MAX_STEPS)]


class WarpathScoreIn(Model):
    attack_result: Literal["succeeded", "failed", "blocked"]
    detection: Literal["detected", "partial", "missed", "not_applicable"]
    minutes_to_detect: int | None = Field(None, ge=0, le=100000)
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class AttackTechniqueOut(Model):
    id: str
    name: str
    tactics: list[str]


class WarpathCataloguePlaybook(Model):
    id: str
    name: str
    techniques: list[AttackTechniqueOut]


class WarpathCatalogueOut(Model):
    release: str
    released: str
    attribution: str
    playbooks: list[WarpathCataloguePlaybook]
    note: str


class WarpathScoreOut(Model):
    attack_result: str
    detection: str
    minutes_to_detect: int | None
    note: str
    scored_by: str
    scored_at: datetime


class WarpathStepOut(Model):
    step: int
    playbook_id: str
    target: str
    technique: AttackTechniqueOut
    expected_detection: str
    attack_state: str | None  # NEXUS step state, once running
    score_state: str | None
    score: WarpathScoreOut | None


class WarpathScorecardOut(Model):
    steps: int
    scored: int
    attacks_succeeded: int
    attacks_blocked: int
    detected: int
    partial: int
    missed: int
    median_minutes_to_detect: float | None
    by_tactic: dict[str, dict[str, int]]  # tactic -> {detected, partial, missed, not_scored}


class WarpathExerciseOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    name: str
    objective: str
    source_path_id: uuid.UUID | None
    state: str
    plan_sha256: str
    created_by: str
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    workflow_run_id: uuid.UUID | None
    attack_release: str


class WarpathExerciseDetail(WarpathExerciseOut):
    steps: list[WarpathStepOut]
    scorecard: WarpathScorecardOut


# --- Helpers ---------------------------------------------------------------------------------


def _names(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    ids_ = {i for i in ids if i}
    if not ids_:
        return {}
    rows = db.execute(select(User.id, User.display_name).where(User.id.in_(ids_)))
    return {u: n for u, n in rows}


def _tech(tid: str) -> AttackTechniqueOut:
    t = techniques().get(tid)
    return AttackTechniqueOut(
        id=tid, name=t.name if t else "?", tactics=list(t.tactics) if t else []
    )


def _plan(
    db: Session, ws: uuid.UUID, project_id: uuid.UUID, body: WarpathExerciseIn
) -> list[dict[str, Any]]:
    scope = active_scope(db, project_id)
    if scope is None or not scope.is_lab:
        raise api_error(
            409, "no_lab_scope", "WARPATH exercises need the project's active lab scope."
        )
    snap = snapshot(db, scope)
    now = utcnow()
    plan: list[dict[str, Any]] = []
    for i, st in enumerate(body.steps, start=1):
        allowed = MAPPING.get(st.playbook_id)
        if allowed is None:
            raise api_error(
                422, "not_a_lab_playbook", f"Step {i}: {st.playbook_id} isn't a lab playbook."
            )
        if st.technique_id not in allowed:
            raise api_error(
                422,
                "technique_not_performed",
                f"Step {i}: {st.playbook_id} doesn't perform {st.technique_id}; it can claim "
                f"{', '.join(allowed)}.",
            )
        decision = evaluate(snap, st.target, now)
        if not decision.allowed:
            raise api_error(422, "out_of_scope", f"Step {i}: {decision.reason}")
        plan.append(
            {
                "playbook_id": st.playbook_id,
                "target": decision.target,
                "technique_id": st.technique_id,
                "expected_detection": st.expected_detection,
            }
        )
    if body.source_path_id is not None:
        p = db.get(AttackPath, body.source_path_id)
        if p is None or p.workspace_id != ws or p.project_id != project_id:
            raise not_found("Attack path not found.")
    return plan


def _exercise(db: Session, ctx: WorkspaceContext, exercise_id: uuid.UUID) -> WarpathExercise:
    ex = db.get(WarpathExercise, exercise_id)
    if ex is None or ex.workspace_id != ctx.workspace_id:
        raise not_found("Exercise not found.")
    return ex


def _sync(db: Session, ex: WarpathExercise, ctx: WorkspaceContext) -> None:
    """A running exercise ends when its NEXUS run does."""
    if ex.state != "running" or ex.workflow_run_id is None:
        return
    run = engine.advance(db, ex.workflow_run_id, ctx)
    if run.state is WorkflowRunState.CANCELLED:
        ex.state = "cancelled"
    elif run.state is not WorkflowRunState.RUNNING:
        ex.state = "finished"
    db.flush()


def _out(db: Session, ex: WarpathExercise) -> WarpathExerciseOut:
    project = db.get(Project, ex.project_id)
    names = _names(db, {ex.created_by_user_id, ex.approved_by_user_id})
    return WarpathExerciseOut(
        id=ex.id,
        project_id=ex.project_id,
        project_name=project.name if project else "—",
        name=ex.name,
        objective=ex.objective,
        source_path_id=ex.source_path_id,
        state=ex.state,
        plan_sha256=ex.plan_sha256,
        created_by=names.get(ex.created_by_user_id, "Unknown"),
        created_at=ex.created_at,
        approved_by=names.get(ex.approved_by_user_id) if ex.approved_by_user_id else None,
        approved_at=ex.approved_at,
        workflow_run_id=ex.workflow_run_id,
        attack_release=str(attack()["release"]),
    )


def _latest_scores(db: Session, ex: WarpathExercise) -> dict[int, WarpathScore]:
    rows = db.scalars(
        select(WarpathScore)
        .where(WarpathScore.exercise_id == ex.id)
        .order_by(WarpathScore.step, WarpathScore.scored_at.desc(), WarpathScore.id)
    ).all()
    latest: dict[int, WarpathScore] = {}
    for r in rows:
        latest.setdefault(r.step, r)
    return latest


def _detail(db: Session, ex: WarpathExercise) -> WarpathExerciseDetail:
    latest = _latest_scores(db, ex)
    states: dict[str, str] = {}
    if ex.workflow_run_id:
        states = {
            s.key: s.state.value
            for s in db.scalars(
                select(WorkflowStep).where(WorkflowStep.run_id == ex.workflow_run_id)
            )
        }
    names = _names(db, {s.scored_by_user_id for s in latest.values()})
    steps: list[WarpathStepOut] = []
    by_tactic: dict[str, dict[str, int]] = {}
    minutes: list[int] = []
    for i, p in enumerate(ex.plan, start=1):
        sc = latest.get(i)
        tech = _tech(p["technique_id"])
        steps.append(
            WarpathStepOut(
                step=i,
                playbook_id=p["playbook_id"],
                target=p["target"],
                technique=tech,
                expected_detection=p.get("expected_detection", ""),
                attack_state=states.get(f"s{i}_attack"),
                score_state=states.get(f"s{i}_score"),
                score=WarpathScoreOut(
                    attack_result=sc.attack_result,
                    detection=sc.detection,
                    minutes_to_detect=sc.minutes_to_detect,
                    note=sc.note,
                    scored_by=names.get(sc.scored_by_user_id, "Unknown"),
                    scored_at=sc.scored_at,
                )
                if sc
                else None,
            )
        )
        for tactic in tech.tactics or ["unknown"]:
            row = by_tactic.setdefault(
                tactic, {"detected": 0, "partial": 0, "missed": 0, "not_scored": 0}
            )
            key = sc.detection if sc and sc.detection != "not_applicable" else "not_scored"
            row[key] = row.get(key, 0) + 1
        if sc and sc.minutes_to_detect is not None:
            minutes.append(sc.minutes_to_detect)
    scored = list(latest.values())
    minutes.sort()
    median = (
        None
        if not minutes
        else float(minutes[len(minutes) // 2])
        if len(minutes) % 2
        else (minutes[len(minutes) // 2 - 1] + minutes[len(minutes) // 2]) / 2
    )
    return WarpathExerciseDetail(
        **_out(db, ex).model_dump(),
        steps=steps,
        scorecard=WarpathScorecardOut(
            steps=len(ex.plan),
            scored=len(scored),
            attacks_succeeded=sum(1 for s in scored if s.attack_result == "succeeded"),
            attacks_blocked=sum(1 for s in scored if s.attack_result == "blocked"),
            detected=sum(1 for s in scored if s.detection == "detected"),
            partial=sum(1 for s in scored if s.detection == "partial"),
            missed=sum(1 for s in scored if s.detection == "missed"),
            median_minutes_to_detect=median,
            by_tactic=by_tactic,
        ),
    )


def _audit(
    db: Session, ctx: WorkspaceContext, action: str, ex: WarpathExercise, **data: Any
) -> None:
    record(
        db,
        action,
        entity_type="warpath_exercise",
        entity_id=ex.id,
        data={"project_id": str(ex.project_id), "name": ex.name, **data},
        **ctx.audit_kwargs(),
    )


# --- Routes ----------------------------------------------------------------------------------


@router.get("/warpath/catalogue", response_model=WarpathCatalogueOut)
def catalogue(ctx: WorkspaceContext = ws_permission(Permission.READ)) -> WarpathCatalogueOut:
    from nightfall.blackops.catalog import PLAYBOOKS

    a = attack()
    return WarpathCatalogueOut(
        release=str(a["release"]),
        released=str(a["released"]),
        attribution=str(a["attribution"]),
        playbooks=[
            WarpathCataloguePlaybook(
                id=pid, name=PLAYBOOKS[pid].name, techniques=[_tech(t) for t in techs]
            )
            for pid, techs in MAPPING.items()
        ],
        note="Today's lab playbooks are discovery and scanning, so exercises cover "
        "reconnaissance and probing. Later attack stages need new reviewed lab playbooks.",
    )


@router.get("/warpath/exercises", response_model=list[WarpathExerciseOut])
def list_exercises(
    db: DB,
    project_id: uuid.UUID | None = None,
    state: str | None = None,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> list[WarpathExerciseOut]:
    q = select(WarpathExercise).where(WarpathExercise.workspace_id == ctx.workspace_id)
    if project_id:
        q = q.where(WarpathExercise.project_id == project_id)
    rows = db.scalars(q.order_by(WarpathExercise.created_at.desc()).limit(200)).all()
    for ex in rows:
        _sync(db, ex, ctx)
    return [_out(db, ex) for ex in rows if state is None or ex.state == state]


@router.post(
    "/projects/{project_id}/warpath/exercises",
    response_model=WarpathExerciseDetail,
    status_code=201,
)
def create_exercise(
    project_id: uuid.UUID,
    body: WarpathExerciseIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> WarpathExerciseDetail:
    project = db.get(Project, project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    plan = _plan(db, ctx.workspace_id, project_id, body)
    ex = WarpathExercise(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        name=body.name,
        objective=body.objective,
        source_path_id=body.source_path_id,
        plan=plan,
        plan_sha256=plan_sha256(plan),
        created_by_user_id=ctx.user_id,
    )
    db.add(ex)
    db.flush()
    _audit(db, ctx, "warpath.drafted", ex, steps=len(plan))
    return _detail(db, ex)


@router.put("/warpath/exercises/{exercise_id}", response_model=WarpathExerciseDetail)
def update_exercise(
    exercise_id: uuid.UUID,
    body: WarpathExerciseIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> WarpathExerciseDetail:
    ex = _exercise(db, ctx, exercise_id)
    if ex.state != "draft":
        raise api_error(409, "frozen", "An approved exercise can't be edited; copy it instead.")
    plan = _plan(db, ctx.workspace_id, ex.project_id, body)
    ex.name, ex.objective, ex.plan, ex.plan_sha256 = (
        body.name,
        body.objective,
        plan,
        plan_sha256(plan),
    )
    db.flush()
    return _detail(db, ex)


@router.delete("/warpath/exercises/{exercise_id}", status_code=204)
def delete_exercise(
    exercise_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT)
) -> Response:
    ex = _exercise(db, ctx, exercise_id)
    if ex.state != "draft":
        raise api_error(409, "frozen", "Only a draft can be deleted.")
    _audit(db, ctx, "warpath.draft_deleted", ex)
    db.delete(ex)
    db.flush()
    return Response(status_code=204)


@router.get("/warpath/exercises/{exercise_id}", response_model=WarpathExerciseDetail)
def get_exercise(
    exercise_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> WarpathExerciseDetail:
    ex = _exercise(db, ctx, exercise_id)
    _sync(db, ex, ctx)
    return _detail(db, ex)


@router.post("/warpath/exercises/{exercise_id}/approve", response_model=WarpathExerciseDetail)
def approve_exercise(
    exercise_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.PLAYBOOKS_RUN, fresh_mfa=True),
) -> WarpathExerciseDetail:
    """Freezes the plan. Runs nothing: each attack step still needs its own lab approval."""
    ex = _exercise(db, ctx, exercise_id)
    if ex.state != "draft":
        raise api_error(409, "not_draft", "Only a draft can be approved.")
    if plan_sha256(ex.plan) != ex.plan_sha256:
        raise api_error(409, "plan_changed", "The plan doesn't match its fingerprint.")
    ex.state, ex.approved_by_user_id, ex.approved_at = "approved", ctx.user_id, utcnow()
    db.flush()
    _audit(db, ctx, "warpath.approved", ex, plan_sha256=ex.plan_sha256)
    return _detail(db, ex)


@router.post("/warpath/exercises/{exercise_id}/start", response_model=WarpathExerciseDetail)
def start_exercise(
    exercise_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.PLAYBOOKS_RUN, fresh_mfa=True),
) -> WarpathExerciseDetail:
    """Creates the NEXUS run. Its attack steps can only be started from BLACKSITE."""
    ex = _exercise(db, ctx, exercise_id)
    if ex.state != "approved":
        raise api_error(409, "not_approved", "Approve the exercise first.")
    w = warpath_definition(ex.plan, ex.plan_sha256)
    now = utcnow()
    run = WorkflowRun(
        workspace_id=ctx.workspace_id,
        project_id=ex.project_id,
        definition_id=WARPATH_ID,
        definition_version=w.version,
        definition_sha256=w.sha256,
        inputs={
            "exercise_id": str(ex.id),
            "exercise_name": ex.name,
            "plan": ex.plan,
            "plan_sha256": ex.plan_sha256,
        },
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
    ex.state, ex.workflow_run_id = "running", run.id
    db.flush()
    record(
        db,
        "workflow.started",
        entity_type="workflow_run",
        entity_id=run.id,
        data={"project_id": str(ex.project_id), "workflow": WARPATH_ID, "version": w.version},
        **ctx.audit_kwargs(),
    )
    _audit(db, ctx, "warpath.started", ex, workflow_run_id=str(run.id))
    engine.advance(db, run.id, ctx)
    return _detail(db, ex)


@router.post("/warpath/exercises/{exercise_id}/cancel", response_model=WarpathExerciseDetail)
def cancel_exercise(
    exercise_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.PLAYBOOKS_RUN),
) -> WarpathExerciseDetail:
    ex = _exercise(db, ctx, exercise_id)
    _sync(db, ex, ctx)
    if ex.state not in ("approved", "running"):
        raise api_error(409, "not_active", "Only an approved or running exercise can be cancelled.")
    if ex.workflow_run_id is not None:
        run = db.get(WorkflowRun, ex.workflow_run_id)
        if run is not None and run.state is WorkflowRunState.RUNNING:
            now = utcnow()
            engine.end_open_steps(db, run, engine.steps_of(db, run), "Exercise cancelled", now)
            run.state, run.finished_at = WorkflowRunState.CANCELLED, now
            run.cancelled_by_user_id, run.cancel_reason = ctx.user_id, "Exercise cancelled"
    ex.state = "cancelled"
    db.flush()
    _audit(db, ctx, "warpath.cancelled", ex)
    return _detail(db, ex)


@router.post(
    "/warpath/exercises/{exercise_id}/steps/{step}/score", response_model=WarpathExerciseDetail
)
def score_step(
    exercise_id: uuid.UUID,
    step: int,
    body: WarpathScoreIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> WarpathExerciseDetail:
    ex = _exercise(db, ctx, exercise_id)
    _sync(db, ex, ctx)
    if not 1 <= step <= len(ex.plan):
        raise not_found("Step not found.")
    if ex.state not in ("running", "finished"):
        raise api_error(409, "not_running", "Start the exercise before scoring it.")
    review = None
    if ex.workflow_run_id is not None:
        review = db.scalar(
            select(WorkflowStep).where(
                WorkflowStep.run_id == ex.workflow_run_id, WorkflowStep.key == f"s{step}_score"
            )
        )
    has_score = db.scalar(
        select(WarpathScore.id).where(WarpathScore.exercise_id == ex.id, WarpathScore.step == step)
    )
    waiting = review is not None and review.state is WorkflowStepState.RUNNING
    if not waiting and has_score is None:
        raise api_error(409, "not_ready", "Score a step once its attack step has run.")
    now = utcnow()
    tid = ex.plan[step - 1]["technique_id"]
    db.add(
        WarpathScore(
            workspace_id=ctx.workspace_id,
            exercise_id=ex.id,
            step=step,
            technique_id=tid,
            attack_result=body.attack_result,
            detection=body.detection,
            minutes_to_detect=body.minutes_to_detect,
            note=body.note,
            scored_by_user_id=ctx.user_id,
            scored_at=now,
        )
    )
    if waiting and review is not None:
        review.state, review.finished_at = WorkflowStepState.SUCCEEDED, now
        review.detail = f"Scored: attack {body.attack_result}, detection {body.detection}."
    db.flush()
    _audit(db, ctx, "warpath.scored", ex, step=step, technique=tid, detection=body.detection,
           attack_result=body.attack_result)  # fmt: skip
    if body.detection in ("missed", "partial"):
        _detection_gap(db, ctx, ex, step, tid, body, now)
    if ex.workflow_run_id is not None:
        engine.advance(db, ex.workflow_run_id, ctx)
        _sync(db, ex, ctx)
    return _detail(db, ex)


def _detection_gap(
    db: Session,
    ctx: WorkspaceContext,
    ex: WarpathExercise,
    step: int,
    tid: str,
    body: WarpathScoreIn,
    now: datetime,
) -> None:
    """A SHIELD alert (decision 4); one open alert per exercise step."""
    key = f"detection.gap:{ex.id}:{step}"
    if db.scalar(
        select(Alert.id).where(
            Alert.workspace_id == ex.workspace_id,
            Alert.dedupe_key == key,
            Alert.state != "resolved",
        )
    ):
        return
    t = _tech(tid)
    missed = body.detection == "missed"
    alert = Alert(
        workspace_id=ex.workspace_id,
        project_id=ex.project_id,
        kind="detection.gap",
        severity=Severity.MEDIUM if missed else Severity.LOW,
        title=f"{'Missed' if missed else 'Partly detected'}: {tid} {t.name} (WARPATH)",
        detail=f"In exercise {ex.name!r}, step {step} ({ex.plan[step - 1]['playbook_id']} on "
        f"{ex.plan[step - 1]['target']}) was {'not detected' if missed else 'only partly detected'}"
        f". Expected: {ex.plan[step - 1].get('expected_detection') or 'not stated'}. "
        f"{body.note}".strip(),
        target=ex.plan[step - 1]["target"],
        dedupe_key=key,
        rules="warpath/1",
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(alert)
    db.flush()
    record(
        db,
        "alert.raised",
        entity_type="alert",
        entity_id=alert.id,
        data={"project_id": str(ex.project_id), "kind": "detection.gap", "title": alert.title},
        **ctx.audit_kwargs(),
    )
