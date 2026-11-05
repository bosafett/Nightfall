"""Agent runs: start, list, inspect, cancel. Starting a run needs the same permission as
requesting a collection; what the agent proposes is still checked by the gateway, and
anything above passive still needs someone other than the requester to approve it."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Response
from pydantic import StringConstraints
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError

from nightfall.agents.registry import AGENTS
from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AgentTask, AgentTaskStatus, Asset, Project, Role, User
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["agents"])

HOURLY_LIMIT = 30  # agent runs per workspace per hour
OPEN = (AgentTaskStatus.QUEUED, AgentTaskStatus.RUNNING)


USAGE_DAYS = 30
RunnableAgent = Literal["director", "scout", "investigator", "hunter", "adversary", "analyst"]


class AgentUsage(Model):
    """Counted from agent_tasks for this workspace over the last USAGE_DAYS days."""

    runs: int
    succeeded: int
    failed: int
    input_tokens: int
    output_tokens: int


class AgentOut(Model):
    key: str
    label: str
    role: str
    status: Literal["available", "automatic"]
    usage: AgentUsage


class AgentsOut(Model):
    ai_enabled: bool
    model: str | None
    usage_days: int
    agents: list[AgentOut]


class RunIn(Model):
    agent: RunnableAgent
    objective: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = ""
    asset_id: uuid.UUID | None = None  # Investigator: the asset to explain


class TaskOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    agent: str
    agent_label: str
    objective: str
    status: AgentTaskStatus
    parent_task_id: uuid.UUID | None
    subject_finding_id: uuid.UUID | None
    subject_asset_id: uuid.UUID | None
    subject_asset: str | None
    requested_by: str | None
    error: str | None
    model: str | None
    prompt_version: str | None
    input_tokens: int | None
    output_tokens: int | None
    latency_ms: int | None
    queued_at: datetime
    finished_at: datetime | None


class TaskDetail(TaskOut):
    result: dict[str, Any]
    children: list[TaskOut]


@router.get("/agents", response_model=AgentsOut)
def list_agents(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> AgentsOut:
    s = get_settings()
    enabled = s.ai_provider != "none"
    since = utcnow() - timedelta(days=USAGE_DAYS)
    rows = db.execute(
        select(
            AgentTask.agent,
            func.count(),
            func.count(case((AgentTask.status == AgentTaskStatus.SUCCEEDED, 1))),
            func.count(case((AgentTask.status == AgentTaskStatus.FAILED, 1))),
            func.coalesce(func.sum(AgentTask.input_tokens), 0),
            func.coalesce(func.sum(AgentTask.output_tokens), 0),
        )
        .where(AgentTask.workspace_id == ctx.workspace_id, AgentTask.created_at >= since)
        .group_by(AgentTask.agent)
    ).all()
    usage = {
        r[0]: AgentUsage(
            runs=r[1],
            succeeded=r[2],
            failed=r[3],
            input_tokens=int(r[4] or 0),
            output_tokens=int(r[5] or 0),
        )
        for r in rows
    }
    empty = AgentUsage(runs=0, succeeded=0, failed=0, input_tokens=0, output_tokens=0)
    return AgentsOut(
        ai_enabled=enabled,
        model=s.ai_model if enabled else None,
        usage_days=USAGE_DAYS,
        agents=[
            AgentOut(
                key=a.key,
                label=a.label,
                role=a.role,
                status="available" if a.user_runnable else "automatic",
                usage=usage.get(a.key, empty),
            )
            for a in AGENTS.values()
        ],
    )


def _out(
    task: AgentTask, names: dict[uuid.UUID, str], assets: dict[uuid.UUID, str] | None = None
) -> TaskOut:
    spec = AGENTS.get(task.agent)
    return TaskOut(
        id=task.id,
        project_id=task.project_id,
        agent=task.agent,
        agent_label=spec.label if spec else task.agent.capitalize(),
        objective=task.objective,
        status=task.status,
        parent_task_id=task.parent_task_id,
        subject_finding_id=task.subject_finding_id,
        subject_asset_id=task.subject_asset_id,
        subject_asset=(assets or {}).get(task.subject_asset_id) if task.subject_asset_id else None,
        requested_by=names.get(task.requested_by_user_id) if task.requested_by_user_id else None,
        error=task.error,
        model=task.model,
        prompt_version=task.prompt_version,
        input_tokens=task.input_tokens,
        output_tokens=task.output_tokens,
        latency_ms=task.latency_ms,
        queued_at=task.queued_at,
        finished_at=task.finished_at,
    )


def _assets(db: DB, tasks: list[AgentTask]) -> dict[uuid.UUID, str]:
    ids = {t.subject_asset_id for t in tasks if t.subject_asset_id}
    if not ids:
        return {}
    return dict(db.execute(select(Asset.id, Asset.value).where(Asset.id.in_(ids))).tuples().all())


def _outs(db: DB, tasks: list[AgentTask]) -> list[TaskOut]:
    names, assets = _names(db, tasks), _assets(db, tasks)
    return [_out(t, names, assets) for t in tasks]


def _names(db: DB, tasks: list[AgentTask]) -> dict[uuid.UUID, str]:
    ids = {t.requested_by_user_id for t in tasks if t.requested_by_user_id}
    if not ids:
        return {}
    rows = db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).all()
    return {i: n for i, n in rows}


@router.post("/projects/{project_id}/agent-runs", response_model=TaskOut, status_code=202)
def start_run(
    project_id: uuid.UUID,
    body: RunIn,
    response: Response,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE),
) -> TaskOut:
    if get_settings().ai_provider == "none":
        raise api_error(409, "ai_off", "AI is turned off on this deployment.")
    project = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if project is None:
        raise not_found("Project not found.")
    asset_id = None
    if body.agent == "investigator":
        if body.asset_id is None:
            raise api_error(422, "asset_required", "Choose the asset to explain.")
        asset = db.scalar(
            select(Asset).where(Asset.id == body.asset_id, Asset.workspace_id == ctx.workspace_id)
        )
        if asset is None or asset.organization_id != project.organization_id:
            raise api_error(422, "asset", "That asset isn't in this project's organization.")
        asset_id = asset.id
    elif body.asset_id is not None:
        raise api_error(422, "asset_unexpected", "Only the Investigator takes an asset.")
    if body.agent == "director" and not body.objective:
        raise api_error(422, "objective_required", "Give the Director an objective.")
    existing = db.scalar(
        select(AgentTask).where(
            AgentTask.project_id == project_id,
            AgentTask.agent == body.agent,
            AgentTask.status.in_(OPEN),
            AgentTask.subject_finding_id.is_(None),
            AgentTask.subject_asset_id == asset_id
            if asset_id is not None
            else AgentTask.subject_asset_id.is_(None),
        )
    )
    if existing is not None:
        response.status_code = 200
        return _outs(db, [existing])[0]
    recent = (
        db.scalar(
            select(func.count())
            .select_from(AgentTask)
            .where(
                AgentTask.workspace_id == ctx.workspace_id,
                AgentTask.created_at >= utcnow() - timedelta(hours=1),
            )
        )
        or 0
    )
    if recent >= HOURLY_LIMIT:
        raise api_error(429, "rate_limited", f"Agents are limited to {HOURLY_LIMIT} runs per hour.")
    spec = AGENTS[body.agent]
    task = AgentTask(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        agent=body.agent,
        objective=body.objective or spec.role,
        subject_asset_id=asset_id,
        requested_by_user_id=ctx.user_id,
    )
    db.add(task)
    try:
        db.flush()
    except IntegrityError as exc:  # raced with another request for the same run
        raise api_error(409, "conflict", "This agent is already running for the project.") from exc
    record(
        db,
        "agent_task.requested",
        entity_type="agent_task",
        entity_id=task.id,
        data={
            "agent": body.agent,
            "project_id": str(project_id),
            **({"asset_id": str(asset_id)} if asset_id else {}),
        },
        **ctx.audit_kwargs(),
    )
    if get_settings().on_demand_worker:
        from nightfall.serverless import drain

        background.add_task(drain)
    return _outs(db, [task])[0]


@router.get("/projects/{project_id}/agent-tasks", response_model=list[TaskOut])
def list_tasks(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[TaskOut]:
    tasks = list(
        db.scalars(
            select(AgentTask)
            .where(AgentTask.project_id == project_id)
            .order_by(AgentTask.created_at.desc())
            .limit(50)
        )
    )
    return _outs(db, tasks)


@router.get("/agent-tasks", response_model=list[TaskOut])
def list_workspace_tasks(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[TaskOut]:
    tasks = list(
        db.scalars(
            select(AgentTask)
            .where(AgentTask.workspace_id == ctx.workspace_id)
            .order_by(AgentTask.created_at.desc())
            .limit(50)
        )
    )
    return _outs(db, tasks)


def _task(db: DB, task_id: uuid.UUID) -> AgentTask:
    task = db.get(AgentTask, task_id)
    if task is None:
        raise not_found("Agent task not found.")
    return task


@router.get("/agent-tasks/{task_id}", response_model=TaskDetail)
def get_task(
    task_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> TaskDetail:
    task = _task(db, task_id)
    children = list(
        db.scalars(
            select(AgentTask)
            .where(AgentTask.parent_task_id == task.id)
            .order_by(AgentTask.created_at)
        )
    )
    outs = _outs(db, [task, *children])
    return TaskDetail(**outs[0].model_dump(), result=task.result, children=outs[1:])


@router.post("/agent-tasks/{task_id}/cancel", response_model=TaskOut)
def cancel_task(
    task_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE),
) -> TaskOut:
    task = _task(db, task_id)
    if task.requested_by_user_id != ctx.user_id and ctx.member.role not in (Role.OWNER, Role.ADMIN):
        raise api_error(403, "forbidden", "Only the requester or an admin can cancel this.")
    if task.status not in OPEN:
        raise api_error(409, "conflict", "This task has already finished.")
    task.status = AgentTaskStatus.CANCELLED
    task.finished_at = utcnow()
    record(
        db,
        "agent_task.cancelled",
        entity_type="agent_task",
        entity_id=task.id,
        data={"agent": task.agent},
        **ctx.audit_kwargs(),
    )
    db.flush()
    return _outs(db, [task])[0]
