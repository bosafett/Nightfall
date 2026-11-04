"""Command Center overview (Phase 2).

Every number is computed from stored records. Modules whose tables don't exist yet
(assets, operations, findings, agents) are reported as unavailable with the phase that
adds them — never as zero, and never with sample data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    AssessmentType,
    Asset,
    Operation,
    OperationStatus,
    Organization,
    Project,
    ProjectStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["overview"])

GRAPH_NODE_LIMIT = 300
ASSESSMENT_LIMIT = 6
OPEN_STATUSES = (ProjectStatus.PLANNING, ProjectStatus.ACTIVE, ProjectStatus.PAUSED)


class Window(StrEnum):
    HOUR = "1h"
    DAY = "24h"
    WEEK = "7d"
    MONTH = "30d"


WINDOW_LENGTH = {
    Window.HOUR: timedelta(hours=1),
    Window.DAY: timedelta(days=1),
    Window.WEEK: timedelta(days=7),
    Window.MONTH: timedelta(days=30),
}


class Unavailable(Model):
    available: Literal[False] = False
    phase: int


class ProjectKpi(Model):
    available: Literal[True] = True
    active: int
    open: int  # planning + active + paused
    started_in_window: int


class AssetKpi(Model):
    available: Literal[True] = True
    total: int
    new_in_window: int


class OperationKpi(Model):
    available: Literal[True] = True
    in_window: int
    pending: int  # queued or running now
    awaiting_approval: int
    failed_in_window: int


class AssessmentItem(Model):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    name: str
    assessment_type: AssessmentType
    status: ProjectStatus
    started_at: datetime | None
    last_activity_at: datetime


class GraphNode(Model):
    id: str
    kind: Literal["organization", "project"]
    label: str
    record_id: uuid.UUID
    status: ProjectStatus | None = None


class GraphEdge(Model):
    id: str
    source: str
    target: str
    kind: Literal["has_project"]
    # "observed" = recorded fact; "hypothesis" arrives with findings/attack paths (phase 4).
    status: Literal["observed", "hypothesis"]


class Graph(Model):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool


class OverviewOut(Model):
    window: Window
    generated_at: datetime
    projects: ProjectKpi
    critical_findings: Unavailable
    assets: AssetKpi
    operations: OperationKpi
    assessments: list[AssessmentItem]
    recent_findings: Unavailable
    agent_activity: Unavailable
    risk: Unavailable
    graph: Graph


@router.get("/overview", response_model=OverviewOut)
def overview(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    window: Window = Query(Window.DAY),
) -> OverviewOut:
    now = utcnow()
    since = now - WINDOW_LENGTH[window]
    ws = ctx.workspace_id

    counts = db.execute(
        select(
            func.count().filter(Project.status == ProjectStatus.ACTIVE),
            func.count().filter(Project.status.in_(OPEN_STATUSES)),
            func.count().filter(Project.started_at >= since),
        ).where(Project.workspace_id == ws)
    ).one()

    asset_counts = db.execute(
        select(func.count(), func.count().filter(Asset.created_at >= since)).where(
            Asset.workspace_id == ws
        )
    ).one()
    op_counts = db.execute(
        select(
            func.count().filter(Operation.queued_at >= since),
            func.count().filter(
                Operation.status.in_([OperationStatus.QUEUED, OperationStatus.RUNNING])
            ),
            func.count().filter(
                Operation.queued_at >= since, Operation.status == OperationStatus.FAILED
            ),
            func.count().filter(Operation.status == OperationStatus.AWAITING_APPROVAL),
        ).where(Operation.workspace_id == ws)
    ).one()

    rows = db.execute(
        select(Project, Organization.name)
        .join(Organization, Organization.id == Project.organization_id)
        .where(Project.workspace_id == ws, Project.status.in_(OPEN_STATUSES))
        .order_by(Project.updated_at.desc())
        .limit(ASSESSMENT_LIMIT)
    ).all()
    assessments = [
        AssessmentItem(
            id=p.id,
            organization_id=p.organization_id,
            organization_name=org_name,
            name=p.name,
            assessment_type=p.assessment_type,
            status=p.status,
            started_at=p.started_at,
            last_activity_at=p.updated_at,
        )
        for p, org_name in rows
    ]

    return OverviewOut(
        window=window,
        generated_at=now,
        projects=ProjectKpi(active=counts[0], open=counts[1], started_in_window=counts[2]),
        critical_findings=Unavailable(phase=4),
        assets=AssetKpi(total=asset_counts[0], new_in_window=asset_counts[1]),
        operations=OperationKpi(
            in_window=op_counts[0],
            pending=op_counts[1],
            failed_in_window=op_counts[2],
            awaiting_approval=op_counts[3],
        ),
        assessments=assessments,
        recent_findings=Unavailable(phase=4),
        agent_activity=Unavailable(phase=5),
        risk=Unavailable(phase=4),
        graph=_graph(db, ws),
    )


def _graph(db: DB, ws: uuid.UUID) -> Graph:
    orgs = db.execute(
        select(Organization.id, Organization.name)
        .where(Organization.workspace_id == ws)
        .order_by(func.lower(Organization.name))
        .limit(GRAPH_NODE_LIMIT + 1)
    ).all()
    projects = db.execute(
        select(Project.id, Project.organization_id, Project.name, Project.status)
        .where(Project.workspace_id == ws, Project.status != ProjectStatus.ARCHIVED)
        .order_by(Project.organization_id, func.lower(Project.name))
        .limit(GRAPH_NODE_LIMIT + 1)
    ).all()

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    shown: set[uuid.UUID] = set()
    for org_id, name in orgs:
        if len(nodes) >= GRAPH_NODE_LIMIT:
            break
        nodes.append(
            GraphNode(id=f"org:{org_id}", kind="organization", label=name, record_id=org_id)
        )
        shown.add(org_id)
    for pid, org_id, name, status in projects:
        if len(nodes) >= GRAPH_NODE_LIMIT:
            break
        if org_id not in shown:
            continue
        nodes.append(
            GraphNode(id=f"project:{pid}", kind="project", label=name, record_id=pid, status=status)
        )
        edges.append(
            GraphEdge(
                id=f"has_project:{pid}",
                source=f"org:{org_id}",
                target=f"project:{pid}",
                kind="has_project",
                status="observed",
            )
        )
    truncated = len(orgs) > GRAPH_NODE_LIMIT or len(nodes) < len(orgs) + len(projects)
    return Graph(nodes=nodes, edges=edges, truncated=truncated)
