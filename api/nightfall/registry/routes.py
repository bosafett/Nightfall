"""Target registry, Phase 1 slice: organizations and projects (project = assessment in 0.1)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import StringConstraints
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AssessmentType, Organization, Project, ProjectStatus
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["registry"])

Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
LongText = Annotated[str, StringConstraints(strip_whitespace=True, max_length=10000)]
LIST_LIMIT = 500


class OrganizationIn(Model):
    name: Title
    notes: LongText = ""


class OrganizationPatch(Model):
    name: Title | None = None
    notes: LongText | None = None


class OrganizationOut(Model):
    id: uuid.UUID
    name: str
    notes: str
    project_count: int
    created_at: datetime
    updated_at: datetime


class ProjectIn(Model):
    organization_id: uuid.UUID
    name: Title
    description: LongText = ""
    assessment_type: AssessmentType


class ProjectPatch(Model):
    name: Title | None = None
    description: LongText | None = None
    assessment_type: AssessmentType | None = None
    status: ProjectStatus | None = None


class ProjectOut(Model):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    name: str
    description: str
    assessment_type: AssessmentType
    status: ProjectStatus
    started_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _flush_unique(db: Session, message: str) -> None:
    try:
        db.flush()
    except IntegrityError as exc:
        raise api_error(409, "duplicate", message) from exc


def _org_out(db: Session, org: Organization) -> OrganizationOut:
    count = (
        db.scalar(
            select(func.count()).select_from(Project).where(Project.organization_id == org.id)
        )
        or 0
    )
    return OrganizationOut(
        id=org.id,
        name=org.name,
        notes=org.notes,
        project_count=count,
        created_at=org.created_at,
        updated_at=org.updated_at,
    )


def _get_org(db: Session, ctx: WorkspaceContext, org_id: uuid.UUID) -> Organization:
    org = db.scalar(
        select(Organization).where(
            Organization.id == org_id, Organization.workspace_id == ctx.workspace_id
        )
    )
    if org is None:
        raise not_found("Organization not found.")
    return org


def _project_out(p: Project, org_name: str) -> ProjectOut:
    return ProjectOut(
        id=p.id,
        organization_id=p.organization_id,
        organization_name=org_name,
        name=p.name,
        description=p.description,
        assessment_type=p.assessment_type,
        status=p.status,
        started_at=p.started_at,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


# --- organizations -------------------------------------------------------------


@router.get("/organizations", response_model=list[OrganizationOut])
def list_organizations(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[OrganizationOut]:
    counts = (
        select(Project.organization_id, func.count().label("n"))
        .where(Project.workspace_id == ctx.workspace_id)
        .group_by(Project.organization_id)
        .subquery()
    )
    rows = db.execute(
        select(Organization, func.coalesce(counts.c.n, 0))
        .outerjoin(counts, counts.c.organization_id == Organization.id)
        .where(Organization.workspace_id == ctx.workspace_id)
        .order_by(func.lower(Organization.name))
        .limit(LIST_LIMIT)
    ).all()
    return [
        OrganizationOut(
            id=o.id,
            name=o.name,
            notes=o.notes,
            project_count=n,
            created_at=o.created_at,
            updated_at=o.updated_at,
        )
        for o, n in rows
    ]


@router.post("/organizations", response_model=OrganizationOut, status_code=201)
def create_organization(
    body: OrganizationIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE)
) -> OrganizationOut:
    org = Organization(workspace_id=ctx.workspace_id, name=body.name, notes=body.notes)
    db.add(org)
    _flush_unique(db, "An organization with that name already exists.")
    db.refresh(org)
    record(
        db,
        "organization.created",
        entity_type="organization",
        entity_id=org.id,
        data={"name": org.name},
        **ctx.audit_kwargs(),
    )
    return _org_out(db, org)


@router.get("/organizations/{org_id}", response_model=OrganizationOut)
def get_organization(
    org_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> OrganizationOut:
    return _org_out(db, _get_org(db, ctx, org_id))


@router.patch("/organizations/{org_id}", response_model=OrganizationOut)
def update_organization(
    org_id: uuid.UUID,
    body: OrganizationPatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> OrganizationOut:
    org = _get_org(db, ctx, org_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    for field, value in changes.items():
        setattr(org, field, value)
    _flush_unique(db, "An organization with that name already exists.")
    db.refresh(org)
    record(
        db,
        "organization.updated",
        entity_type="organization",
        entity_id=org.id,
        data={"fields": sorted(changes)},
        **ctx.audit_kwargs(),
    )
    return _org_out(db, org)


# --- projects -------------------------------------------------------------------


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    organization_id: Annotated[uuid.UUID | None, Query()] = None,
) -> list[ProjectOut]:
    q = (
        select(Project, Organization.name)
        .join(Organization, Organization.id == Project.organization_id)
        .where(Project.workspace_id == ctx.workspace_id)
    )
    if organization_id is not None:
        q = q.where(Project.organization_id == organization_id)
    rows = db.execute(q.order_by(Project.updated_at.desc()).limit(LIST_LIMIT)).all()
    return [_project_out(p, name) for p, name in rows]


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(
    body: ProjectIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE)
) -> ProjectOut:
    org = _get_org(db, ctx, body.organization_id)
    p = Project(
        workspace_id=ctx.workspace_id,
        organization_id=org.id,
        name=body.name,
        description=body.description,
        assessment_type=body.assessment_type,
    )
    db.add(p)
    db.flush()
    db.refresh(p)
    record(
        db,
        "project.created",
        entity_type="project",
        entity_id=p.id,
        data={
            "name": p.name,
            "organization_id": str(org.id),
            "assessment_type": p.assessment_type.value,
        },
        **ctx.audit_kwargs(),
    )
    return _project_out(p, org.name)


def _get_project(db: Session, ctx: WorkspaceContext, project_id: uuid.UUID) -> tuple[Project, str]:
    row = db.execute(
        select(Project, Organization.name)
        .join(Organization, Organization.id == Project.organization_id)
        .where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    ).first()
    if row is None:
        raise not_found("Project not found.")
    return row[0], row[1]


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> ProjectOut:
    p, org_name = _get_project(db, ctx, project_id)
    return _project_out(p, org_name)


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: uuid.UUID,
    body: ProjectPatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> ProjectOut:
    p, org_name = _get_project(db, ctx, project_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    data: dict[str, object] = {"fields": sorted(changes)}
    if "status" in changes and changes["status"] != p.status:
        data["status"] = {"from": p.status.value, "to": changes["status"].value}
        if changes["status"] is ProjectStatus.ACTIVE and p.started_at is None:
            p.started_at = utcnow()
    for field, value in changes.items():
        setattr(p, field, value)
    db.flush()
    db.refresh(p)
    record(
        db,
        "project.updated",
        entity_type="project",
        entity_id=p.id,
        data=data,
        **ctx.audit_kwargs(),
    )
    return _project_out(p, org_name)
