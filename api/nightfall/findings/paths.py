"""Attack paths and the project intelligence graph.

An attack path is a hypothesis until a person reviews it. It can only be marked validated
if every finding it relies on is itself validated, so a chain of unverified guesses is
never presented as a demonstrated path.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter
from pydantic import Field, StringConstraints
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    Asset,
    AssetRelationship,
    AttackPath,
    AttackPathStatus,
    AttackPathStep,
    Confidence,
    Finding,
    Project,
    Severity,
    User,
    ValidationStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.findings.routes import ref

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["attack-paths"])
GRAPH_LIMIT = 400


class StepIn(Model):
    asset_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    description: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)
    ]


class PathIn(Model):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
    narrative: Annotated[str, StringConstraints(strip_whitespace=True, max_length=20000)] = ""
    confidence: Confidence = Confidence.LOW
    steps: Annotated[list[StepIn], Field(min_length=2, max_length=50)]


class ReviewIn(Model):
    status: AttackPathStatus
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class StepOut(Model):
    ordinal: int
    description: str
    asset_id: uuid.UUID | None
    asset_value: str | None
    finding_id: uuid.UUID | None
    finding_ref: str | None
    finding_title: str | None
    finding_status: ValidationStatus | None
    finding_severity: Severity | None


class PathOut(Model):
    id: uuid.UUID
    project_id: uuid.UUID
    title: str
    narrative: str
    status: AttackPathStatus
    confidence: Confidence
    created_by: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_note: str
    proposed_by_task_id: uuid.UUID | None
    created_at: datetime
    steps: list[StepOut]


def _project(db: Session, ctx: WorkspaceContext, project_id: uuid.UUID) -> Project:
    p = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if p is None:
        raise not_found("Project not found.")
    return p


def _path_out(db: Session, p: AttackPath) -> PathOut:
    rows = db.execute(
        select(AttackPathStep, Asset.value, Finding)
        .outerjoin(Asset, Asset.id == AttackPathStep.asset_id)
        .outerjoin(Finding, Finding.id == AttackPathStep.finding_id)
        .where(AttackPathStep.attack_path_id == p.id)
        .order_by(AttackPathStep.ordinal)
    ).all()
    ids = [i for i in (p.created_by_user_id, p.reviewed_by_user_id) if i]
    names = (
        dict(db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).tuples().all())
        if ids
        else {}
    )
    return PathOut(
        id=p.id,
        project_id=p.project_id,
        title=p.title,
        narrative=p.narrative,
        status=p.status,
        confidence=p.confidence,
        created_by=names.get(p.created_by_user_id) if p.created_by_user_id else None,
        reviewed_by=names.get(p.reviewed_by_user_id) if p.reviewed_by_user_id else None,
        reviewed_at=p.reviewed_at,
        review_note=p.review_note,
        proposed_by_task_id=p.proposed_by_task_id,
        created_at=p.created_at,
        steps=[
            StepOut(
                ordinal=s.ordinal,
                description=s.description,
                asset_id=s.asset_id,
                asset_value=av,
                finding_id=s.finding_id,
                finding_ref=ref(f.number) if f else None,
                finding_title=f.title if f else None,
                finding_status=f.validation_status if f else None,
                finding_severity=f.severity if f else None,
            )
            for s, av, f in rows
        ],
    )


def _write_steps(
    db: Session, ctx: WorkspaceContext, project: Project, path: AttackPath, steps: list[StepIn]
) -> None:
    for i, s in enumerate(steps, start=1):
        if s.asset_id is None and s.finding_id is None:
            raise api_error(422, "empty_step", f"Step {i} needs an asset or a finding.")
        if s.asset_id is not None:
            a = db.scalar(
                select(Asset).where(Asset.id == s.asset_id, Asset.workspace_id == ctx.workspace_id)
            )
            if a is None or a.organization_id != project.organization_id:
                raise api_error(
                    422, "step_asset", f"Step {i}: asset isn't in this project's organization."
                )
        if s.finding_id is not None:
            f = db.scalar(
                select(Finding).where(
                    Finding.id == s.finding_id, Finding.workspace_id == ctx.workspace_id
                )
            )
            if f is None or f.project_id != project.id:
                raise api_error(422, "step_finding", f"Step {i}: finding isn't in this project.")
        db.add(
            AttackPathStep(
                workspace_id=ctx.workspace_id,
                attack_path_id=path.id,
                ordinal=i,
                asset_id=s.asset_id,
                finding_id=s.finding_id,
                description=s.description,
            )
        )
    db.flush()


@router.get("/projects/{project_id}/attack-paths", response_model=list[PathOut])
def list_paths(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[PathOut]:
    _project(db, ctx, project_id)
    paths = db.scalars(
        select(AttackPath)
        .where(AttackPath.project_id == project_id)
        .order_by(AttackPath.created_at.desc())
    ).all()
    return [_path_out(db, p) for p in paths]


@router.post("/projects/{project_id}/attack-paths", response_model=PathOut, status_code=201)
def create_path(
    project_id: uuid.UUID,
    body: PathIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> PathOut:
    project = _project(db, ctx, project_id)
    p = AttackPath(
        workspace_id=ctx.workspace_id,
        project_id=project.id,
        title=body.title,
        narrative=body.narrative,
        confidence=body.confidence,
        created_by_user_id=ctx.user_id,
    )
    db.add(p)
    db.flush()
    _write_steps(db, ctx, project, p, body.steps)
    db.refresh(p)
    record(
        db,
        "attack_path.created",
        entity_type="attack_path",
        entity_id=p.id,
        data={"title": p.title, "steps": len(body.steps)},
        **ctx.audit_kwargs(),
    )
    return _path_out(db, p)


def _get_path(db: Session, ctx: WorkspaceContext, path_id: uuid.UUID) -> AttackPath:
    p = db.scalar(
        select(AttackPath)
        .where(AttackPath.id == path_id, AttackPath.workspace_id == ctx.workspace_id)
        .with_for_update()
    )
    if p is None:
        raise not_found("Attack path not found.")
    return p


@router.get("/attack-paths/{path_id}", response_model=PathOut)
def get_path(
    path_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> PathOut:
    return _path_out(db, _get_path(db, ctx, path_id))


@router.put("/attack-paths/{path_id}", response_model=PathOut)
def replace_path(
    path_id: uuid.UUID,
    body: PathIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> PathOut:
    p = _get_path(db, ctx, path_id)
    if p.status is not AttackPathStatus.HYPOTHESIS:
        raise api_error(409, "reviewed", "Reviewed paths can't be edited. Reopen it first.")
    project = _project(db, ctx, p.project_id)
    p.title, p.narrative, p.confidence = body.title, body.narrative, body.confidence
    for s in db.scalars(select(AttackPathStep).where(AttackPathStep.attack_path_id == p.id)):
        db.delete(s)
    db.flush()
    _write_steps(db, ctx, project, p, body.steps)
    record(
        db,
        "attack_path.updated",
        entity_type="attack_path",
        entity_id=p.id,
        data={"steps": len(body.steps)},
        **ctx.audit_kwargs(),
    )
    return _path_out(db, p)


@router.post("/attack-paths/{path_id}/review", response_model=PathOut)
def review_path(
    path_id: uuid.UUID,
    body: ReviewIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> PathOut:
    p = _get_path(db, ctx, path_id)
    if body.status is AttackPathStatus.VALIDATED:
        statuses = db.scalars(
            select(Finding.validation_status)
            .join(AttackPathStep, AttackPathStep.finding_id == Finding.id)
            .where(AttackPathStep.attack_path_id == p.id)
        ).all()
        if not statuses:
            raise api_error(
                422,
                "no_findings",
                "A path can only be validated when it rests on validated findings.",
            )
        if any(s is not ValidationStatus.VALIDATED for s in statuses):
            raise api_error(
                422, "unvalidated_findings", "Every finding in the path must be validated first."
            )
    if body.status is not AttackPathStatus.HYPOTHESIS and not body.note:
        raise api_error(422, "note_required", "Say why: the note is kept with the review.")
    before = p.status
    p.status = body.status
    p.review_note = body.note
    if body.status is AttackPathStatus.HYPOTHESIS:
        p.reviewed_by_user_id, p.reviewed_at = None, None
    else:
        p.reviewed_by_user_id, p.reviewed_at = ctx.user_id, utcnow()
    db.flush()
    record(
        db,
        "attack_path.reviewed",
        entity_type="attack_path",
        entity_id=p.id,
        data={"from": before.value, "to": body.status.value, "note": body.note},
        **ctx.audit_kwargs(),
    )
    return _path_out(db, p)


# --- Graph ----------------------------------------------------------------------


class GNode(Model):
    id: str
    kind: Literal["asset", "finding"]
    label: str
    record_id: uuid.UUID
    asset_kind: str | None = None
    severity: Severity | None = None
    status: ValidationStatus | None = None


class GEdge(Model):
    id: str
    source: str
    target: str
    kind: Literal["subdomain_of", "resolves_to", "cname_to", "affects", "path_step"]
    status: Literal["observed", "hypothesis", "validated", "rejected"]
    evidence_id: uuid.UUID | None = None
    rule_id: str | None = None
    path_id: uuid.UUID | None = None
    path_title: str | None = None


class ProjectGraph(Model):
    nodes: list[GNode]
    edges: list[GEdge]
    truncated: bool


@router.get("/projects/{project_id}/graph", response_model=ProjectGraph)
def project_graph(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> ProjectGraph:
    """Assets of the project's organization, the project's findings, recorded asset
    relationships, finding→asset links and attack-path steps. Every edge says whether it is
    observed (with its evidence and rule) or a hypothesis."""
    project = _project(db, ctx, project_id)
    assets = db.scalars(
        select(Asset)
        .where(
            Asset.organization_id == project.organization_id,
            Asset.kind.in_(
                [
                    "domain",
                    "hostname",
                    "ip_address",
                    "ip_range",
                    "application",
                    "api",
                    "cloud_resource",
                ]
            ),
        )
        .order_by(Asset.kind, Asset.value)
        .limit(GRAPH_LIMIT + 1)
    ).all()
    truncated = len(assets) > GRAPH_LIMIT
    assets = assets[:GRAPH_LIMIT]
    ids = {a.id for a in assets}
    findings = db.scalars(
        select(Finding)
        .where(Finding.project_id == project.id)
        .order_by(Finding.number)
        .limit(GRAPH_LIMIT)
    ).all()
    nodes = [
        GNode(
            id=f"asset:{a.id}", kind="asset", label=a.value, record_id=a.id, asset_kind=a.kind.value
        )
        for a in assets
    ]
    nodes += [
        GNode(
            id=f"finding:{f.id}",
            kind="finding",
            label=f"{ref(f.number)} {f.title}",
            record_id=f.id,
            severity=f.severity,
            status=f.validation_status,
        )
        for f in findings
    ]
    edges: list[GEdge] = []
    rels = db.scalars(
        select(AssetRelationship).where(
            or_(AssetRelationship.from_asset_id.in_(ids), AssetRelationship.to_asset_id.in_(ids))
        )
    ).all()
    for r in rels:
        if r.from_asset_id in ids and r.to_asset_id in ids:
            edges.append(
                GEdge(
                    id=f"rel:{r.id}",
                    source=f"asset:{r.from_asset_id}",
                    target=f"asset:{r.to_asset_id}",
                    kind=r.rel_type.value,
                    status=r.status.value,
                    evidence_id=r.evidence_id,
                    rule_id=r.rule_id,
                )
            )
    for f in findings:
        if f.asset_id in ids:
            hyp = f.validation_status is ValidationStatus.HYPOTHESIS
            edges.append(
                GEdge(
                    id=f"affects:{f.id}",
                    source=f"finding:{f.id}",
                    target=f"asset:{f.asset_id}",
                    kind="affects",
                    status="hypothesis" if hyp else "observed",
                    rule_id=f.rule_id,
                )
            )
    node_ids = {n.id for n in nodes}
    for p in db.scalars(select(AttackPath).where(AttackPath.project_id == project.id)):
        steps = db.scalars(
            select(AttackPathStep)
            .where(AttackPathStep.attack_path_id == p.id)
            .order_by(AttackPathStep.ordinal)
        ).all()
        keys = [f"finding:{s.finding_id}" if s.finding_id else f"asset:{s.asset_id}" for s in steps]
        for i, (a, b) in enumerate(zip(keys, keys[1:], strict=False), start=1):
            if a in node_ids and b in node_ids and a != b:
                edges.append(
                    GEdge(
                        id=f"path:{p.id}:{i}",
                        source=a,
                        target=b,
                        kind="path_step",
                        status=p.status.value,
                        path_id=p.id,
                        path_title=p.title,
                    )
                )
    return ProjectGraph(nodes=nodes, edges=edges, truncated=truncated)
