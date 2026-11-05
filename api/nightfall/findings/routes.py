"""Findings: list/filter, create, edit, human status decisions, evidence links.

Status rules (also enforced by the database):
  * hypothesis / unverified: anyone who can edit findings may set them;
  * validated / false_positive / remediated: a human decision, recorded with who, when and
    a required note. Nothing automated can produce these states.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import StringConstraints
from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    HUMAN_STATUSES,
    Asset,
    AttackPath,
    AttackPathStep,
    Confidence,
    Evidence,
    Finding,
    FindingEvidence,
    FindingOrigin,
    Organization,
    Project,
    Severity,
    User,
    ValidationStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model, OkOut
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.registry.assets import EvidenceSummary, evidence_summary

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["findings"])

Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
Long = Annotated[str, StringConstraints(strip_whitespace=True, max_length=10000)]
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)]
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
LIST_LIMIT = 1000


class Sort(StrEnum):
    SEVERITY = "severity"
    DISCOVERED = "discovered"
    LAST_SEEN = "last_seen"


class FindingIn(Model):
    project_id: uuid.UUID
    asset_id: uuid.UUID | None = None
    title: Title
    description: Annotated[str, StringConstraints(strip_whitespace=True, max_length=20000)] = ""
    severity: Severity
    confidence: Confidence
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    discovery_source: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)] = (
        "Manual entry"
    )
    impact: Long = ""
    remediation: Long = ""


class FindingPatch(Model):
    title: Title | None = None
    description: (
        Annotated[str, StringConstraints(strip_whitespace=True, max_length=20000)] | None
    ) = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    impact: Long | None = None
    remediation: Long | None = None


class StatusIn(Model):
    status: ValidationStatus
    note: Note = ""


class LinkIn(Model):
    evidence_id: uuid.UUID
    note: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)] = ""


class FindingOut(Model):
    id: uuid.UUID
    number: int
    ref: str
    project_id: uuid.UUID
    project_name: str
    organization_id: uuid.UUID
    organization_name: str
    asset_id: uuid.UUID | None
    asset_value: str | None
    title: str
    severity: Severity
    confidence: Confidence
    validation_status: ValidationStatus
    origin: FindingOrigin
    first_observed_at: datetime
    last_observed_at: datetime
    evidence_count: int


class LinkedEvidence(EvidenceSummary):
    linked_by: str
    note: str


class PathRef(Model):
    id: uuid.UUID
    title: str
    status: str


class FindingDetail(FindingOut):
    description: str
    impact: str
    remediation: str
    discovery_source: str
    check_id: str | None
    rule_id: str | None
    validated_by: str | None
    validated_at: datetime | None
    status_note: str
    created_by: str | None
    evidence: list[LinkedEvidence]
    attack_paths: list[PathRef]


def ref(number: int) -> str:
    return f"NF-{number:04d}"


def _base() -> Select[Any]:
    ev_count = (
        select(func.count())
        .select_from(FindingEvidence)
        .where(FindingEvidence.finding_id == Finding.id)
        .correlate(Finding)
        .scalar_subquery()
    )
    return (
        select(Finding, Project.name, Organization.id, Organization.name, Asset.value, ev_count)
        .join(Project, Project.id == Finding.project_id)
        .join(Organization, Organization.id == Project.organization_id)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
    )


def _out(row: Any) -> FindingOut:
    f, pname, oid, oname, avalue, n = row
    return FindingOut(
        id=f.id,
        number=f.number,
        ref=ref(f.number),
        project_id=f.project_id,
        project_name=pname,
        organization_id=oid,
        organization_name=oname,
        asset_id=f.asset_id,
        asset_value=avalue,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        validation_status=f.validation_status,
        origin=f.origin,
        first_observed_at=f.first_observed_at,
        last_observed_at=f.last_observed_at,
        evidence_count=n or 0,
    )


def _row(db: Session, ctx: WorkspaceContext, finding_id: uuid.UUID) -> Any:
    row = db.execute(
        _base().where(Finding.id == finding_id, Finding.workspace_id == ctx.workspace_id)
    ).first()
    if row is None:
        raise not_found("Finding not found.")
    return row


def _names(db: Session, ids: list[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = [i for i in ids if i]
    if not wanted:
        return {}
    return dict(
        db.execute(select(User.id, User.display_name).where(User.id.in_(wanted))).tuples().all()
    )


def _project_asset_check(
    db: Session, ctx: WorkspaceContext, project_id: uuid.UUID, asset_id: uuid.UUID | None
) -> None:
    project = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if project is None:
        raise not_found("Project not found.")
    if asset_id is not None:
        asset = db.scalar(
            select(Asset).where(Asset.id == asset_id, Asset.workspace_id == ctx.workspace_id)
        )
        if asset is None:
            raise not_found("Asset not found.")
        if asset.organization_id != project.organization_id:
            raise api_error(
                422,
                "asset_mismatch",
                "That asset belongs to a different organization than the project.",
            )


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    project_id: Annotated[uuid.UUID | None, Query()] = None,
    organization_id: Annotated[uuid.UUID | None, Query()] = None,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    status: Annotated[list[ValidationStatus] | None, Query()] = None,
    sort: Sort = Sort.SEVERITY,
    descending: bool = True,
) -> list[FindingOut]:
    q = _base().where(Finding.workspace_id == ctx.workspace_id)
    if project_id:
        q = q.where(Finding.project_id == project_id)
    if organization_id:
        q = q.where(Organization.id == organization_id)
    if asset_id:
        q = q.where(Finding.asset_id == asset_id)
    if severity:
        q = q.where(Finding.severity.in_(severity))
    if status:
        q = q.where(Finding.validation_status.in_(status))
    rank = case(SEVERITY_RANK, value=Finding.severity)
    if sort is Sort.SEVERITY:
        q = q.order_by(rank if descending else rank.desc(), Finding.last_observed_at.desc())
    elif sort is Sort.DISCOVERED:
        col = Finding.first_observed_at
        q = q.order_by(col.desc() if descending else col.asc())
    else:
        col = Finding.last_observed_at
        q = q.order_by(col.desc() if descending else col.asc())
    return [_out(r) for r in db.execute(q.limit(LIST_LIMIT))]


@router.post("/findings", response_model=FindingDetail, status_code=201)
def create_finding(
    body: FindingIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT)
) -> FindingDetail:
    if body.validation_status in HUMAN_STATUSES:
        raise api_error(
            422,
            "status_requires_decision",
            "Record the finding first, then validate it with a note.",
        )
    _project_asset_check(db, ctx, body.project_id, body.asset_id)
    f = Finding(
        workspace_id=ctx.workspace_id,
        project_id=body.project_id,
        asset_id=body.asset_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        confidence=body.confidence,
        validation_status=body.validation_status,
        origin=FindingOrigin.HUMAN,
        discovery_source=body.discovery_source,
        impact=body.impact,
        remediation=body.remediation,
        created_by_user_id=ctx.user_id,
    )
    db.add(f)
    db.flush()
    db.refresh(f)
    record(
        db,
        "finding.created",
        entity_type="finding",
        entity_id=f.id,
        data={
            "ref": ref(f.number),
            "severity": f.severity.value,
            "status": f.validation_status.value,
        },
        **ctx.audit_kwargs(),
    )
    return get_finding(f.id, db, ctx)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> FindingDetail:
    row = _row(db, ctx, finding_id)
    f: Finding = row[0]
    links = db.execute(
        select(Evidence, FindingEvidence.linked_by, FindingEvidence.note)
        .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
        .where(FindingEvidence.finding_id == f.id)
        .order_by(Evidence.collected_at.desc())
    ).all()
    paths = db.execute(
        select(AttackPath.id, AttackPath.title, AttackPath.status)
        .distinct()
        .join(AttackPathStep, AttackPathStep.attack_path_id == AttackPath.id)
        .where(AttackPathStep.finding_id == f.id)
    ).all()
    names = _names(db, [f.validated_by_user_id, f.created_by_user_id])
    return FindingDetail(
        **_out(row).model_dump(),
        description=f.description,
        impact=f.impact,
        remediation=f.remediation,
        discovery_source=f.discovery_source,
        check_id=f.check_id,
        rule_id=f.rule_id,
        validated_by=names.get(f.validated_by_user_id) if f.validated_by_user_id else None,
        validated_at=f.validated_at,
        status_note=f.status_note,
        created_by=names.get(f.created_by_user_id) if f.created_by_user_id else None,
        evidence=[
            LinkedEvidence(**evidence_summary(e).model_dump(), linked_by=lb, note=n)
            for e, lb, n in links
        ],
        attack_paths=[PathRef(id=i, title=t, status=s.value) for i, t, s in paths],
    )


def _finding(db: Session, ctx: WorkspaceContext, finding_id: uuid.UUID) -> Finding:
    f = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id, Finding.workspace_id == ctx.workspace_id)
        .with_for_update()
    )
    if f is None:
        raise not_found("Finding not found.")
    return f


@router.patch("/findings/{finding_id}", response_model=FindingDetail)
def update_finding(
    finding_id: uuid.UUID,
    body: FindingPatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> FindingDetail:
    f = _finding(db, ctx, finding_id)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    before = {k: getattr(f, k) for k in changes}
    for k, v in changes.items():
        setattr(f, k, v)
    db.flush()
    record(
        db,
        "finding.updated",
        entity_type="finding",
        entity_id=f.id,
        data={
            "fields": sorted(changes),
            **(
                {"severity": {"from": before["severity"].value, "to": f.severity.value}}
                if "severity" in changes
                else {}
            ),
        },
        **ctx.audit_kwargs(),
    )
    return get_finding(f.id, db, ctx)


@router.post("/findings/{finding_id}/status", response_model=FindingDetail)
def set_status(
    finding_id: uuid.UUID,
    body: StatusIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_VALIDATE),
) -> FindingDetail:
    f = _finding(db, ctx, finding_id)
    if body.status in HUMAN_STATUSES and not body.note:
        raise api_error(
            422,
            "note_required",
            "Say why: the note is kept with the decision and shown in reports.",
        )
    if body.status is ValidationStatus.VALIDATED:
        has_evidence = db.scalar(
            select(func.count())
            .select_from(FindingEvidence)
            .where(FindingEvidence.finding_id == f.id)
        )
        if not has_evidence:
            raise api_error(
                422, "evidence_required", "Link at least one piece of evidence before validating."
            )
    before = f.validation_status
    f.validation_status = body.status
    f.status_note = body.note
    if body.status in HUMAN_STATUSES:
        f.validated_by_user_id = ctx.user_id
        f.validated_at = utcnow()
    else:
        f.validated_by_user_id = None
        f.validated_at = None
    db.flush()
    record(
        db,
        "finding.status_changed",
        entity_type="finding",
        entity_id=f.id,
        data={"from": before.value, "to": body.status.value, "note": body.note},
        **ctx.audit_kwargs(),
    )
    return get_finding(f.id, db, ctx)


@router.post("/findings/{finding_id}/evidence", response_model=FindingDetail)
def link_evidence(
    finding_id: uuid.UUID,
    body: LinkIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> FindingDetail:
    f = _finding(db, ctx, finding_id)
    e = db.scalar(
        select(Evidence).where(
            Evidence.id == body.evidence_id, Evidence.workspace_id == ctx.workspace_id
        )
    )
    if e is None:
        raise not_found("Evidence not found.")
    if e.project_id != f.project_id:
        raise api_error(422, "evidence_mismatch", "That evidence belongs to another project.")
    if db.get(FindingEvidence, (f.id, e.id)) is not None:
        raise api_error(409, "duplicate", "That evidence is already linked.")
    db.add(
        FindingEvidence(
            workspace_id=ctx.workspace_id,
            finding_id=f.id,
            evidence_id=e.id,
            note=body.note,
            linked_by=f"user:{ctx.user_id}",
        )
    )
    db.flush()
    record(
        db,
        "finding.evidence_linked",
        entity_type="finding",
        entity_id=f.id,
        data={"evidence_id": str(e.id)},
        **ctx.audit_kwargs(),
    )
    return get_finding(f.id, db, ctx)


@router.delete("/findings/{finding_id}/evidence/{evidence_id}", response_model=OkOut)
def unlink_evidence(
    finding_id: uuid.UUID,
    evidence_id: uuid.UUID,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.FINDINGS_EDIT),
) -> OkOut:
    f = _finding(db, ctx, finding_id)
    link = db.get(FindingEvidence, (f.id, evidence_id))
    if link is None:
        raise not_found("Link not found.")
    if link.linked_by.startswith("rule:"):
        raise api_error(
            409, "rule_link", "Evidence linked by a rule is the finding's provenance and stays."
        )
    if f.validation_status is ValidationStatus.VALIDATED:
        raise api_error(409, "validated", "Unvalidate the finding before removing evidence.")
    db.delete(link)
    record(
        db,
        "finding.evidence_unlinked",
        entity_type="finding",
        entity_id=f.id,
        data={"evidence_id": str(evidence_id)},
        **ctx.audit_kwargs(),
    )
    return OkOut()


@router.get("/projects/{project_id}/evidence", response_model=list[EvidenceSummary])
def project_evidence(
    project_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> list[EvidenceSummary]:
    rows = db.scalars(
        select(Evidence)
        .where(Evidence.project_id == project_id, Evidence.workspace_id == ctx.workspace_id)
        .order_by(Evidence.collected_at.desc())
        .limit(500)
    ).all()
    return [evidence_summary(e) for e in rows]
