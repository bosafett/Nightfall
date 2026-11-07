"""CHRONICLE v1: a project's operational history (Addendum 5, JANUS CORE).

Read-only and computed on request. CHRONICLE stores nothing of its own: every entry is an
existing audit event, and it points to the records involved (operation, finding, evidence,
report...) instead of copying them, so the audit log stays the single authoritative source.

An event belongs to a project when its entity is one of the project's records (the project,
its scope versions, operations, findings, evidence, attack paths, reports, playbook runs,
agent tasks), when its data names the project (e.g. an operation refused before it existed),
or when it is a proof-of-control check against one of the project's scope versions.

Filters narrow the history to one asset (the asset, its findings, evidence and agent tasks,
and the operations that produced that evidence) or one operation (the operation, its
evidence and the findings linked to that evidence).

Any member may read a project's history, as with the War Room's decision log. Like it,
entries carry only fixed safe fields: never IP addresses, user agents or raw event data.
The full audit log stays owner- and admin-only.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import ColumnElement, String, cast, literal, or_, select, tuple_, union_all
from sqlalchemy.orm import Session

from nightfall.core.audit.routes import redact
from nightfall.core.db.models import (
    AgentTask,
    AssessmentSnapshot,
    Asset,
    AttackPath,
    AuditEvent,
    Evidence,
    Finding,
    FindingEvidence,
    Operation,
    PlaybookRun,
    Project,
    Scope,
    User,
    WorkflowRun,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["chronicle"])

MAX_LIMIT = 200
SAFE_FIELDS = (
    "tool",
    "target",
    "risk_class",
    "reason",
    "agent",
    "from",
    "to",
    "note",
    "version",
    "reference",
    "title",
    "ref",
    "severity",
    "status",
    "playbook_id",
    "profile",
    "name",
    "method",
    "ok",
    "detail",
    "scope_version",
    "fields",
    "workflow",
    "step",
    "answer",
    "attempt",
    "format",
    "sha256",
    "accepted",
    "refused",
    "cancelled",
    "approved",
    "steps",
    "error",
)

# Sentence for each action (the actor's name goes in front for people).
ACTIONS: dict[str, str] = {
    "project.created": "created the project",
    "project.updated": "updated the project",
    "scope.draft_created": "started a scope draft",
    "scope.draft_updated": "edited the scope draft",
    "scope.draft_discarded": "discarded the scope draft",
    "scope.target_added": "added a scope target",
    "scope.target_removed": "removed a scope target",
    "scope.exclusion_added": "added a scope exclusion",
    "scope.exclusion_removed": "removed a scope exclusion",
    "scope.authorized": "authorized the scope",
    "ownership.checked": "checked proof of control",
    "operation.requested": "requested an operation",
    "operation.approved": "approved an operation",
    "operation.rejected": "rejected an operation",
    "operation.denied": "Operation refused by CONTROL",
    "operation.cancelled": "cancelled an operation",
    "operation.completed": "Operation completed",
    "operation.failed": "Operation failed",
    "probe.requested": "requested a probe",
    "probe.submitted": "submitted a probe",
    "probe.denied": "Probe refused by CONTROL",
    "playbook.requested": "launched a playbook",
    "playbook.approved": "approved a playbook run",
    "playbook.rejected": "rejected a playbook run",
    "playbook.cancelled": "cancelled a playbook run",
    "playbook.denied": "Playbook refused by preflight",
    "finding.created": "recorded a finding",
    "finding.updated": "edited a finding",
    "finding.status_changed": "changed a finding's status",
    "finding.evidence_linked": "linked evidence to a finding",
    "finding.evidence_unlinked": "unlinked evidence from a finding",
    "finding.proposed_by_agent": "AI agent proposed a finding (hypothesis)",
    "finding.reviewed_by_agent": "AI agent reviewed a finding",
    "attack_path.created": "drew an attack path",
    "attack_path.updated": "edited an attack path",
    "attack_path.reviewed": "reviewed an attack path",
    "attack_path.proposed_by_agent": "AI agent proposed an attack path",
    "agent_task.requested": "asked an AI agent",
    "agent_task.succeeded": "AI agent task finished",
    "agent_task.cancelled": "cancelled an AI agent task",
    "agent.proposal_refused": "AI proposal refused by the gateway",
    "report.generated": "froze a report snapshot",
    "report.exported": "downloaded a report",
    "evidence.integrity_failed": "Evidence failed its integrity check",
    "asset.created": "added an asset",
    "asset.updated": "updated an asset",
    "relationship.proposed_by_agent": "AI agent proposed an asset relationship",
    "workflow.started": "started a workflow",
    "workflow.step_started": "started a workflow step",
    "workflow.step_blocked": "Workflow step couldn't start",
    "workflow.step_retried": "retried a workflow step",
    "workflow.review_completed": "completed a workflow review",
    "workflow.checkpoint_answered": "answered a workflow checkpoint",
    "workflow.cancelled": "cancelled a workflow",
    "workflow.finished": "Workflow finished",
}


class ChronicleEntry(Model):
    id: uuid.UUID  # the audit event
    occurred_at: datetime
    action: str
    category: str
    actor_type: str
    actor: str
    summary: str
    details: dict[str, Any]
    entity_type: str | None
    entity_id: uuid.UUID | None
    evidence_ids: list[uuid.UUID]


class ChronicleOut(Model):
    project_id: uuid.UUID | None  # None for an asset's activity across projects
    organization_id: uuid.UUID
    entries: list[ChronicleEntry]
    next_before: uuid.UUID | None  # pass as ?before= for older entries


def _entities(
    project_id: uuid.UUID | None, asset_id: uuid.UUID | None, operation_id: uuid.UUID | None
) -> Any:
    """(entity_type, entity_id) pairs whose events belong in this view."""

    def pair(entity: str, col: Any, *where: ColumnElement[bool]) -> Any:
        return select(literal(entity).label("t"), col.label("i")).where(*where)

    if operation_id is not None:
        op_evidence = select(Evidence.id).where(
            Evidence.operation_id == operation_id, Evidence.project_id == project_id
        )
        parts = [
            pair(
                "operation",
                Operation.id,
                Operation.id == operation_id,
                Operation.project_id == project_id,
            ),
            pair("evidence", Evidence.id, Evidence.id.in_(op_evidence)),
            pair(
                "finding",
                FindingEvidence.finding_id,
                FindingEvidence.evidence_id.in_(op_evidence),
            ),
        ]
    elif asset_id is not None:
        # Without a project: the asset's activity across every project of the workspace.
        def in_project(col: Any) -> list[ColumnElement[bool]]:
            return [col == project_id] if project_id is not None else []

        asset_evidence = select(Evidence.id).where(
            Evidence.asset_id == asset_id, *in_project(Evidence.project_id)
        )
        parts = [
            pair("asset", Asset.id, Asset.id == asset_id),
            pair(
                "finding", Finding.id, Finding.asset_id == asset_id, *in_project(Finding.project_id)
            ),
            pair("evidence", Evidence.id, Evidence.id.in_(asset_evidence)),
            pair(
                "operation",
                Evidence.operation_id,
                Evidence.id.in_(asset_evidence),
                Evidence.operation_id.is_not(None),
            ),
            pair(
                "agent_task",
                AgentTask.id,
                AgentTask.subject_asset_id == asset_id,
                *in_project(AgentTask.project_id),
            ),
        ]
    else:
        parts = [
            pair("project", Project.id, Project.id == project_id),
            pair("scope", Scope.id, Scope.project_id == project_id),
            pair("operation", Operation.id, Operation.project_id == project_id),
            pair("finding", Finding.id, Finding.project_id == project_id),
            pair("evidence", Evidence.id, Evidence.project_id == project_id),
            pair("attack_path", AttackPath.id, AttackPath.project_id == project_id),
            pair("report", AssessmentSnapshot.id, AssessmentSnapshot.project_id == project_id),
            pair("playbook_run", PlaybookRun.id, PlaybookRun.project_id == project_id),
            pair("agent_task", AgentTask.id, AgentTask.project_id == project_id),
            pair("workflow_run", WorkflowRun.id, WorkflowRun.project_id == project_id),
        ]
    return union_all(*parts).subquery()


def _belongs(
    project_id: uuid.UUID | None, asset_id: uuid.UUID | None, operation_id: uuid.UUID | None
) -> ColumnElement[bool]:
    ents = _entities(project_id, asset_id, operation_id)
    by_entity = tuple_(AuditEvent.entity_type, AuditEvent.entity_id).in_(select(ents.c.t, ents.c.i))
    if asset_id is not None or operation_id is not None or project_id is None:
        return by_entity
    pid = str(project_id)
    scope_ids = select(cast(Scope.id, String)).where(Scope.project_id == project_id)
    return or_(
        by_entity,
        # Events about work that never got a record (refused before creation), and
        # events whose entity lives elsewhere but name the project.
        AuditEvent.data["project_id"].astext == pid,
        # Proof-of-control checks are on workspace-wide claims, against a scope version.
        (AuditEvent.action == "ownership.checked")
        & AuditEvent.data["scope_id"].astext.in_(scope_ids),
    )


def _evidence_ids(data: dict[str, Any]) -> list[uuid.UUID]:
    out: list[uuid.UUID] = []
    raw = [data.get("evidence_id"), *(data.get("evidence_ids") or [])]
    for v in raw:
        try:
            if v:
                out.append(uuid.UUID(str(v)))
        except ValueError:
            continue
    return out


def _entry(e: AuditEvent, names: dict[uuid.UUID, str]) -> ChronicleEntry:
    data = redact(e.data) if isinstance(e.data, dict) else {}
    text = ACTIONS.get(e.action, e.action.replace("_", " ").replace(".", ": "))
    if e.actor_type.value == "user":
        actor = names.get(e.actor_id, "Unknown") if e.actor_id else "Unknown"
        # Sentences that start with a capital describe the system, not the person.
        summary = text if text[:1].isupper() else f"{actor} {text}"
    elif e.actor_type.value == "agent":
        actor = "AI agent"
        summary = text if text.startswith("AI") else f"AI agent: {text}"
    else:
        actor = "System"
        summary = text if text[:1].isupper() else f"System: {text}"
    details = {k: data[k] for k in SAFE_FIELDS if k in data and data[k] not in (None, "", [])}
    return ChronicleEntry(
        id=e.id,
        occurred_at=e.occurred_at,
        action=e.action,
        category=e.action.split(".", 1)[0],
        actor_type=e.actor_type.value,
        actor=actor,
        summary=summary,
        details=details,
        entity_type=e.entity_type,
        entity_id=e.entity_id,
        evidence_ids=_evidence_ids(data),
    )


def timeline(
    db: Session,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID | None,
    *,
    asset_id: uuid.UUID | None = None,
    operation_id: uuid.UUID | None = None,
    before: AuditEvent | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    q = select(AuditEvent).where(
        AuditEvent.workspace_id == workspace_id, _belongs(project_id, asset_id, operation_id)
    )
    if before is not None:
        q = q.where(tuple_(AuditEvent.occurred_at, AuditEvent.id) < (before.occurred_at, before.id))
    q = q.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(limit)
    return list(db.scalars(q))


def _page(
    db: Session,
    ctx: WorkspaceContext,
    project_id: uuid.UUID | None,
    organization_id: uuid.UUID,
    before: uuid.UUID | None,
    limit: int,
    **filters: uuid.UUID | None,
) -> ChronicleOut:
    anchor = None
    if before is not None:
        anchor = db.get(AuditEvent, before)
        if anchor is None or anchor.workspace_id != ctx.workspace_id:
            raise not_found("That history entry isn't in this workspace.")
    rows = timeline(db, ctx.workspace_id, project_id, before=anchor, limit=limit + 1, **filters)
    more = len(rows) > limit
    rows = rows[:limit]
    ids = {e.actor_id for e in rows if e.actor_id and e.actor_type.value == "user"}
    names = (
        {r[0]: r[1] for r in db.execute(select(User.id, User.display_name).where(User.id.in_(ids)))}
        if ids
        else {}
    )
    return ChronicleOut(
        project_id=project_id,
        organization_id=organization_id,
        entries=[_entry(e, names) for e in rows],
        next_before=rows[-1].id if more and rows else None,
    )


@router.get("/projects/{project_id}/chronicle", response_model=ChronicleOut)
def project_chronicle(
    project_id: uuid.UUID,
    db: DB,
    asset_id: uuid.UUID | None = None,
    operation_id: uuid.UUID | None = None,
    before: uuid.UUID | None = None,
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> ChronicleOut:
    """Newest first. Pass `next_before` back as `before` for the next page."""
    project = db.get(Project, project_id)
    if project is None or project.workspace_id != ctx.workspace_id:
        raise not_found("Project not found.")
    return _page(
        db,
        ctx,
        project.id,
        project.organization_id,
        before,
        limit,
        asset_id=asset_id,
        operation_id=operation_id,
    )


@router.get("/assets/{asset_id}/chronicle", response_model=ChronicleOut)
def asset_chronicle(
    asset_id: uuid.UUID,
    db: DB,
    before: uuid.UUID | None = None,
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> ChronicleOut:
    """An asset's activity across all projects: its findings, the evidence about it and
    the operations that produced that evidence, agent tasks about it, and edits to it."""
    asset = db.get(Asset, asset_id)
    if asset is None or asset.workspace_id != ctx.workspace_id:
        raise not_found("Asset not found.")
    return _page(db, ctx, None, asset.organization_id, before, limit, asset_id=asset.id)
