"""Assets: registered manually or discovered by collectors."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import StringConstraints
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from nightfall.core.audit.writer import record
from nightfall.core.db.models import (
    Asset,
    AssetHistory,
    AssetKind,
    AssetOwnership,
    AssetRelationship,
    AssetStatus,
    Confidence,
    Evidence,
    Organization,
    RelationshipStatus,
    RelationshipType,
    User,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission
from nightfall.scope import normalize
from nightfall.scope.normalize import NormalizationError

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["assets"])
LIST_LIMIT = 1000
HISTORY_LIMIT = 200
Notes = Annotated[str, StringConstraints(strip_whitespace=True, max_length=10000)]


def normalize_asset_value(kind: AssetKind, value: str) -> str:
    if kind in (AssetKind.DOMAIN, AssetKind.HOSTNAME):
        return normalize.hostname(value)
    if kind is AssetKind.IP_ADDRESS:
        return str(normalize.ip(value))
    if kind is AssetKind.IP_RANGE:
        return str(normalize.network(value))
    v = value.strip()
    if not v or len(v) > 500:
        raise NormalizationError("Enter between 1 and 500 characters.")
    return v


class AssetIn(Model):
    organization_id: uuid.UUID
    kind: AssetKind
    value: Annotated[str, StringConstraints(max_length=500)]
    ownership: AssetOwnership = AssetOwnership.UNKNOWN
    notes: Notes = ""


class AssetPatch(Model):
    ownership: AssetOwnership | None = None
    notes: Notes | None = None
    # A person's decision (ATLAS); collectors cannot set it (enforced by migration 0016).
    status: AssetStatus | None = None


class AssetOut(Model):
    id: uuid.UUID
    organization_id: uuid.UUID
    organization_name: str
    kind: AssetKind
    value: str
    ownership: AssetOwnership
    source: str
    notes: str
    status: AssetStatus
    first_seen_at: datetime
    last_seen_at: datetime


class AssetHistoryOut(Model):
    id: uuid.UUID
    change: str  # created | status | ownership | notes
    old_value: str | None
    new_value: str | None
    actor_user_id: uuid.UUID | None
    actor_name: str | None
    recorded_by: str  # database role that made the change, or "migration" for backfill
    occurred_at: datetime


class RelationshipOut(Model):
    direction: str  # "out" (this asset → other) or "in"
    rel_type: RelationshipType
    status: RelationshipStatus
    confidence: Confidence
    other_asset_id: uuid.UUID
    other_value: str
    rule_id: str
    evidence_id: uuid.UUID | None
    proposed_by_task_id: uuid.UUID | None
    last_seen_at: datetime


class EvidenceSummary(Model):
    id: uuid.UUID
    operation_id: uuid.UUID | None
    source: str
    collection_method: str
    tool_name: str
    tool_version: str
    confidence: Confidence
    collected_at: datetime
    size_bytes: int
    sha256: str


class AssetDetail(AssetOut):
    relationships: list[RelationshipOut]
    evidence: list[EvidenceSummary]
    history: list[AssetHistoryOut]


def evidence_summary(e: Evidence) -> EvidenceSummary:
    return EvidenceSummary(
        id=e.id,
        operation_id=e.operation_id,
        source=e.source,
        collection_method=e.collection_method,
        tool_name=e.tool_name,
        tool_version=e.tool_version,
        confidence=e.confidence,
        collected_at=e.collected_at,
        size_bytes=e.size_bytes,
        sha256=e.content_sha256.hex(),
    )


def _out(a: Asset, org_name: str) -> AssetOut:
    return AssetOut(
        id=a.id,
        organization_id=a.organization_id,
        organization_name=org_name,
        kind=a.kind,
        value=a.value,
        ownership=a.ownership,
        source=a.source,
        notes=a.notes,
        status=a.status,
        first_seen_at=a.first_seen_at,
        last_seen_at=a.last_seen_at,
    )


def _get(db: Session, ctx: WorkspaceContext, asset_id: uuid.UUID) -> tuple[Asset, str]:
    row = db.execute(
        select(Asset, Organization.name)
        .join(Organization, Organization.id == Asset.organization_id)
        .where(Asset.id == asset_id, Asset.workspace_id == ctx.workspace_id)
    ).first()
    if row is None:
        raise not_found("Asset not found.")
    return row[0], row[1]


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    organization_id: Annotated[uuid.UUID | None, Query()] = None,
    kind: Annotated[AssetKind | None, Query()] = None,
    status: Annotated[AssetStatus | None, Query()] = None,
) -> list[AssetOut]:
    q = (
        select(Asset, Organization.name)
        .join(Organization, Organization.id == Asset.organization_id)
        .where(Asset.workspace_id == ctx.workspace_id)
    )
    if organization_id is not None:
        q = q.where(Asset.organization_id == organization_id)
    if kind is not None:
        q = q.where(Asset.kind == kind)
    if status is not None:
        q = q.where(Asset.status == status)
    rows = db.execute(q.order_by(Asset.kind, Asset.value).limit(LIST_LIMIT)).all()
    return [_out(a, n) for a, n in rows]


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(
    body: AssetIn, db: DB, ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE)
) -> AssetOut:
    org = db.scalar(
        select(Organization).where(
            Organization.id == body.organization_id, Organization.workspace_id == ctx.workspace_id
        )
    )
    if org is None:
        raise not_found("Organization not found.")
    try:
        value = normalize_asset_value(body.kind, body.value)
    except NormalizationError as exc:
        raise api_error(422, "invalid_value", str(exc)) from exc
    a = Asset(
        workspace_id=ctx.workspace_id,
        organization_id=org.id,
        kind=body.kind,
        value=value,
        ownership=body.ownership,
        source="manual",
        notes=body.notes,
    )
    db.add(a)
    try:
        db.flush()
    except IntegrityError as exc:
        raise api_error(409, "duplicate", "That asset is already registered.") from exc
    db.refresh(a)
    record(
        db,
        "asset.created",
        entity_type="asset",
        entity_id=a.id,
        data={"kind": a.kind.value, "value": a.value},
        **ctx.audit_kwargs(),
    )
    return _out(a, org.name)


@router.get("/assets/{asset_id}", response_model=AssetDetail)
def get_asset(
    asset_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> AssetDetail:
    a, org_name = _get(db, ctx, asset_id)
    other = aliased(Asset)
    rels = db.execute(
        select(AssetRelationship, other.id, other.value)
        .join(
            other,
            or_(
                (AssetRelationship.from_asset_id == a.id)
                & (other.id == AssetRelationship.to_asset_id),
                (AssetRelationship.to_asset_id == a.id)
                & (other.id == AssetRelationship.from_asset_id),
            ),
        )
        .order_by(AssetRelationship.rel_type, other.value)
        .limit(500)
    ).all()
    # Evidence about this asset directly, plus the evidence behind each relationship that
    # discovered it, so every collected asset traces back to the raw output that found it.
    rel_evidence = select(AssetRelationship.evidence_id).where(
        or_(AssetRelationship.from_asset_id == a.id, AssetRelationship.to_asset_id == a.id),
        AssetRelationship.evidence_id.is_not(None),
    )
    evidence = db.scalars(
        select(Evidence)
        .where(or_(Evidence.asset_id == a.id, Evidence.id.in_(rel_evidence)))
        .order_by(Evidence.collected_at.desc())
        .limit(50)
    ).all()
    history = db.execute(
        select(AssetHistory, User.display_name)
        .outerjoin(User, User.id == AssetHistory.actor_user_id)
        .where(AssetHistory.asset_id == a.id)
        .order_by(AssetHistory.occurred_at.desc(), AssetHistory.id)
        .limit(HISTORY_LIMIT)
    ).all()
    return AssetDetail(
        **_out(a, org_name).model_dump(),
        relationships=[
            RelationshipOut(
                direction="out" if r.from_asset_id == a.id else "in",
                rel_type=r.rel_type,
                status=r.status,
                confidence=r.confidence,
                other_asset_id=oid,
                other_value=ov,
                rule_id=r.rule_id,
                evidence_id=r.evidence_id,
                proposed_by_task_id=r.proposed_by_task_id,
                last_seen_at=r.last_seen_at,
            )
            for r, oid, ov in rels
        ],
        evidence=[evidence_summary(e) for e in evidence],
        history=[
            AssetHistoryOut(
                id=h.id,
                change=h.change,
                old_value=h.old_value,
                new_value=h.new_value,
                actor_user_id=h.actor_user_id,
                actor_name=name,
                recorded_by=h.recorded_by,
                occurred_at=h.occurred_at,
            )
            for h, name in history
        ],
    )


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: uuid.UUID,
    body: AssetPatch,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.REGISTRY_WRITE),
) -> AssetOut:
    a, org_name = _get(db, ctx, asset_id)
    changes = {
        k: v
        for k, v in body.model_dump(exclude_unset=True, exclude_none=True).items()
        if getattr(a, k) != v
    }
    old_status = a.status
    for k, v in changes.items():
        setattr(a, k, v)
    db.flush()
    db.refresh(a)
    if changes:
        data: dict[str, object] = {"fields": sorted(changes)}
        if "status" in changes:
            data["status"] = {"from": old_status.value, "to": a.status.value}
        record(
            db,
            "asset.updated",
            entity_type="asset",
            entity_id=a.id,
            data=data,
            **ctx.audit_kwargs(),
        )
    return _out(a, org_name)
