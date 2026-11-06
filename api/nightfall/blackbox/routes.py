"""BLACK BOX: evidence inventory, on-demand integrity verification, retention reporting.

Verification re-reads stored content and recomputes its SHA-256 against the evidence row.
It runs only when a person asks (no recurring execution), in batches small enough for one
serverless request, and records each run in the audit log. Retention is reported, never
enforced: evidence is insert-only and nothing here deletes it.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from sqlalchemy import case, func, select, tuple_
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import AuditEvent, Evidence, EvidenceKind
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.evidence_store import EvidenceStore, read_raw_from
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["blackbox"])

VERIFY_BATCH = 200  # evidence rows per request; blobs are at most 5 MB each
FAILURES_RECORDED = 50
AGE_THRESHOLDS = (90, 365)


class KindCount(Model):
    kind: EvidenceKind
    count: int


class AgeCount(Model):
    older_than_days: int
    count: int


class LastVerification(Model):
    occurred_at: datetime
    checked: int
    failed: int
    complete: bool


class BlackBoxOut(Model):
    total: int
    total_bytes: int
    simulated: int
    by_kind: list[KindCount]
    oldest_collected_at: datetime | None
    newest_collected_at: datetime | None
    by_age: list[AgeCount]
    retention_policy: Literal["keep_indefinitely"]
    last_verification: LastVerification | None


class Failure(Model):
    evidence_id: uuid.UUID
    problem: Literal["missing", "hash_mismatch", "size_mismatch"]


class VerifyOut(Model):
    checked: int
    ok: int
    failures: list[Failure]
    run_id: uuid.UUID
    total_checked: int  # this run so far, from the audit log
    total_failed: int
    next_after: uuid.UUID | None  # pass back as `after` with `run_id`; None when finished


@router.get("/blackbox", response_model=BlackBoxOut)
def inventory(db: DB, ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ)) -> BlackBoxOut:
    now = utcnow()
    mine = Evidence.workspace_id == ctx.workspace_id
    ages = [
        func.count(case((Evidence.collected_at < now - timedelta(days=d), 1)))
        for d in AGE_THRESHOLDS
    ]
    row = db.execute(
        select(
            func.count(),
            func.coalesce(func.sum(Evidence.size_bytes), 0),
            func.count(case((Evidence.is_simulation, 1))),
            func.min(Evidence.collected_at),
            func.max(Evidence.collected_at),
            *ages,
        ).where(mine)
    ).one()
    kinds = db.execute(
        select(Evidence.kind, func.count())
        .where(mine)
        .group_by(Evidence.kind)
        .order_by(Evidence.kind)
    ).all()
    last = db.scalar(
        select(AuditEvent)
        .where(
            AuditEvent.workspace_id == ctx.workspace_id, AuditEvent.action == "blackbox.verified"
        )
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    return BlackBoxOut(
        total=row[0],
        total_bytes=int(row[1]),
        simulated=row[2],
        by_kind=[KindCount(kind=k, count=c) for k, c in kinds],
        oldest_collected_at=row[3],
        newest_collected_at=row[4],
        by_age=[
            AgeCount(older_than_days=d, count=c)
            for d, c in zip(AGE_THRESHOLDS, row[5:], strict=True)
        ],
        retention_policy="keep_indefinitely",
        last_verification=None
        if last is None
        else LastVerification(
            occurred_at=last.occurred_at,
            checked=int(last.data.get("total_checked", 0)),
            failed=int(last.data.get("total_failed", 0)),
            complete=bool(last.data.get("complete", False)),
        ),
    )


def _load(db: Session, digest: bytes) -> bytes | None:
    s = get_settings()
    if s.evidence_backend == "postgres":
        return read_raw_from(db, digest)  # row-level security confines it to this workspace
    return EvidenceStore(s.evidence_dir).read_raw(digest)


def _problem(data: bytes | None, digest: bytes, size: int) -> str | None:
    if data is None:
        return "missing"
    if hashlib.sha256(data).digest() != digest:
        return "hash_mismatch"
    if len(data) != size:
        return "size_mismatch"
    return None


@router.post("/blackbox/verify", response_model=VerifyOut)
def verify(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.AUDIT_READ),
    after: Annotated[uuid.UUID | None, Query()] = None,
    run_id: Annotated[uuid.UUID | None, Query()] = None,
) -> VerifyOut:
    """One batch of a verification run. Start without parameters; continue with the
    returned `next_after` and `run_id` until `next_after` is null."""
    if (after is None) != (run_id is None):
        raise api_error(422, "invalid_cursor", "Pass both after and run_id, or neither.")
    q = select(
        Evidence.id, Evidence.content_sha256, Evidence.size_bytes, Evidence.created_at
    ).where(Evidence.workspace_id == ctx.workspace_id)
    if after is not None:
        cursor = db.execute(
            select(Evidence.created_at, Evidence.id).where(
                Evidence.id == after, Evidence.workspace_id == ctx.workspace_id
            )
        ).first()
        if cursor is None:
            raise not_found("Evidence not found.")
        q = q.where(tuple_(Evidence.created_at, Evidence.id) > tuple_(cursor[0], cursor[1]))
    rows = db.execute(q.order_by(Evidence.created_at, Evidence.id).limit(VERIFY_BATCH + 1)).all()
    more = len(rows) > VERIFY_BATCH
    rows = rows[:VERIFY_BATCH]

    cache: dict[bytes, bytes | None] = {}
    failures: list[Failure] = []
    for eid, digest, size, _ in rows:
        digest = bytes(digest)
        if digest not in cache:
            cache[digest] = _load(db, digest)
        problem = _problem(cache[digest], digest, size)
        if problem is not None:
            failures.append(Failure(evidence_id=eid, problem=problem))  # type: ignore[arg-type]

    for f in failures[:FAILURES_RECORDED]:
        record(
            db,
            "evidence.integrity_failed",
            entity_type="evidence",
            entity_id=f.evidence_id,
            data={"problem": f.problem, "by": "blackbox"},
            **ctx.audit_kwargs(),
        )
    prior_checked, prior_failed = 0, 0
    if run_id is not None:
        prior = db.execute(
            select(
                func.coalesce(func.sum(AuditEvent.data["checked"].as_integer()), 0),
                func.coalesce(func.sum(AuditEvent.data["failed"].as_integer()), 0),
            ).where(
                AuditEvent.workspace_id == ctx.workspace_id,
                AuditEvent.action == "blackbox.verified",
                AuditEvent.data["run_id"].astext == str(run_id),
            )
        ).one()
        prior_checked, prior_failed = int(prior[0]), int(prior[1])
    run = run_id or uuid.uuid4()
    data: dict[str, Any] = {
        "run_id": str(run),
        "checked": len(rows),
        "failed": len(failures),
        "total_checked": prior_checked + len(rows),
        "total_failed": prior_failed + len(failures),
        "complete": not more,
    }
    record(db, "blackbox.verified", data=data, **ctx.audit_kwargs())
    return VerifyOut(
        checked=len(rows),
        ok=len(rows) - len(failures),
        failures=failures,
        run_id=run,
        total_checked=data["total_checked"],
        total_failed=data["total_failed"],
        next_after=rows[-1][0] if more else None,
    )
