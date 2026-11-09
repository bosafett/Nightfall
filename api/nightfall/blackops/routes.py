"""BLACK OPS API (Addendum 4): browse playbooks, preflight, launch, approve, history.

A playbook run never executes anything itself. Launching one re-runs the preflight on the
server and then writes one ordinary operation per step, pinned to the active scope version:

  DISCOVER   the catalog (reviewed definitions in code, fingerprinted)
  PREFLIGHT  scope, profile, target type, dependencies, budget, conflicts, permission
  PROPOSE    the steps are shown with their risk and whether they need approval
  APPROVE    someone other than the requester approves the run's steps (per-operation
             approvals, so the worker's existing re-check applies unchanged)
  EXECUTE    the normal worker, or the lab worker for lab scopes (disjoint queues)
  VERIFY     scope, approval and profile re-checked by the worker before anything is sent
  CAPTURE    evidence, assets and unverified findings through BLACK ICE
  CLEANUP    nothing to undo: the available playbooks are read-only

Every refusal is audited, including launches refused by preflight.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, NoReturn

from fastapi import APIRouter, BackgroundTasks, Query, Request
from pydantic import StringConstraints
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nightfall.blackops import profile_b
from nightfall.blackops.catalog import (
    PLAYBOOKS,
    PROFILES,
    Category,
    Playbook,
    Profile,
    TargetType,
)
from nightfall.blacksite.boundary import lab_boundary
from nightfall.config import get_settings
from nightfall.core.audit.writer import record, record_detached
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    AuditEvent,
    Evidence,
    Finding,
    Operation,
    OperationStatus,
    PlaybookRun,
    PlaybookSetting,
    Project,
    RiskClass,
    Scope,
    Severity,
    User,
    ValidationStatus,
)
from nightfall.core.db.session import DB
from nightfall.core.errors import api_error, not_found
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import (
    WorkspaceContext,
    is_blacksite,
    may_approve_own,
    ws_permission,
)
from nightfall.core.tenancy.permissions import Permission, has_permission
from nightfall.recon.collectors import LAB_TOOLS, TOOLS
from nightfall.recon.routes import (
    HOURLY_LIMIT,
    PENDING,
    DecisionIn,
    _drain_later,
    approve_locked,
    reject_locked,
)
from nightfall.registry.assets import EvidenceSummary, evidence_summary
from nightfall.scope.engine import evaluate, parse_target
from nightfall.scope.repository import active_scope, snapshot

router = APIRouter(prefix="/api/workspaces/{workspace_id}/blackops", tags=["blackops"])


# --- Library -------------------------------------------------------------------------


class PlaybookStepOut(Model):
    tool: str
    label: str
    risk_class: RiskClass
    purpose: str
    lab_capable: bool


class DependencyOut(Model):
    name: str
    license: str
    pinned: str


class ChangeOut(Model):
    version: str
    date: str
    note: str


class ProfileOut(Model):
    key: Profile
    code: str
    label: str
    description: str
    available: bool
    unavailable_reason: str | None


class PlaybookOut(Model):
    id: str
    name: str
    version: str
    definition_sha256: str
    category: Category
    summary: str
    risk_class: RiskClass
    profiles: list[Profile]
    lab_only: bool
    target_types: list[TargetType]
    steps: list[PlaybookStepOut]
    needs_approval_live: bool
    identities_required: int  # Profile B: designated test identities a run needs
    takes_paths: bool  # Profile B playbook 8: operator-registered paths
    takes_safe_forms: bool  # Profile B playbook 6: forms marked safe for POST
    enabled: bool
    availability: Literal["available", "disabled", "blocked"]
    blocked_reason: str | None


class SettingChangeOut(Model):
    enabled: bool
    changed_by: str | None
    changed_at: datetime


class PlaybookDetail(PlaybookOut):
    description: str
    expected_duration: str
    limits: list[str]
    outputs: list[str]
    cleanup: str
    dependencies: list[DependencyOut]
    tests: list[str]
    changelog: list[ChangeOut]
    setting_history: list[SettingChangeOut]
    runs: int


class LibraryOut(Model):
    profiles: list[ProfileOut]
    playbooks: list[PlaybookOut]
    can_run: bool
    can_manage: bool
    # Features currently unlocked by a self-review (temporary owner decision): never independent.
    self_review_notices: list[str] = []


def _unavailable_tools() -> set[str]:
    """Tools this deployment can't run (same rule as BLACK ICE's source panel)."""
    from nightfall.recon.collectors import PACK_TOOLS, PROFILE_B_TOOLS
    from nightfall.tools.nuclei import pack1

    s = get_settings()
    out = {"nuclei"} if s.on_demand_worker and not s.nuclei_bin else set()
    if pack1.unavailable_reason(s) or s.on_demand_worker:
        out |= set(PACK_TOOLS)  # lab tool pack 1: BLACKSITE plus its own review, lab worker
    if profile_b.unavailable_reason(s) or s.collector_mode != "live":
        out |= set(PROFILE_B_TOOLS)  # Profile B: its gates, a live self-hosted worker
    return out


def _enabled_map(db: Session, ctx: WorkspaceContext) -> dict[str, bool]:
    rows = db.execute(
        select(PlaybookSetting.playbook_id, PlaybookSetting.enabled).where(
            PlaybookSetting.workspace_id == ctx.workspace_id
        )
    ).all()
    return {pid: enabled for pid, enabled in rows}


def _out(p: Playbook, enabled: bool) -> PlaybookOut:
    missing = [t for t in p.tools if t not in TOOLS]
    unavailable = sorted(set(p.tools) & _unavailable_tools())
    blocked = (
        f"Unknown tool {missing[0]}."
        if missing
        else f"{TOOLS[unavailable[0]][0]} can't run on this deployment."
        if unavailable
        else None
    )
    return PlaybookOut(
        id=p.id,
        name=p.name,
        version=p.version,
        definition_sha256=p.sha256,
        category=p.category,
        summary=p.summary,
        risk_class=p.risk_class,
        profiles=list(p.profiles),
        lab_only=p.profiles == (Profile.LAB,),
        identities_required=p.identities,
        takes_paths=p.takes_paths,
        takes_safe_forms=p.takes_safe_forms,
        target_types=list(p.target_types),
        steps=[
            PlaybookStepOut(
                tool=s.tool,
                label=TOOLS[s.tool][0],
                risk_class=TOOLS[s.tool][1],
                purpose=s.purpose,
                lab_capable=s.tool in LAB_TOOLS,
            )
            for s in p.steps
        ],
        needs_approval_live=p.needs_approval(Profile.LIVE),
        enabled=enabled,
        availability="blocked" if blocked else "available" if enabled else "disabled",
        blocked_reason=blocked,
    )


def _playbook(playbook_id: str) -> Playbook:
    p = PLAYBOOKS.get(playbook_id)
    if p is None:
        raise not_found("Playbook not found.")
    return p


@router.get("/playbooks", response_model=LibraryOut)
def list_playbooks(db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)) -> LibraryOut:
    enabled = _enabled_map(db, ctx)
    pb_reason = profile_b.unavailable_reason(get_settings())
    return LibraryOut(
        self_review_notices=_self_review_notices(),
        profiles=[
            ProfileOut(
                key=k,
                code=v.code,
                label=v.label,
                description=v.description,
                available=v.available or (k is Profile.VALIDATION and pb_reason is None),
                unavailable_reason=pb_reason if k is Profile.VALIDATION else v.unavailable_reason,
            )
            for k, v in PROFILES.items()
        ],
        playbooks=[_out(p, enabled.get(p.id, True)) for p in PLAYBOOKS.values()],
        can_run=has_permission(ctx.role, Permission.PLAYBOOKS_RUN),
        can_manage=has_permission(ctx.role, Permission.PLAYBOOKS_MANAGE),
    )


def _setting_history(
    db: Session, ctx: WorkspaceContext, playbook_id: str
) -> list[SettingChangeOut]:
    rows = db.execute(
        select(AuditEvent.data, AuditEvent.occurred_at, User.display_name)
        .outerjoin(User, User.id == AuditEvent.actor_id)
        .where(
            AuditEvent.workspace_id == ctx.workspace_id,
            AuditEvent.action == "playbook.setting_changed",
            AuditEvent.data["playbook_id"].astext == playbook_id,
        )
        .order_by(AuditEvent.occurred_at.desc())
        .limit(50)
    ).all()
    return [
        SettingChangeOut(enabled=bool(data.get("enabled")), changed_by=name, changed_at=at)
        for data, at, name in rows
    ]


@router.get("/playbooks/{playbook_id}", response_model=PlaybookDetail)
def get_playbook(
    playbook_id: str, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> PlaybookDetail:
    p = _playbook(playbook_id)
    runs = (
        db.scalar(
            select(func.count())
            .select_from(PlaybookRun)
            .where(PlaybookRun.workspace_id == ctx.workspace_id, PlaybookRun.playbook_id == p.id)
        )
        or 0
    )
    return PlaybookDetail(
        **_out(p, _enabled_map(db, ctx).get(p.id, True)).model_dump(),
        description=p.description,
        expected_duration=p.expected_duration,
        limits=list(p.limits),
        outputs=list(p.outputs),
        cleanup=p.cleanup,
        dependencies=[
            DependencyOut(name=d.name, license=d.license, pinned=d.pinned) for d in p.dependencies()
        ],
        tests=list(p.tests),
        changelog=[ChangeOut(version=c.version, date=c.date, note=c.note) for c in p.changelog],
        setting_history=_setting_history(db, ctx, p.id),
        runs=runs,
    )


class SettingIn(Model):
    enabled: bool


@router.put("/playbooks/{playbook_id}/setting", response_model=PlaybookDetail)
def set_playbook_enabled(
    playbook_id: str,
    body: SettingIn,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.PLAYBOOKS_MANAGE),
) -> PlaybookDetail:
    p = _playbook(playbook_id)
    row = db.get(PlaybookSetting, (ctx.workspace_id, p.id))
    if row is None:
        db.add(
            PlaybookSetting(
                workspace_id=ctx.workspace_id,
                playbook_id=p.id,
                enabled=body.enabled,
                updated_by_user_id=ctx.user_id,
            )
        )
    else:
        row.enabled = body.enabled
        row.updated_by_user_id = ctx.user_id
        row.updated_at = utcnow()
    record(
        db,
        "playbook.setting_changed",
        entity_type="playbook",
        data={"playbook_id": p.id, "version": p.version, "enabled": body.enabled},
        **ctx.audit_kwargs(),
    )
    db.flush()
    return get_playbook(playbook_id, db, ctx)


# --- Preflight -----------------------------------------------------------------------


class PreflightCheckOut(Model):
    key: str
    label: str
    status: Literal["pass", "fail", "info"]
    detail: str


class ProposedStep(Model):
    step: int
    tool: str
    label: str
    risk_class: RiskClass
    needs_approval: bool


class PreflightIn(Model):
    playbook_id: Annotated[str, StringConstraints(max_length=64)]
    target: Annotated[str, StringConstraints(max_length=300)]
    identity_ids: list[uuid.UUID] = []  # Profile B only: designated test identities
    # Profile B playbook 8 only: paths on the target that belong to the higher role.
    paths: list[Annotated[str, StringConstraints(max_length=500)]] = []
    # Profile B playbook 6 only: form paths the operator marks safe to POST to (decision 5).
    safe_forms: list[Annotated[str, StringConstraints(max_length=500)]] = []


class PreflightOut(Model):
    playbook_id: str
    version: str
    definition_sha256: str
    target: str
    profile: Profile | None
    scope_version: int | None
    allowed: bool
    needs_approval: bool
    checks: list[PreflightCheckOut]
    steps: list[ProposedStep]


@dataclass
class _Preflight:
    out: PreflightOut
    scope: Scope | None
    proof_check_id: uuid.UUID | None = None  # Profile B: the passing proof-of-control check

    @property
    def first_failure(self) -> PreflightCheckOut | None:
        return next((c for c in self.out.checks if c.status == "fail"), None)


def _target_type(value: str) -> TargetType | None:
    host, addr = parse_target(value)
    if addr is not None:
        return TargetType.IP
    if host is not None:
        return TargetType.HOSTNAME
    return None


def _review_record(profile: Profile) -> dict[str, str]:
    """For the audit trail: which kind of review a lab or Profile B run ran under."""
    from nightfall.control.reviews import review

    s = get_settings()
    ref = {Profile.LAB: s.blacksite_review_ref, Profile.VALIDATION: s.profile_b_review_ref}.get(
        profile
    )
    if profile not in (Profile.LAB, Profile.VALIDATION):
        return {}
    r = review(ref, s, utcnow(), profile.value)
    return {"review_kind": r.kind, "review": r.label}


def _self_review_notices() -> list[str]:
    from nightfall.control.reviews import review

    s = get_settings()
    now = utcnow()
    out = []
    for name, ref in (
        ("BLACKSITE", s.blacksite_review_ref),
        ("Lab tool pack 1", s.lab_pack1_review_ref),
        ("Profile B", s.profile_b_review_ref),
    ):
        r = review(ref, s, now, name)
        if r.kind == "self" and r.ok:
            out.append(f"{name}: {r.label}")
    return out


def _review_label(ref: str | None) -> str:
    from nightfall.control.reviews import review

    return review(ref, get_settings(), utcnow(), "Profile B").label


def preflight(
    db: Session,
    ctx: WorkspaceContext,
    project_id: uuid.UUID,
    p: Playbook,
    raw_target: str,
    blacksite: bool = False,
    identity_ids: list[uuid.UUID] | None = None,
    paths: list[str] | None = None,
    safe_forms: list[str] | None = None,
) -> _Preflight:
    """The checks a launch must pass. Read-only; the launch route runs it again itself."""
    checks: list[PreflightCheckOut] = []
    proof_check_id: uuid.UUID | None = None

    def add(key: str, label: str, ok: bool, detail: str) -> None:
        checks.append(
            PreflightCheckOut(key=key, label=label, status="pass" if ok else "fail", detail=detail)
        )

    enabled = _enabled_map(db, ctx).get(p.id, True)
    add(
        "definition",
        "Reviewed definition",
        True,
        f"{p.id} {p.version}, SHA-256 {p.sha256[:12]}…, {len(p.steps)} step(s)",
    )
    add(
        "enabled",
        "Enabled in this workspace",
        enabled,
        "Enabled." if enabled else "An owner has disabled this playbook.",
    )
    can_run = has_permission(ctx.role, Permission.PLAYBOOKS_RUN)
    add(
        "permission",
        "Your authorization",
        can_run,
        "You may launch playbooks." if can_run else "Only workspace owners launch playbooks.",
    )

    scope = active_scope(db, project_id)
    decision = evaluate(snapshot(db, scope) if scope else None, raw_target, utcnow())
    target = decision.target
    add(
        "scope",
        "Target in authorized scope",
        decision.allowed and scope is not None,
        f"In scope v{scope.version} ({scope.authorization_reference or 'no reference'})."
        if decision.allowed and scope is not None
        else decision.reason,
    )

    profile: Profile | None = None
    if scope is not None:
        profile = (
            Profile.LAB
            if scope.is_lab
            else Profile.VALIDATION
            if p.profiles == (Profile.VALIDATION,)
            else Profile.LIVE
        )
        info = PROFILES[profile]
        # Profile B's availability is its gates, checked below.
        ok = (info.available or profile is Profile.VALIDATION) and profile in p.profiles
        where_ok = (profile is Profile.LAB) == blacksite  # D3: lab work only via BLACKSITE
        add(
            "profile",
            "Execution profile",
            ok and where_ok,
            f"Profile {info.code} · {info.label}."
            if ok and where_ok
            else f"This playbook doesn't support profile {info.code} ({info.label}); it "
            f"supports {', '.join(PROFILES[x].code for x in p.profiles)}."
            if not ok
            else "Lab runs are launched from BLACKSITE on the lab machine (host-only)."
            if profile is Profile.LAB
            else "BLACKSITE runs lab work only.",
        )
        if blacksite:
            from nightfall.control.reviews import review

            s_ = get_settings()
            r = review(s_.blacksite_review_ref, s_, utcnow(), "BLACKSITE")
            add(
                "review",
                "Review recorded",
                r.ok,
                f"{r.label}." if r.ok else f"{r.problem} Lab execution stays off.",
            )

    if profile is Profile.VALIDATION and scope is not None:
        settings = get_settings()
        why = profile_b.unavailable_reason(settings)
        add(
            "profile_b",
            "Profile B gates",
            why is None,
            f"Enabled; {_review_label(settings.profile_b_review_ref)}." if why is None else why,
        )
        seen = profile_b.worker_seen(db, utcnow())
        add(
            "profile_b_worker",
            "Self-hosted Profile B worker",
            seen is not None,
            f"Checked in at {seen:%Y-%m-%d %H:%M} UTC; the run executes there only."
            if seen
            else "No self-hosted Profile B worker has checked in in the last "
            f"{int(profile_b.WORKER_SEEN.total_seconds() // 60)} minutes. Start it "
            "(infra/profile-b/README.md); Profile B never runs on the hosted platform.",
        )
        proof = profile_b.control_proof(db, scope, target, utcnow()) if decision.allowed else None
        proof_check_id = proof.id if proof else None
        add(
            "control",
            "Proof of control",
            proof is not None,
            f"Checked {proof.checked_at:%Y-%m-%d %H:%M} UTC against scope v{scope.version}."
            if proof
            else f"Prove control of {target} (DNS record or file) and check it against scope "
            f"v{scope.version}; a check must have passed in the last 24 hours.",
        )
        ids = identity_ids or []
        problem = profile_b.identity_problems(db, ctx.workspace_id, target, ids)
        if problem is None and len(ids) < p.identities:
            problem = f"This playbook needs {p.identities} test identit" + (
                "y." if p.identities == 1 else "ies."
            )
        if p.takes_paths:
            from nightfall.recon.access_audit import valid_paths

            try:
                n = len(valid_paths(paths or []))
                add("paths", "Registered paths", True, f"{n} path(s) on {target}.")
            except ValueError as exc:
                add("paths", "Registered paths", False, str(exc))
        if p.takes_safe_forms:
            from nightfall.recon.access_audit import valid_paths

            forms = safe_forms or []
            try:
                n = len(valid_paths(forms)) if forms else 0
                add(
                    "safe_forms",
                    "Forms marked safe for POST",
                    n <= 20,
                    f"{n} form path(s) may receive a POST; other POST forms are skipped."
                    if n
                    else "None: POST forms are skipped; only GET forms and links are tested.",
                )
            except ValueError as exc:
                add("safe_forms", "Forms marked safe for POST", False, str(exc))
        add(
            "identities",
            "Test identities",
            problem is None,
            problem or (f"{len(ids)} active identity(ies) for {target}." if ids else "None used."),
        )

    ttype = _target_type(target)
    if ttype is TargetType.HOSTNAME and TargetType.DOMAIN in p.target_types:
        ok, why = target.count(".") >= 1, "Needs a domain (for example example.com)."
    else:
        ok = ttype in p.target_types
        why = f"Needs a target of type {', '.join(t.value for t in p.target_types)}."
    add("target_type", "Target type", ok, f"{ttype.value if ttype else 'unknown'}." if ok else why)

    lab_missing = {t for t in p.tools if profile is Profile.LAB and t not in LAB_TOOLS}
    missing = sorted(
        (set(p.tools) & _unavailable_tools()) | lab_missing | (set(p.tools) - set(TOOLS))
    )
    add(
        "dependencies",
        "Tools available",
        not missing,
        f"Not available here: {', '.join(missing)}."
        if missing
        else "All step tools are registered on this deployment.",
    )

    recent = (
        db.scalar(
            select(func.count())
            .select_from(Operation)
            .where(
                Operation.workspace_id == ctx.workspace_id,
                Operation.created_at >= utcnow() - timedelta(hours=1),
            )
        )
        or 0
    )
    left = HOURLY_LIMIT - recent
    add(
        "budget",
        "Execution budget",
        left >= len(p.steps),
        f"{left} of {HOURLY_LIMIT} operations left this hour; this run uses {len(p.steps)}.",
    )

    busy = db.scalars(
        select(Operation.tool).where(
            Operation.project_id == project_id,
            Operation.target_value == target,
            Operation.tool.in_(p.tools),
            Operation.status.in_(PENDING),
        )
    ).all()
    add(
        "conflicts",
        "No overlapping work",
        not busy,
        "Nothing pending for these steps on this target."
        if not busy
        else f"Already pending on this target: {', '.join(sorted(set(busy)))}. Wait for it to "
        "finish or cancel it.",
    )

    needs_approval = profile is not None and p.needs_approval(profile)
    checks.append(
        PreflightCheckOut(
            key="approval",
            label="Approval",
            status="info",
            detail="Needs approval by someone other than you before anything runs."
            + (" Lab approvals expire after 24 hours." if profile is Profile.LAB else "")
            + (
                " Profile B: approve with two-factor in the last 15 minutes; the approval "
                "expires after 24 hours."
                if profile is Profile.VALIDATION
                else ""
            )
            if needs_approval
            else "Passive only: runs as soon as it is launched.",
        )
    )
    return _Preflight(
        out=PreflightOut(
            playbook_id=p.id,
            version=p.version,
            definition_sha256=p.sha256,
            target=target,
            profile=profile,
            scope_version=scope.version if scope else None,
            allowed=all(c.status != "fail" for c in checks),
            needs_approval=needs_approval,
            checks=checks,
            steps=[
                ProposedStep(
                    step=i,
                    tool=s.tool,
                    label=TOOLS[s.tool][0] if s.tool in TOOLS else s.tool,
                    risk_class=TOOLS[s.tool][1] if s.tool in TOOLS else RiskClass.HIGH,
                    needs_approval=needs_approval,
                )
                for i, s in enumerate(p.steps, start=1)
            ],
        ),
        scope=scope,
        proof_check_id=proof_check_id,
    )


def _project(db: Session, ctx: WorkspaceContext, project_id: uuid.UUID) -> Project:
    project = db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == ctx.workspace_id)
    )
    if project is None:
        raise not_found("Project not found.")
    return project


@router.post("/projects/{project_id}/preflight", response_model=PreflightOut)
def run_preflight(
    project_id: uuid.UUID,
    body: PreflightIn,
    request: Request,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
) -> PreflightOut:
    _project(db, ctx, project_id)
    p = _playbook(body.playbook_id)
    return preflight(
        db,
        ctx,
        project_id,
        p,
        body.target,
        is_blacksite(request),
        body.identity_ids,
        body.paths,
        body.safe_forms,
    ).out


# --- Runs ----------------------------------------------------------------------------

RunStatus = Literal[
    "awaiting_approval", "running", "succeeded", "partial", "failed", "denied", "rejected",
    "cancelled",
]  # fmt: skip


class RunStepOut(Model):
    step: int
    operation_id: uuid.UUID
    tool: str
    label: str
    risk_class: RiskClass
    status: OperationStatus
    denial_reason: str | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    result_summary: dict[str, Any]


class RunOut(Model):
    id: uuid.UUID
    playbook_id: str
    playbook_name: str
    playbook_version: str
    definition_sha256: str
    definition_current: bool
    profile: Profile
    project_id: uuid.UUID
    project_name: str
    scope_version: int
    target: str
    requested_by: str | None
    requested_by_user_id: uuid.UUID
    created_at: datetime
    status: RunStatus
    steps: list[RunStepOut]


class RunFindingOut(Model):
    id: uuid.UUID
    title: str
    severity: Severity
    validation_status: ValidationStatus
    check_id: str | None
    change: str


class RunDetail(RunOut):
    findings: list[RunFindingOut]
    evidence: list[EvidenceSummary]


class LaunchIn(PreflightIn):
    # The operator approves exactly what the preflight showed: a definition that changed
    # in between (new version) is refused rather than silently swapped in.
    version: Annotated[str, StringConstraints(max_length=32)]
    definition_sha256: Annotated[str, StringConstraints(max_length=64)]


def run_status(statuses: list[OperationStatus]) -> RunStatus:
    S = OperationStatus
    if any(s is S.AWAITING_APPROVAL for s in statuses):
        return "awaiting_approval"
    if any(s in (S.QUEUED, S.RUNNING) for s in statuses):
        return "running"
    if statuses and all(s is S.SUCCEEDED for s in statuses):
        return "succeeded"
    if any(s is S.SUCCEEDED for s in statuses):
        return "partial"
    for s, name in ((S.DENIED, "denied"), (S.REJECTED, "rejected"), (S.FAILED, "failed")):
        if any(x is s for x in statuses):
            return name  # type: ignore[return-value]
    return "cancelled"


def _runs(db: Session, ctx: WorkspaceContext, where: list[Any], limit: int = 100) -> list[RunOut]:
    rows = db.execute(
        select(PlaybookRun, Project.name, Scope.version, User.display_name)
        .join(Project, Project.id == PlaybookRun.project_id)
        .join(Scope, Scope.id == PlaybookRun.scope_id)
        .outerjoin(User, User.id == PlaybookRun.requested_by_user_id)
        .where(PlaybookRun.workspace_id == ctx.workspace_id, *where)
        .order_by(PlaybookRun.created_at.desc())
        .limit(limit)
    ).all()
    ids = [r[0].id for r in rows]
    ops: dict[uuid.UUID, list[Operation]] = {i: [] for i in ids}
    if ids:
        for op in db.scalars(
            select(Operation)
            .where(Operation.playbook_run_id.in_(ids))
            .order_by(Operation.playbook_step)
        ):
            ops[op.playbook_run_id].append(op)  # type: ignore[index]
    out: list[RunOut] = []
    for run, pname, version, requester in rows:
        p = PLAYBOOKS.get(run.playbook_id)
        steps = [
            RunStepOut(
                step=op.playbook_step or 0,
                operation_id=op.id,
                tool=op.tool,
                label=TOOLS.get(op.tool, (op.tool, op.risk_class))[0],
                risk_class=op.risk_class,
                status=op.status,
                denial_reason=op.denial_reason,
                error=op.error,
                started_at=op.started_at,
                finished_at=op.finished_at,
                result_summary=op.result_summary,
            )
            for op in ops[run.id]
        ]
        out.append(
            RunOut(
                id=run.id,
                playbook_id=run.playbook_id,
                playbook_name=p.name if p else run.playbook_id,
                playbook_version=run.playbook_version,
                definition_sha256=run.definition_sha256,
                definition_current=p is not None and p.sha256 == run.definition_sha256,
                profile=Profile(run.profile),
                project_id=run.project_id,
                project_name=pname,
                scope_version=version,
                target=run.target_value,
                requested_by=requester,
                requested_by_user_id=run.requested_by_user_id,
                created_at=run.created_at,
                status=run_status([s.status for s in steps]),
                steps=steps,
            )
        )
    return out


@router.get("/runs", response_model=list[RunOut])
def list_runs(
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.READ),
    project_id: Annotated[uuid.UUID | None, Query()] = None,
    playbook_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[RunOut]:
    where: list[Any] = []
    if project_id is not None:
        where.append(PlaybookRun.project_id == project_id)
    if playbook_id is not None:
        where.append(PlaybookRun.playbook_id == playbook_id)
    return _runs(db, ctx, where, limit)


@router.get("/runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: uuid.UUID, db: DB, ctx: WorkspaceContext = ws_permission(Permission.READ)
) -> RunDetail:
    found = _runs(db, ctx, [PlaybookRun.id == run_id], 1)
    if not found:
        raise not_found("Playbook run not found.")
    run = found[0]
    changes: dict[uuid.UUID, str] = {}
    for s in run.steps:
        for f in s.result_summary.get("findings") or []:
            try:
                changes.setdefault(uuid.UUID(str(f.get("finding_id"))), str(f.get("change")))
            except ValueError:
                continue
    findings = (
        db.scalars(select(Finding).where(Finding.id.in_(list(changes)))).all() if changes else []
    )
    order = list(Severity)
    evidence = db.scalars(
        select(Evidence)
        .where(Evidence.operation_id.in_([s.operation_id for s in run.steps]))
        .order_by(Evidence.collected_at)
    ).all()
    return RunDetail(
        **run.model_dump(),
        findings=[
            RunFindingOut(
                id=f.id,
                title=f.title,
                severity=f.severity,
                validation_status=f.validation_status,
                check_id=f.check_id,
                change=changes[f.id],
            )
            for f in sorted(findings, key=lambda f: (order.index(f.severity), f.title))
        ],
        evidence=[evidence_summary(e) for e in evidence],
    )


@router.post("/projects/{project_id}/runs", response_model=RunDetail, status_code=201)
def launch_run(
    project_id: uuid.UUID,
    body: LaunchIn,
    request: Request,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.PLAYBOOKS_RUN, fresh_mfa=True),
) -> RunDetail:
    _project(db, ctx, project_id)
    p = _playbook(body.playbook_id)

    def deny(code: str, reason: str, checks: list[PreflightCheckOut] | None = None) -> NoReturn:
        record_detached(
            "playbook.denied",
            entity_type="project",
            entity_id=project_id,
            data={
                "playbook_id": p.id,
                "version": p.version,
                "target": body.target[:300],
                "reason": reason,
                "failed_checks": [c.key for c in checks or [] if c.status == "fail"],
            },
            **ctx.audit_kwargs(),
        )
        raise api_error(422, code, reason)

    if body.version != p.version or body.definition_sha256 != p.sha256:
        deny(
            "definition_changed",
            f"The playbook is now version {p.version}; run the preflight again.",
        )
    pre = preflight(
        db,
        ctx,
        project_id,
        p,
        body.target,
        is_blacksite(request),
        body.identity_ids,
        body.paths,
        body.safe_forms,
    )
    failure = pre.first_failure
    scope, profile, target = pre.scope, pre.out.profile, pre.out.target
    if failure is not None or scope is None or profile is None:
        deny("preflight_failed", failure.detail if failure else "Preflight failed.", pre.out.checks)

    run = PlaybookRun(
        workspace_id=ctx.workspace_id,
        project_id=project_id,
        scope_id=scope.id,
        playbook_id=p.id,
        playbook_version=p.version,
        definition_sha256=p.sha256,
        profile=profile.value,
        target_value=target,
        requested_by_user_id=ctx.user_id,
        identity_ids=list(body.identity_ids) if profile is Profile.VALIDATION else [],
        ownership_check_ids=[pre.proof_check_id]
        if profile is Profile.VALIDATION and pre.proof_check_id
        else [],
    )
    needs_approval = p.needs_approval(profile)
    try:
        with db.begin_nested():
            db.add(run)
            db.flush()
            for i, step in enumerate(p.steps, start=1):
                label, risk = TOOLS[step.tool]
                db.add(
                    Operation(
                        workspace_id=ctx.workspace_id,
                        project_id=project_id,
                        scope_id=scope.id,
                        tool=step.tool,
                        risk_class=risk,
                        target_value=target,
                        params={
                            "method": label,
                            "playbook": f"{p.id}@{p.version}",
                            "step": i,
                            **({"paths": list(dict.fromkeys(body.paths))} if p.takes_paths else {}),
                            **(
                                {"safe_forms": list(dict.fromkeys(body.safe_forms))}
                                if p.takes_safe_forms
                                else {}
                            ),
                        },
                        requested_by_user_id=ctx.user_id,
                        is_lab=profile is Profile.LAB,
                        playbook_run_id=run.id,
                        playbook_step=i,
                        status=OperationStatus.AWAITING_APPROVAL
                        if needs_approval
                        else OperationStatus.QUEUED,
                    )
                )
            db.flush()
    except IntegrityError:  # a step was requested concurrently (one pending per target)
        raise api_error(
            409, "conflict", "Another request for this target started at the same time."
        ) from None
    record(
        db,
        "playbook.requested",
        entity_type="playbook_run",
        entity_id=run.id,
        data={
            "playbook_id": p.id,
            "version": p.version,
            "definition_sha256": p.sha256,
            "profile": profile.value,
            "target": target,
            "scope_version": scope.version,
            "steps": p.tools,
            **_review_record(profile),
        },
        **ctx.audit_kwargs(),
    )
    if not needs_approval:
        _drain_later(background)
    return get_run(run.id, db, ctx)


def _run_ops(
    db: Session, ctx: WorkspaceContext, run_id: uuid.UUID
) -> tuple[PlaybookRun, list[Operation]]:
    run = db.scalar(
        select(PlaybookRun).where(
            PlaybookRun.id == run_id, PlaybookRun.workspace_id == ctx.workspace_id
        )
    )
    if run is None:
        raise not_found("Playbook run not found.")
    ops = db.scalars(
        select(Operation)
        .where(Operation.playbook_run_id == run.id)
        .order_by(Operation.playbook_step)
        .with_for_update()
    ).all()
    return run, list(ops)


def _awaiting_ops(
    db: Session, ctx: WorkspaceContext, run_id: uuid.UUID, request: Request, executes: bool
) -> tuple[PlaybookRun, list[Operation]]:
    run, ops = _run_ops(db, ctx, run_id)
    lab_boundary(request, ctx, run.profile == "lab", "playbook.decide", executes=executes)
    waiting = [o for o in ops if o.status is OperationStatus.AWAITING_APPROVAL]
    if not waiting:
        raise api_error(409, "not_awaiting", "This run isn't waiting for a decision.")
    if run.requested_by_user_id == ctx.user_id and not may_approve_own(db, ctx):
        record_detached(
            "playbook.denied",
            entity_type="playbook_run",
            entity_id=run.id,
            data={"reason": "self_approval"},
            **ctx.audit_kwargs(),
        )
        raise api_error(
            409,
            "self_approval",
            "You launched this run, and the approval policy doesn't let you decide it.",
        )
    return run, waiting


@router.post("/runs/{run_id}/approve", response_model=RunDetail)
def approve_run(
    run_id: uuid.UUID,
    body: DecisionIn,
    request: Request,
    background: BackgroundTasks,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_APPROVE, fresh_mfa=True),
) -> RunDetail:
    """Approves every step still waiting, each against the run's pinned scope (a step whose
    target fell out of scope is denied instead, with the reason)."""
    run, waiting = _awaiting_ops(db, ctx, run_id, request, executes=True)
    approved = [o.id for o in waiting if approve_locked(db, ctx, o, body.reason)]
    record(
        db,
        "playbook.approved",
        entity_type="playbook_run",
        entity_id=run.id,
        data={"playbook_id": run.playbook_id, "approved": len(approved), "steps": len(waiting)},
        **ctx.audit_kwargs(),
    )
    db.flush()
    if approved:
        _drain_later(background)
    return get_run(run_id, db, ctx)


@router.post("/runs/{run_id}/reject", response_model=RunDetail)
def reject_run(
    run_id: uuid.UUID,
    body: DecisionIn,
    request: Request,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_APPROVE, fresh_mfa=True),
) -> RunDetail:
    run, waiting = _awaiting_ops(db, ctx, run_id, request, executes=False)
    for o in waiting:
        reject_locked(db, ctx, o, body.reason)
    record(
        db,
        "playbook.rejected",
        entity_type="playbook_run",
        entity_id=run.id,
        data={"playbook_id": run.playbook_id, "reason": body.reason},
        **ctx.audit_kwargs(),
    )
    db.flush()
    return get_run(run_id, db, ctx)


@router.post("/runs/{run_id}/cancel", response_model=RunDetail)
def cancel_run(
    run_id: uuid.UUID,
    request: Request,
    db: DB,
    ctx: WorkspaceContext = ws_permission(Permission.OPERATIONS_PROPOSE),
) -> RunDetail:
    run, ops = _run_ops(db, ctx, run_id)
    lab_boundary(request, ctx, run.profile == "lab", "playbook.cancel")
    open_ops = [
        o for o in ops if o.status in (OperationStatus.QUEUED, OperationStatus.AWAITING_APPROVAL)
    ]
    if not open_ops:
        raise api_error(409, "not_queued", "No step of this run is waiting to run.")
    for o in open_ops:
        o.status = OperationStatus.CANCELLED
        o.finished_at = utcnow()
        record(
            db, "operation.cancelled", entity_type="operation", entity_id=o.id, **ctx.audit_kwargs()
        )
    record(
        db,
        "playbook.cancelled",
        entity_type="playbook_run",
        entity_id=run.id,
        data={"cancelled": len(open_ops)},
        **ctx.audit_kwargs(),
    )
    db.flush()
    return get_run(run_id, db, ctx)
