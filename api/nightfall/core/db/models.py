"""ORM mappings. The schema itself is defined by the Alembic migrations (raw SQL);
these classes mirror it for queries. Server-side defaults are authoritative."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, LargeBinary, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True)}


class Role(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TokenPurpose(enum.StrEnum):
    INVITE = "invite"
    PASSWORD_RESET = "password_reset"  # noqa: S105


class ActorType(enum.StrEnum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


class AssessmentType(enum.StrEnum):
    RECONNAISSANCE = "reconnaissance"
    SECURITY_ASSESSMENT = "security_assessment"
    AI_SYSTEM_ASSESSMENT = "ai_system_assessment"
    ADVERSARIAL_SIMULATION = "adversarial_simulation"


class ProjectStatus(enum.StrEnum):
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


def _pg_enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, create_type=False, values_callable=lambda e: [m.value for m in e])


def _uuid_pk_col() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _created() -> Mapped[datetime]:
    return mapped_column(server_default=text("now()"))


def _updated() -> Mapped[datetime]:
    # Maintained by a database trigger; fetched back after UPDATE.
    return mapped_column(server_default=text("now()"), server_onupdate=text("now()"))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    email: Mapped[str]
    display_name: Mapped[str]
    password_hash: Mapped[str]
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    mfa_enabled: Mapped[bool] = mapped_column(server_default=text("false"))
    totp_last_step: Mapped[int | None]
    is_disabled: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    token_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = _created()
    last_seen_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    mfa_verified_at: Mapped[datetime | None]
    ip: Mapped[str | None]
    user_agent: Mapped[str | None]


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    name: Mapped[str]
    slug: Mapped[str]
    # 'single_operator' (default, D1) or 'two_person' (migration 0013).
    approval_policy: Mapped[str] = mapped_column(server_default=text("'single_operator'"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class WorkspaceMember(Base):
    __tablename__ = "workspace_members"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    role: Mapped[Role] = mapped_column(_pg_enum(Role, "workspace_role"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    purpose: Mapped[TokenPurpose] = mapped_column(_pg_enum(TokenPurpose, "auth_token_purpose"))
    token_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    email: Mapped[str | None]
    role: Mapped[Role | None] = mapped_column(_pg_enum(Role, "workspace_role"))
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created()


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    name: Mapped[str]
    notes: Mapped[str] = mapped_column(server_default=text("''"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str]
    description: Mapped[str] = mapped_column(server_default=text("''"))
    assessment_type: Mapped[AssessmentType] = mapped_column(
        _pg_enum(AssessmentType, "assessment_type")
    )
    status: Mapped[ProjectStatus] = mapped_column(
        _pg_enum(ProjectStatus, "project_status"), server_default=text("'planning'")
    )
    started_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class AuditEvent(Base):
    __tablename__ = "audit_events"
    # No RETURNING on insert: the app role can't read back events outside its workspace
    # context (e.g. sign-in events), and Postgres requires SELECT rights for RETURNING.
    __table_args__ = {"implicit_returning": False}
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("workspaces.id"))
    actor_type: Mapped[ActorType] = mapped_column(_pg_enum(ActorType, "actor_type"))
    actor_id: Mapped[uuid.UUID | None]
    action: Mapped[str]
    entity_type: Mapped[str | None]
    entity_id: Mapped[uuid.UUID | None]
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    ip: Mapped[str | None]
    user_agent: Mapped[str | None]
    occurred_at: Mapped[datetime] = _created()


# --- Phase 3: assets, scopes, operations, evidence --------------------------------


class AssetKind(enum.StrEnum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    APPLICATION = "application"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"
    OTHER = "other"


class AssetOwnership(enum.StrEnum):
    ORGANIZATION = "organization"
    THIRD_PARTY = "third_party"
    UNKNOWN = "unknown"


class ScopeStatus(enum.StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class ScopeEntryKind(enum.StrEnum):
    HOST = "host"  # exactly this hostname
    DOMAIN_TREE = "domain_tree"  # this domain and every subdomain
    IP = "ip"
    CIDR = "cidr"


class RiskClass(enum.StrEnum):
    PASSIVE = "passive"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class OperationStatus(enum.StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class EvidenceKind(enum.StrEnum):
    OBSERVATION = "observation"
    TOOL_OUTPUT = "tool_output"
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    AGENT_NOTE = "agent_note"


class Confidence(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RelationshipType(enum.StrEnum):
    SUBDOMAIN_OF = "subdomain_of"
    RESOLVES_TO = "resolves_to"
    CNAME_TO = "cname_to"


class RelationshipStatus(enum.StrEnum):
    OBSERVED = "observed"
    HYPOTHESIS = "hypothesis"


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    kind: Mapped[AssetKind] = mapped_column(_pg_enum(AssetKind, "asset_kind"))
    value: Mapped[str]
    ownership: Mapped[AssetOwnership] = mapped_column(
        _pg_enum(AssetOwnership, "asset_ownership"), server_default=text("'unknown'")
    )
    source: Mapped[str]
    notes: Mapped[str] = mapped_column(server_default=text("''"))
    first_seen_at: Mapped[datetime] = _created()
    last_seen_at: Mapped[datetime] = _created()
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class Scope(Base):
    __tablename__ = "scopes"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    version: Mapped[int]
    status: Mapped[ScopeStatus] = mapped_column(
        _pg_enum(ScopeStatus, "scope_status"), server_default=text("'draft'")
    )
    authorization_reference: Mapped[str] = mapped_column(server_default=text("''"))
    valid_from: Mapped[datetime | None]
    valid_until: Mapped[datetime | None]
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    authorized_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    authorized_at: Mapped[datetime | None]
    superseded_at: Mapped[datetime | None]
    is_lab: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class ScopeTarget(Base):
    __tablename__ = "scope_targets"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID]
    scope_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scopes.id"))
    kind: Mapped[ScopeEntryKind] = mapped_column(_pg_enum(ScopeEntryKind, "scope_entry_kind"))
    value: Mapped[str]
    note: Mapped[str] = mapped_column(server_default=text("''"))
    created_at: Mapped[datetime] = _created()


class ScopeExclusion(Base):
    __tablename__ = "scope_exclusions"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID]
    scope_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scopes.id"))
    kind: Mapped[ScopeEntryKind] = mapped_column(_pg_enum(ScopeEntryKind, "scope_entry_kind"))
    value: Mapped[str]
    reason: Mapped[str] = mapped_column(server_default=text("''"))
    created_at: Mapped[datetime] = _created()


class Operation(Base):
    __tablename__ = "operations"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    scope_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scopes.id"))
    tool: Mapped[str]
    risk_class: Mapped[RiskClass] = mapped_column(_pg_enum(RiskClass, "risk_class"))
    target_value: Mapped[str]
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    status: Mapped[OperationStatus] = mapped_column(
        _pg_enum(OperationStatus, "operation_status"), server_default=text("'queued'")
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    proposed_by_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"))
    is_lab: Mapped[bool] = mapped_column(server_default=text("false"))
    playbook_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("playbook_runs.id"))
    playbook_step: Mapped[int | None]
    denial_reason: Mapped[str | None]
    error: Mapped[str | None]
    result_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb")
    )
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    queued_at: Mapped[datetime] = _created()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class PlaybookRun(Base):
    """BLACK OPS (migration 0012): one run of a versioned playbook. Insert-only."""

    __tablename__ = "playbook_runs"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    scope_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scopes.id"))
    playbook_id: Mapped[str]
    playbook_version: Mapped[str]
    definition_sha256: Mapped[str]
    profile: Mapped[str]
    target_value: Mapped[str]
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _created()


class PlaybookSetting(Base):
    __tablename__ = "playbook_settings"
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"), primary_key=True)
    playbook_id: Mapped[str] = mapped_column(primary_key=True)
    enabled: Mapped[bool]
    updated_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = _created()


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    operation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("operations.id"))
    kind: Mapped[EvidenceKind] = mapped_column(_pg_enum(EvidenceKind, "evidence_kind"))
    source: Mapped[str]
    collection_method: Mapped[str]
    collected_at: Mapped[datetime]
    confidence: Mapped[Confidence] = mapped_column(_pg_enum(Confidence, "confidence_level"))
    tool_name: Mapped[str]
    tool_version: Mapped[str]
    input_params: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    content_sha256: Mapped[bytes] = mapped_column(LargeBinary)
    content_type: Mapped[str]
    size_bytes: Mapped[int]
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    is_simulation: Mapped[bool] = mapped_column(server_default=text("false"))
    created_at: Mapped[datetime] = _created()


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    from_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"))
    to_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"))
    rel_type: Mapped[RelationshipType] = mapped_column(
        _pg_enum(RelationshipType, "relationship_type")
    )
    status: Mapped[RelationshipStatus] = mapped_column(
        _pg_enum(RelationshipStatus, "relationship_status"), server_default=text("'observed'")
    )
    confidence: Mapped[Confidence] = mapped_column(_pg_enum(Confidence, "confidence_level"))
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("evidence.id"))
    rule_id: Mapped[str]
    proposed_by_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"))
    first_seen_at: Mapped[datetime] = _created()
    last_seen_at: Mapped[datetime] = _created()


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"
    worker_id: Mapped[str] = mapped_column(primary_key=True)
    version: Mapped[str]
    last_seen_at: Mapped[datetime] = _created()


class ApprovalDecision(enum.StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class Approval(Base):
    __tablename__ = "approvals"
    # Decisions are insert-only for every role; no RETURNING needed beyond the PK.
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    operation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("operations.id"))
    approver_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[ApprovalDecision] = mapped_column(
        _pg_enum(ApprovalDecision, "approval_decision")
    )
    reason: Mapped[str] = mapped_column(server_default=text("''"))
    scope_id_at_decision: Mapped[uuid.UUID] = mapped_column(ForeignKey("scopes.id"))
    decided_at: Mapped[datetime] = _created()


# --- Phase 4a: findings, attack paths, snapshots -------------------------------------


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(enum.StrEnum):
    HYPOTHESIS = "hypothesis"
    UNVERIFIED = "unverified"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


OPEN_STATUSES = (
    ValidationStatus.HYPOTHESIS,
    ValidationStatus.UNVERIFIED,
    ValidationStatus.VALIDATED,
)
HUMAN_STATUSES = (
    ValidationStatus.VALIDATED,
    ValidationStatus.FALSE_POSITIVE,
    ValidationStatus.REMEDIATED,
)


class FindingOrigin(enum.StrEnum):
    HUMAN = "human"
    DETERMINISTIC_CHECK = "deterministic_check"
    AGENT = "agent"


class AttackPathStatus(enum.StrEnum):
    HYPOTHESIS = "hypothesis"
    VALIDATED = "validated"
    REJECTED = "rejected"


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    number: Mapped[int] = mapped_column(server_default=text("0"))  # set by trigger
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    title: Mapped[str]
    description: Mapped[str] = mapped_column(server_default=text("''"))
    severity: Mapped[Severity] = mapped_column(_pg_enum(Severity, "severity"))
    confidence: Mapped[Confidence] = mapped_column(_pg_enum(Confidence, "confidence_level"))
    validation_status: Mapped[ValidationStatus] = mapped_column(
        _pg_enum(ValidationStatus, "validation_status")
    )
    origin: Mapped[FindingOrigin] = mapped_column(_pg_enum(FindingOrigin, "finding_origin"))
    check_id: Mapped[str | None]
    rule_id: Mapped[str | None]
    discovery_source: Mapped[str] = mapped_column(server_default=text("''"))
    impact: Mapped[str] = mapped_column(server_default=text("''"))
    remediation: Mapped[str] = mapped_column(server_default=text("''"))
    first_observed_at: Mapped[datetime] = _created()
    last_observed_at: Mapped[datetime] = _created()
    validated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    validated_at: Mapped[datetime | None]
    status_note: Mapped[str] = mapped_column(server_default=text("''"))
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    proposed_by_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"))
    guardian_review: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    note: Mapped[str] = mapped_column(server_default=text("''"))
    linked_by: Mapped[str]
    created_at: Mapped[datetime] = _created()


class AttackPath(Base):
    __tablename__ = "attack_paths"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    title: Mapped[str]
    narrative: Mapped[str] = mapped_column(server_default=text("''"))
    status: Mapped[AttackPathStatus] = mapped_column(
        _pg_enum(AttackPathStatus, "attack_path_status"), server_default=text("'hypothesis'")
    )
    confidence: Mapped[Confidence] = mapped_column(
        _pg_enum(Confidence, "confidence_level"), server_default=text("'low'")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None]
    review_note: Mapped[str] = mapped_column(server_default=text("''"))
    proposed_by_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"))
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class AttackPathStep(Base):
    __tablename__ = "attack_path_steps"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    attack_path_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_paths.id"))
    ordinal: Mapped[int]
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"))
    description: Mapped[str]


class AssessmentSnapshot(Base):
    __tablename__ = "assessment_snapshots"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    taken_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    taken_at: Mapped[datetime] = _created()
    ruleset_version: Mapped[str]
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_sha256: Mapped[bytes] = mapped_column(LargeBinary)


class AgentTaskStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id: Mapped[uuid.UUID] = _uuid_pk_col()
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("workspaces.id"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    agent: Mapped[str]
    parent_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id"))
    subject_finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"))
    subject_asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    objective: Mapped[str]
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    status: Mapped[AgentTaskStatus] = mapped_column(
        _pg_enum(AgentTaskStatus, "agent_task_status"), server_default=text("'queued'")
    )
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    error: Mapped[str | None]
    provider: Mapped[str | None]
    model: Mapped[str | None]
    prompt_version: Mapped[str | None]
    input_tokens: Mapped[int | None]
    output_tokens: Mapped[int | None]
    latency_ms: Mapped[int | None]
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    queued_at: Mapped[datetime] = _created()
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
