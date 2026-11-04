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
