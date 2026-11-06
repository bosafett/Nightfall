"""Shared request/response models."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from nightfall.core.db.models import Role


def _email(value: str) -> str:
    value = value.strip().lower()
    local, sep, domain = value.partition("@")
    if not sep or not local or "." not in domain or " " in value or len(value) > 320:
        raise ValueError("Enter a valid email address.")
    return value


Email = Annotated[str, AfterValidator(_email)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Password = Annotated[str, Field(min_length=1, max_length=1024)]
TotpCode = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]
Token = Annotated[str, Field(min_length=20, max_length=128)]


class Model(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")


class UserOut(Model):
    id: uuid.UUID
    email: str
    display_name: str
    mfa_enabled: bool


class WorkspaceSummary(Model):
    id: uuid.UUID
    name: str
    slug: str
    role: Role
    approval_policy: Literal["single_operator", "two_person"] = "single_operator"


class SessionInfo(Model):
    mfa_verified: bool


class MeOut(Model):
    user: UserOut
    session: SessionInfo
    workspaces: list[WorkspaceSummary]


class OkOut(Model):
    ok: bool = True
