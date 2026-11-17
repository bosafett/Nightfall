"""SHIELD v3 phase 1: sign-in alerts (migration 0024; design
docs/designs/2026-11-shield-v3-intrusion-detection.md §5).

The sign-in code calls `raise_alert` when it sees an attack on a known account. Alerts are
written by the database function nf_record_sign_in_alert in a separate transaction, so they
survive the failed request's rollback. Blocking is unchanged: the throttles in
core/identity/throttle.py already lock an account or an address; these alerts make that
visible to the account's user and their workspace admins.

Routes: the account's own alerts (`/api/auth/sign-in-alerts`, acknowledge), and the alerts of a
workspace's members for its owners and admins (`/api/workspaces/{id}/sign-in-alerts`).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import or_, select, text

from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import SignInAlert, User, WorkspaceMember
from nightfall.core.db.session import DB, get_session_factory
from nightfall.core.errors import not_found
from nightfall.core.identity.deps import Auth
from nightfall.core.schemas import Model
from nightfall.core.tenancy.deps import WorkspaceContext, ws_permission
from nightfall.core.tenancy.permissions import Permission

log = logging.getLogger(__name__)

Kind = Literal["signin.locked", "signin.password_known", "signin.stepup_locked"]

TEXT: dict[str, tuple[str, str]] = {
    "signin.locked": (
        "Account locked after repeated failed sign-ins",
        "Someone failed to sign in to this account too many times, so sign-in was paused for 15 "
        "minutes. If this wasn't you, someone may be guessing the password: use a long, unique "
        "one and keep two-factor on.",
    ),
    "signin.password_known": (
        "Correct password, wrong two-factor code",
        "Someone entered this account's correct password but couldn't pass two-factor, which "
        "stopped the sign-in. If this wasn't you, change the password now.",
    ),
    "signin.stepup_locked": (
        "Two-factor check failed repeatedly in a signed-in session",
        "A session signed in to this account failed the two-factor check too many times. If this "
        "wasn't you, sign out everywhere and change the password.",
    ),
}

# Shown alongside alerts: acknowledged ones drop off after this long.
KEEP_ACKNOWLEDGED = timedelta(days=30)


def raise_alert(user_id: uuid.UUID, kind: Kind, ip: str | None) -> None:
    """Record or repeat an alert. Never raises: an alert must not change the sign-in answer."""
    try:
        with get_session_factory()() as db:
            db.execute(
                text("SELECT nf_record_sign_in_alert(:u, :k, :a)"),
                {"u": user_id, "k": kind, "a": ip or ""},
            )
            db.commit()
    except Exception:
        log.exception("failed to record sign-in alert %s", kind)


class SignInAlertOut(Model):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    kind: str
    severity: str
    title: str
    detail: str
    count: int
    addresses: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    state: str


def _out(a: SignInAlert, email: str) -> SignInAlertOut:
    title, detail = TEXT.get(a.kind, (a.kind, ""))
    return SignInAlertOut(
        id=a.id,
        user_id=a.user_id,
        email=email,
        kind=a.kind,
        severity=a.severity.value,
        title=title,
        detail=detail,
        count=a.count,
        addresses=list(a.addresses),
        first_seen_at=a.first_seen_at,
        last_seen_at=a.last_seen_at,
        state=a.state,
    )


def _recent() -> object:
    return or_(
        SignInAlert.state == "open",
        SignInAlert.acknowledged_at > utcnow() - KEEP_ACKNOWLEDGED,
    )


own_router = APIRouter(prefix="/api/auth", tags=["auth"])
ws_router = APIRouter(prefix="/api/workspaces/{workspace_id}", tags=["shield"])


@own_router.get("/sign-in-alerts", response_model=list[SignInAlertOut])
def my_alerts(auth: Auth, db: DB) -> list[SignInAlertOut]:
    rows = db.scalars(
        select(SignInAlert)
        .where(SignInAlert.user_id == auth.user.id, _recent())  # type: ignore[arg-type]
        .order_by(SignInAlert.last_seen_at.desc())
    ).all()
    return [_out(a, auth.user.email) for a in rows]


@own_router.post("/sign-in-alerts/{alert_id}/acknowledge", response_model=SignInAlertOut)
def acknowledge(alert_id: uuid.UUID, auth: Auth, db: DB) -> SignInAlertOut:
    a = db.get(SignInAlert, alert_id)
    if a is None or a.user_id != auth.user.id:
        raise not_found("sign-in alert")
    if a.state == "open":
        a.state = "acknowledged"
        a.acknowledged_at = utcnow()
        record(
            db,
            "auth.sign_in_alert_acknowledged",
            actor_id=auth.user.id,
            entity_type="sign_in_alert",
            entity_id=a.id,
            data={"kind": a.kind},
            ip=auth.ip,
            user_agent=auth.user_agent,
        )
    return _out(a, auth.user.email)


@ws_router.get("/sign-in-alerts", response_model=list[SignInAlertOut])
def member_alerts(
    db: DB, ctx: WorkspaceContext = ws_permission(Permission.MEMBERS_MANAGE)
) -> list[SignInAlertOut]:
    members = select(WorkspaceMember.user_id).where(
        WorkspaceMember.workspace_id == ctx.workspace_id
    )
    rows = db.execute(
        select(SignInAlert, User.email)
        .join(User, User.id == SignInAlert.user_id)
        .where(SignInAlert.user_id.in_(members), _recent())  # type: ignore[arg-type]
        .order_by(SignInAlert.state.desc(), SignInAlert.last_seen_at.desc())
        .limit(200)
    ).all()
    return [_out(a, email) for a, email in rows]
