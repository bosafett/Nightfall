"""Authentication dependency: resolves the session cookie to a user."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select

from nightfall.config import get_settings
from nightfall.core.clock import utcnow
from nightfall.core.db.models import Session as DbSession
from nightfall.core.db.models import User
from nightfall.core.db.session import DB, set_user_context
from nightfall.core.errors import api_error
from nightfall.core.identity.security import hash_token
from nightfall.core.request_info import client_ip, user_agent

SESSION_COOKIE = "nf_session"
_TOUCH_INTERVAL = timedelta(seconds=60)


@dataclass
class AuthContext:
    user: User
    session: DbSession
    ip: str
    user_agent: str

    @property
    def mfa_satisfied(self) -> bool:
        return self.user.mfa_enabled and self.session.mfa_verified_at is not None


def _unauthenticated() -> Exception:
    return api_error(401, "not_authenticated", "Sign in to continue.")


def current_auth(request: Request, db: DB) -> AuthContext:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw or len(raw) > 128:
        raise _unauthenticated()
    s = db.scalar(select(DbSession).where(DbSession.token_sha256 == hash_token(raw)))
    now = utcnow()
    idle = timedelta(seconds=get_settings().session_idle_seconds)
    if s is None or s.revoked_at is not None or s.expires_at <= now or s.last_seen_at + idle <= now:
        raise _unauthenticated()
    user = db.get(User, s.user_id)
    if user is None or user.is_disabled:
        raise _unauthenticated()
    if now - s.last_seen_at >= _TOUCH_INTERVAL:
        s.last_seen_at = now
    set_user_context(db, user.id)
    return AuthContext(user=user, session=s, ip=client_ip(request), user_agent=user_agent(request))


current_auth._nf_authz = True  # type: ignore[attr-defined]  # marker checked by tests

Auth = Annotated[AuthContext, Depends(current_auth, scope="function")]
