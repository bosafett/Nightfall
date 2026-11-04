"""Sign-in, sessions, MFA, password reset and invite acceptance."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Request, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from nightfall.config import get_settings
from nightfall.core.audit.writer import record, record_detached
from nightfall.core.clock import utcnow
from nightfall.core.db.models import (
    AuthToken,
    TokenPurpose,
    User,
    Workspace,
    WorkspaceMember,
)
from nightfall.core.db.models import Session as DbSession
from nightfall.core.db.session import DB, set_user_context, set_workspace_context
from nightfall.core.errors import api_error
from nightfall.core.identity import security
from nightfall.core.identity.deps import SESSION_COOKIE, Auth, AuthContext
from nightfall.core.identity.throttle import login_failures_by_account, login_failures_by_ip
from nightfall.core.request_info import client_ip, user_agent
from nightfall.core.schemas import (
    Email,
    MeOut,
    Model,
    Name,
    OkOut,
    Password,
    SessionInfo,
    Token,
    TotpCode,
    UserOut,
    WorkspaceSummary,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Routes reachable without a session. tests/test_route_security.py enforces that every
# other route declares an authentication or permission dependency.
PUBLIC_ROUTES = {
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/password-reset"),
    ("POST", "/api/auth/accept-invite"),
    ("POST", "/api/auth/invites/lookup"),
}


class LoginIn(Model):
    email: Email
    password: Password
    totp_code: TotpCode | None = None


class MfaSetupOut(Model):
    secret: str
    otpauth_uri: str


class MfaConfirmIn(Model):
    code: TotpCode


class PasswordResetIn(Model):
    token: Token
    new_password: Password


class InviteLookupIn(Model):
    token: Token


class InviteInfoOut(Model):
    workspace_name: str
    email: str
    role: str
    existing_account: bool


class AcceptInviteIn(Model):
    token: Token
    password: Password
    display_name: Name | None = None


class AcceptInviteOut(Model):
    workspace_id: str
    signed_in: bool


# --- helpers ------------------------------------------------------------------


def _bad_password(exc: security.PasswordPolicyError) -> Exception:
    return api_error(422, "weak_password", str(exc))


def _start_session(
    db: Session, response: Response, user: User, request: Request, *, mfa_verified: bool
) -> DbSession:
    settings = get_settings()
    raw, digest = security.new_token()
    now = utcnow()
    s = DbSession(
        user_id=user.id,
        token_sha256=digest,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=settings.session_absolute_seconds),
        mfa_verified_at=now if mfa_verified else None,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    db.add(s)
    response.set_cookie(
        SESSION_COOKIE,
        raw,
        max_age=settings.session_absolute_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return s


def _clear_cookie(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(
        SESSION_COOKIE, path="/", secure=s.cookie_secure, httponly=True, samesite="lax"
    )


def _me(db: Session, user: User, mfa_verified: bool) -> MeOut:
    rows = db.execute(
        select(Workspace, WorkspaceMember.role)
        .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
        .where(WorkspaceMember.user_id == user.id)
        .order_by(Workspace.name)
    ).all()
    return MeOut(
        user=UserOut.model_validate(user),
        session=SessionInfo(mfa_verified=mfa_verified),
        workspaces=[
            WorkspaceSummary(id=w.id, name=w.name, slug=w.slug, role=role) for w, role in rows
        ],
    )


def _revoke_all_sessions(db: Session, user_id: object) -> None:
    db.execute(
        update(DbSession)
        .where(DbSession.user_id == user_id, DbSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


def _valid_token(db: Session, raw: str, purpose: TokenPurpose) -> AuthToken | None:
    t = db.scalar(select(AuthToken).where(AuthToken.token_sha256 == security.hash_token(raw)))
    if (
        t is None
        or t.purpose is not purpose
        or t.used_at is not None
        or t.revoked_at is not None
        or t.expires_at <= utcnow()
    ):
        return None
    return t


def _decrypt_totp(user: User) -> str:
    if user.totp_secret_enc is None:
        raise api_error(400, "mfa_not_started", "Start two-factor setup first.")
    return security.decrypt_secret(get_settings().secret_key, user.totp_secret_enc, user.id)


# --- routes -------------------------------------------------------------------


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: DB) -> MeOut:
    ip, ua = client_ip(request), user_agent(request)
    acct_key, ip_key = f"acct:{body.email}", f"ip:{ip}"
    if login_failures_by_account.blocked(acct_key) or login_failures_by_ip.blocked(ip_key):
        record_detached("auth.login_throttled", data={"email": body.email}, ip=ip, user_agent=ua)
        raise api_error(429, "too_many_attempts", "Too many attempts. Try again in 15 minutes.")

    def fail(code: str, message: str, reason: str) -> Exception:
        login_failures_by_account.hit(acct_key)
        login_failures_by_ip.hit(ip_key)
        record_detached(
            "auth.login_failed",
            actor_id=user.id if user else None,
            data={"email": body.email, "reason": reason},
            ip=ip,
            user_agent=ua,
        )
        return api_error(401, code, message)

    user = db.scalar(select(User).where(User.email == body.email))
    password_ok = security.verify_password(user.password_hash if user else None, body.password)
    if user is None or not password_ok or user.is_disabled:
        raise fail("invalid_credentials", "Email or password is incorrect.", "credentials")

    if user.mfa_enabled:
        if body.totp_code is None:
            raise api_error(401, "mfa_required", "Enter the 6-digit code from your authenticator.")
        step = security.verify_totp(_decrypt_totp(user), body.totp_code, user.totp_last_step)
        if step is None:
            raise fail("invalid_mfa_code", "That code didn't work. Try the next one.", "totp")
        user.totp_last_step = step

    login_failures_by_account.reset(acct_key)
    if security.password_needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
    _start_session(db, response, user, request, mfa_verified=user.mfa_enabled)
    set_user_context(db, user.id)
    record(db, "auth.login", actor_id=user.id, ip=ip, user_agent=ua)
    return _me(db, user, mfa_verified=user.mfa_enabled)


@router.post("/logout", response_model=OkOut)
def logout(auth: Auth, response: Response, db: DB) -> OkOut:
    auth.session.revoked_at = utcnow()
    record(db, "auth.logout", actor_id=auth.user.id, ip=auth.ip, user_agent=auth.user_agent)
    _clear_cookie(response)
    return OkOut()


@router.post("/logout-all", response_model=OkOut)
def logout_all(auth: Auth, response: Response, db: DB) -> OkOut:
    _revoke_all_sessions(db, auth.user.id)
    record(db, "auth.logout_all", actor_id=auth.user.id, ip=auth.ip, user_agent=auth.user_agent)
    _clear_cookie(response)
    return OkOut()


@router.get("/me", response_model=MeOut)
def me(auth: Auth, db: DB) -> MeOut:
    return _me(db, auth.user, mfa_verified=auth.mfa_satisfied)


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(auth: Auth, db: DB) -> MfaSetupOut:
    user = auth.user
    if user.mfa_enabled:
        raise api_error(409, "mfa_already_enabled", "Two-factor is already on for this account.")
    secret = security.new_totp_secret()
    user.totp_secret_enc = security.encrypt_secret(get_settings().secret_key, secret, user.id)
    record(db, "auth.mfa_setup_started", actor_id=user.id, ip=auth.ip, user_agent=auth.user_agent)
    return MfaSetupOut(secret=secret, otpauth_uri=security.totp_uri(secret, user.email))


@router.post("/mfa/confirm", response_model=MeOut)
def mfa_confirm(body: MfaConfirmIn, auth: Auth, db: DB) -> MeOut:
    user = auth.user
    if user.mfa_enabled:
        raise api_error(409, "mfa_already_enabled", "Two-factor is already on for this account.")
    if user.totp_secret_enc is None:
        raise api_error(400, "mfa_not_started", "Start two-factor setup first.")
    key = f"mfa:{user.id}"
    if login_failures_by_account.blocked(key):
        raise api_error(429, "too_many_attempts", "Too many attempts. Try again in 15 minutes.")
    step = security.verify_totp(_decrypt_totp(user), body.code, user.totp_last_step)
    if step is None:
        login_failures_by_account.hit(key)
        raise api_error(400, "invalid_mfa_code", "That code didn't work. Try the next one.")
    user.mfa_enabled = True
    user.totp_last_step = step
    auth.session.mfa_verified_at = utcnow()
    record(db, "auth.mfa_enabled", actor_id=user.id, ip=auth.ip, user_agent=auth.user_agent)
    return _me(db, user, mfa_verified=True)


@router.post("/password-reset", response_model=OkOut)
def password_reset(body: PasswordResetIn, request: Request, db: DB) -> OkOut:
    t = _valid_token(db, body.token, TokenPurpose.PASSWORD_RESET)
    if t is None or t.user_id is None:
        raise api_error(
            400, "invalid_or_expired_token", "This reset link is invalid or has expired."
        )
    try:
        security.check_password_policy(body.new_password)
    except security.PasswordPolicyError as exc:
        raise _bad_password(exc) from exc
    user = db.get(User, t.user_id)
    if user is None or user.is_disabled:
        raise api_error(
            400, "invalid_or_expired_token", "This reset link is invalid or has expired."
        )
    user.password_hash = security.hash_password(body.new_password)
    t.used_at = utcnow()
    _revoke_all_sessions(db, user.id)
    record(
        db,
        "auth.password_reset_completed",
        actor_id=user.id,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    return OkOut()


# POST with the token in the body (not the URL), so it never lands in access logs.
@router.post("/invites/lookup", response_model=InviteInfoOut)
def invite_info(body: InviteLookupIn, db: DB) -> InviteInfoOut:
    t = _valid_token(db, body.token, TokenPurpose.INVITE)
    if t is None or t.workspace_id is None or t.email is None or t.role is None:
        raise api_error(404, "invalid_or_expired_token", "This invite is invalid or has expired.")
    set_workspace_context(db, t.workspace_id)
    ws = db.get(Workspace, t.workspace_id)
    if ws is None:
        raise api_error(404, "invalid_or_expired_token", "This invite is invalid or has expired.")
    existing = db.scalar(select(User.id).where(User.email == t.email)) is not None
    return InviteInfoOut(
        workspace_name=ws.name, email=t.email, role=t.role.value, existing_account=existing
    )


@router.post("/accept-invite", response_model=AcceptInviteOut)
def accept_invite(
    body: AcceptInviteIn, request: Request, response: Response, db: DB
) -> AcceptInviteOut:
    ip, ua = client_ip(request), user_agent(request)
    t = _valid_token(db, body.token, TokenPurpose.INVITE)
    if t is None or t.workspace_id is None or t.email is None or t.role is None:
        raise api_error(400, "invalid_or_expired_token", "This invite is invalid or has expired.")

    user = db.scalar(select(User).where(User.email == t.email))
    signed_in = False
    if user is not None:
        # Existing account: prove ownership with the password. No session is created
        # here, so an account with two-factor still has to sign in normally.
        acct_key = f"acct:{user.email}"
        if login_failures_by_account.blocked(acct_key):
            raise api_error(429, "too_many_attempts", "Too many attempts. Try again in 15 minutes.")
        if user.is_disabled or not security.verify_password(user.password_hash, body.password):
            login_failures_by_account.hit(acct_key)
            record_detached(
                "auth.invite_accept_failed",
                actor_id=user.id,
                ip=ip,
                user_agent=ua,
                data={"email": t.email},
            )
            raise api_error(401, "invalid_credentials", "Password is incorrect for this account.")
    else:
        if body.display_name is None:
            raise api_error(422, "display_name_required", "Add your name.")
        try:
            security.check_password_policy(body.password)
        except security.PasswordPolicyError as exc:
            raise _bad_password(exc) from exc
        user = User(
            email=t.email,
            display_name=body.display_name,
            password_hash=security.hash_password(body.password),
        )
        db.add(user)
        db.flush()
        signed_in = True

    set_user_context(db, user.id)
    set_workspace_context(db, t.workspace_id)
    already = db.scalar(
        select(WorkspaceMember.id).where(
            WorkspaceMember.workspace_id == t.workspace_id, WorkspaceMember.user_id == user.id
        )
    )
    t.used_at = utcnow()
    if already is None:
        db.add(WorkspaceMember(workspace_id=t.workspace_id, user_id=user.id, role=t.role))
    record(
        db,
        "member.joined",
        actor_id=user.id,
        workspace_id=t.workspace_id,
        entity_type="user",
        entity_id=user.id,
        data={"role": t.role.value, "already_member": already is not None},
        ip=ip,
        user_agent=ua,
    )
    if signed_in:
        _start_session(db, response, user, request, mfa_verified=False)
    return AcceptInviteOut(workspace_id=str(t.workspace_id), signed_in=signed_in)


__all__ = ["router", "PUBLIC_ROUTES", "AuthContext"]
