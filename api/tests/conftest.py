"""Integration tests run against a real Postgres (no DB mocking).

Defaults match the local dev cluster; CI overrides via environment variables:
  NIGHTFALL_TEST_DATABASE_URL            app role   (subject to RLS)
  NIGHTFALL_TEST_MIGRATION_DATABASE_URL  owner role (migrations, fixtures)
"""

from __future__ import annotations

import base64
import os
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta

APP_URL = os.environ.get(
    "NIGHTFALL_TEST_DATABASE_URL",
    "postgresql://nightfall_app:app_dev_only@127.0.0.1:5432/nightfall_test",
)
OWNER_URL = os.environ.get(
    "NIGHTFALL_TEST_MIGRATION_DATABASE_URL",
    "postgresql://nightfall_owner:owner_dev_only@127.0.0.1:5432/nightfall_test",
)
WORKER_URL = os.environ.get(
    "NIGHTFALL_TEST_WORKER_DATABASE_URL",
    "postgresql://nightfall_worker:worker_dev_only@127.0.0.1:5432/nightfall_test",
)
ORIGIN = "http://nightfall.test"
BLACKSITE_URL = os.environ.get(
    "NIGHTFALL_TEST_BLACKSITE_DATABASE_URL",
    "postgresql://nightfall_blacksite:blacksite_dev_only@127.0.0.1:5432/nightfall_test",
)
BLACKSITE_ORIGIN = "http://127.0.0.1:8443"
BLACKSITE_REVIEW = "REV-TEST-1"
EVIDENCE_DIR = tempfile.mkdtemp(prefix="nightfall-evidence-")

os.environ.update(
    NIGHTFALL_DATABASE_URL=APP_URL,
    NIGHTFALL_MIGRATION_DATABASE_URL=OWNER_URL,
    NIGHTFALL_SECRET_KEY=base64.b64encode(b"\x01" * 32).decode(),
    NIGHTFALL_PUBLIC_ORIGIN=ORIGIN,
    NIGHTFALL_COOKIE_SECURE="false",
    NIGHTFALL_EVIDENCE_DIR=EVIDENCE_DIR,
    NIGHTFALL_WORKER_DATABASE_URL=WORKER_URL,
    NIGHTFALL_COLLECTOR_MODE="fixture",
)

import pyotp  # noqa: E402
import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine, create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from nightfall.config import _sqlalchemy_url, get_settings  # noqa: E402
from nightfall.core.clock import utcnow  # noqa: E402
from nightfall.core.db.models import Role, User, Workspace, WorkspaceMember  # noqa: E402
from nightfall.core.db.models import Session as DbSession  # noqa: E402
from nightfall.core.identity import security, throttle  # noqa: E402
from nightfall.core.identity.deps import SESSION_COOKIE  # noqa: E402
from nightfall.main import create_app  # noqa: E402

PASSWORD = "correct horse battery staple"
TABLES = (
    "agent_tasks, approvals, asset_relationships, evidence, evidence_blobs, operations, "
    "rate_limit_hits, "
    "scope_exclusions, "
    "scope_targets, "
    "scopes, "
    "assets, worker_heartbeats, audit_events, projects, organizations, auth_tokens, "
    "workspace_members, workspaces, sessions, users"
)


def alembic_config() -> Config:
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option(
        "script_location", os.path.join(os.path.dirname(__file__), "..", "migrations")
    )
    cfg.attributes["url"] = OWNER_URL
    return cfg


@pytest.fixture(scope="session", autouse=True)
def migrated() -> None:
    cfg = alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def owner_engine() -> Engine:
    return create_engine(_sqlalchemy_url(OWNER_URL))


@pytest.fixture(scope="session")
def app_engine() -> Engine:
    return create_engine(_sqlalchemy_url(APP_URL))


@pytest.fixture(autouse=True)
def clean(owner_engine: Engine) -> Iterator[None]:
    with owner_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))
    for limiter in (
        throttle.login_failures_by_account,
        throttle.login_failures_by_ip,
        throttle.mutations_by_ip,
    ):
        limiter.clear()
    yield


@pytest.fixture
def owner_db(owner_engine: Engine) -> Iterator[Session]:
    """Schema-owner session (bypasses RLS) for arranging fixtures and inspecting results."""
    with Session(owner_engine, expire_on_commit=False) as s:
        yield s


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(), base_url=ORIGIN, headers={"Origin": ORIGIN}) as c:
        yield c


@pytest.fixture
def blacksite_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("NIGHTFALL_BLACKSITE_ENABLED", "true")
    monkeypatch.setenv("NIGHTFALL_BLACKSITE_REVIEW_REF", BLACKSITE_REVIEW)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


_blacksite_engine = None


def blacksite_client(peer: str = "127.0.0.1", base_url: str = BLACKSITE_ORIGIN) -> TestClient:
    """The host-only BLACKSITE app, connected as nightfall_blacksite, seen from `peer`."""
    global _blacksite_engine
    from nightfall.blacksite.app import create_blacksite_app
    from nightfall.core.db.session import get_db

    if _blacksite_engine is None:
        _blacksite_engine = create_engine(_sqlalchemy_url(BLACKSITE_URL))
    engine = _blacksite_engine

    def db() -> Iterator[Session]:
        with Session(engine, expire_on_commit=False) as s:
            try:
                yield s
                s.commit()
            except BaseException:
                s.rollback()
                raise

    app = create_blacksite_app()
    app.dependency_overrides[get_db] = db
    return TestClient(
        app, base_url=base_url, headers={"Origin": BLACKSITE_ORIGIN}, client=(peer, 50123)
    )


@pytest.fixture
def blacksite(blacksite_on: None) -> Iterator[TestClient]:
    with blacksite_client() as c:
        yield c


@dataclass
class Member:
    user: User
    workspace_id: uuid.UUID
    member_id: uuid.UUID
    role: Role
    totp_secret: str | None
    token: str | None = None  # session token when signed in via sign_in()

    def cookies(self) -> dict[str, str]:
        assert self.token
        return {SESSION_COOKIE: self.token}


class Factory:
    def __init__(self, db: Session) -> None:
        self.db = db

    def workspace(self, name: str = "Acme Security") -> uuid.UUID:
        ws = Workspace(name=name, slug=f"ws-{uuid.uuid4().hex[:10]}")
        self.db.add(ws)
        self.db.commit()
        return ws.id

    def member(
        self,
        workspace_id: uuid.UUID,
        role: Role,
        *,
        mfa: bool | None = None,
        email: str | None = None,
    ) -> Member:
        mfa = role in (Role.OWNER, Role.ADMIN, Role.OPERATOR) if mfa is None else mfa
        email = email or f"{role.value}-{uuid.uuid4().hex[:8]}@example.test"
        user = self.db.query(User).filter_by(email=email).one_or_none()
        secret = None
        if user is None:
            user = User(
                email=email,
                display_name=role.value.title(),
                password_hash=security.hash_password(PASSWORD),
            )
            self.db.add(user)
            self.db.flush()
            if mfa:
                secret = security.new_totp_secret()
                user.totp_secret_enc = security.encrypt_secret(
                    get_settings().secret_key, secret, user.id
                )
                user.mfa_enabled = True
        m = WorkspaceMember(workspace_id=workspace_id, user_id=user.id, role=role)
        self.db.add(m)
        self.db.commit()
        return Member(
            user=user, workspace_id=workspace_id, member_id=m.id, role=role, totp_secret=secret
        )

    def sign_in(self, m: Member, *, mfa_verified: bool | None = None) -> Member:
        """Create a session directly (the real sign-in flow has its own tests)."""
        raw, digest = security.new_token()
        now = utcnow()
        verified = m.user.mfa_enabled if mfa_verified is None else mfa_verified
        self.db.add(
            DbSession(
                user_id=m.user.id,
                token_sha256=digest,
                last_seen_at=now,
                expires_at=now + timedelta(days=1),
                mfa_verified_at=now if verified else None,
            )
        )
        self.db.commit()
        m.token = raw
        return m


@pytest.fixture
def factory(owner_db: Session) -> Factory:
    return Factory(owner_db)


def current_code(secret: str) -> str:
    return str(pyotp.TOTP(secret).now())


def audit_actions(db: Session) -> list[str]:
    db.expire_all()
    return [r[0] for r in db.execute(text("SELECT action FROM audit_events ORDER BY occurred_at"))]


def use(client: TestClient, m: Member) -> TestClient:
    """Switch the client to m's session."""
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, m.token or "")
    return client
