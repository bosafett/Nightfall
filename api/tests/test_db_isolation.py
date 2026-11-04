"""Row-level security and grants, exercised directly as the API database role."""

import uuid

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from tests.conftest import Factory, alembic_config


def _org(db: Session, ws: uuid.UUID, name: str) -> uuid.UUID:
    return db.execute(
        text("INSERT INTO organizations (workspace_id, name) VALUES (:w, :n) RETURNING id"),
        {"w": ws, "n": name},
    ).scalar_one()


@pytest.fixture
def two_tenants(factory: Factory, owner_db: Session) -> tuple[uuid.UUID, uuid.UUID]:
    a, b = factory.workspace("A"), factory.workspace("B")
    _org(owner_db, a, "Org A")
    _org(owner_db, b, "Org B")
    owner_db.commit()
    return a, b


def test_no_context_sees_nothing(app_engine: Engine, two_tenants: object) -> None:
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM organizations")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM workspaces")).scalar() == 0
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar() == 0


def test_context_limits_rows_to_tenant(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, _ = two_tenants
    with app_engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(a)})
        names = conn.execute(text("SELECT name FROM organizations")).scalars().all()
    assert names == ["Org A"]


def test_cannot_write_into_other_tenant(
    app_engine: Engine, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, b = two_tenants
    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.workspace_id', :w, true)"), {"w": str(a)})
            conn.execute(
                text("INSERT INTO organizations (workspace_id, name) VALUES (:w, 'x')"),
                {"w": b},
            )


@pytest.mark.parametrize(
    "stmt", ["UPDATE audit_events SET action = 'x'", "DELETE FROM audit_events"]
)
def test_audit_log_is_append_only(app_engine: Engine, stmt: str) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text(stmt))


def test_app_role_cannot_create_workspaces_or_delete_orgs(app_engine: Engine) -> None:
    with pytest.raises((ProgrammingError, DBAPIError)), app_engine.begin() as conn:
        conn.execute(text("INSERT INTO workspaces (name, slug) VALUES ('x', 'x-1')"))
    with pytest.raises(ProgrammingError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text("DELETE FROM organizations"))


def test_project_org_must_share_workspace(
    owner_db: Session, two_tenants: tuple[uuid.UUID, uuid.UUID]
) -> None:
    a, b = two_tenants
    org_b = owner_db.execute(
        text("SELECT id FROM organizations WHERE workspace_id = :b"), {"b": b}
    ).scalar_one()
    with pytest.raises(IntegrityError):
        owner_db.execute(
            text(
                "INSERT INTO projects (workspace_id, organization_id, name, assessment_type) "
                "VALUES (:a, :o, 'p', 'reconnaissance')"
            ),
            {"a": a, "o": org_b},
        )
        owner_db.flush()
    owner_db.rollback()


def test_migrations_roundtrip() -> None:
    cfg = alembic_config()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
