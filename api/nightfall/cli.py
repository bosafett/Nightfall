"""nightfall-admin: host-operator commands. Connects as the schema owner
(NIGHTFALL_MIGRATION_DATABASE_URL), so only someone with shell access to the host can run it.

  nightfall-admin create-owner --email E --name N --workspace-name W --workspace-slug S
  nightfall-admin reset-password --email E
  nightfall-admin reset-mfa --email E
  nightfall-admin bootstrap-roles    create/update the API and worker database roles
  nightfall-admin bootstrap-owner    create the first owner if no account exists yet

Passwords are read interactively, or from NIGHTFALL_ADMIN_PASSWORD for automation.

The bootstrap commands are for hosts without a shell (start-up scripts). bootstrap-roles
reads NIGHTFALL_APP_DB_PASSWORD and NIGHTFALL_WORKER_DB_PASSWORD and needs CREATEROLE.
bootstrap-owner reads NIGHTFALL_BOOTSTRAP_OWNER_EMAIL / _NAME / _WORKSPACE and
NIGHTFALL_ADMIN_PASSWORD, and does nothing once any account exists.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any

from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session

from nightfall.config import _sqlalchemy_url
from nightfall.core.audit.writer import record
from nightfall.core.clock import utcnow
from nightfall.core.db.models import ActorType, Role, User, Workspace, WorkspaceMember
from nightfall.core.db.models import Session as DbSession
from nightfall.core.identity.security import (
    PasswordPolicyError,
    check_password_policy,
    hash_password,
)
from nightfall.core.schemas import _email


def _db() -> Session:
    url = os.environ.get("NIGHTFALL_MIGRATION_DATABASE_URL")
    if not url:
        sys.exit("NIGHTFALL_MIGRATION_DATABASE_URL is not set")
    return Session(create_engine(_sqlalchemy_url(url)))


def _password() -> str:
    pw = os.environ.get("NIGHTFALL_ADMIN_PASSWORD")
    if pw is None:
        pw = getpass.getpass("New password: ")
        if getpass.getpass("Repeat password: ") != pw:
            sys.exit("Passwords don't match.")
    try:
        check_password_policy(pw)
    except PasswordPolicyError as exc:
        sys.exit(str(exc))
    return pw


def _user(db: Session, email: str) -> User:
    user = db.scalar(select(User).where(User.email == _email(email)))
    if user is None:
        sys.exit(f"No account for {email}.")
    return user


def _revoke_sessions(db: Session, user: User) -> None:
    db.execute(
        update(DbSession)
        .where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )


def create_owner(a: argparse.Namespace) -> None:
    with _db() as db:
        email = _email(a.email)
        if db.scalar(select(User.id).where(User.email == email)):
            sys.exit(f"An account for {email} already exists.")
        user = User(
            email=email, display_name=a.name.strip(), password_hash=hash_password(_password())
        )
        ws = Workspace(name=a.workspace_name.strip(), slug=a.workspace_slug)
        db.add_all([user, ws])
        db.flush()
        db.add(WorkspaceMember(workspace_id=ws.id, user_id=user.id, role=Role.OWNER))
        record(
            db,
            "admin.owner_created",
            actor_type=ActorType.SYSTEM,
            workspace_id=ws.id,
            entity_type="user",
            entity_id=user.id,
            data={"email": email},
        )
        db.commit()
        print(f"Created {email} as owner of '{ws.name}'.")
        print("Two-factor setup is required at first sign-in.")


def reset_password(a: argparse.Namespace) -> None:
    with _db() as db:
        user = _user(db, a.email)
        user.password_hash = hash_password(_password())
        _revoke_sessions(db, user)
        record(
            db,
            "admin.password_reset",
            actor_type=ActorType.SYSTEM,
            entity_type="user",
            entity_id=user.id,
        )
        db.commit()
        print(f"Password reset for {user.email}. All sessions signed out.")


def reset_mfa(a: argparse.Namespace) -> None:
    with _db() as db:
        user = _user(db, a.email)
        user.mfa_enabled = False
        user.totp_secret_enc = None
        user.totp_last_step = None
        _revoke_sessions(db, user)
        record(
            db,
            "admin.mfa_reset",
            actor_type=ActorType.SYSTEM,
            entity_type="user",
            entity_id=user.id,
        )
        db.commit()
        print(f"Two-factor removed for {user.email}. They'll set it up again at next sign-in.")


ROLES = {
    "nightfall_app": "NIGHTFALL_APP_DB_PASSWORD",
    "nightfall_worker": "NIGHTFALL_WORKER_DB_PASSWORD",
}


# Optional roles (migrations 0010, 0013): they can only log in when their password is
# configured; without it the role exists but is NOLOGIN.
OPTIONAL_ROLES = {
    "nightfall_lab_worker": ("NIGHTFALL_LAB_WORKER_DB_PASSWORD", "lab worker role"),  # noqa: S105
    "nightfall_blacksite": ("NIGHTFALL_BLACKSITE_DB_PASSWORD", "BLACKSITE role"),  # noqa: S105
}


def _optional_role(db: Session, conn: Any, role: str) -> None:
    from psycopg import sql

    var, label = OPTIONAL_ROLES[role]
    pw = os.environ.get(var, "")
    if pw and len(pw) < 24:
        sys.exit(f"{var} must be a random value of at least 24 characters.")
    exists = db.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role})
    if pw:
        stmt = sql.SQL(
            "ALTER ROLE {} LOGIN PASSWORD {}"
            if exists
            else "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
        ).format(sql.Identifier(role), sql.Literal(pw))
    else:
        stmt = sql.SQL(
            "ALTER ROLE {} NOLOGIN"
            if exists
            else "CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
        ).format(sql.Identifier(role))
    with conn.cursor() as cur:
        cur.execute(stmt)
    print(f"{label}: {'login enabled' if pw else 'no login (not configured)'}")


def bootstrap_roles(a: argparse.Namespace) -> None:
    from psycopg import sql

    passwords = {}
    for role, var in ROLES.items():
        pw = os.environ.get(var, "")
        if len(pw) < 24:
            sys.exit(f"{var} must be set to a random value of at least 24 characters.")
        passwords[role] = pw
    with _db() as db:
        conn = db.connection().connection.driver_connection
        if conn is None:
            sys.exit("No database connection.")
        for role, pw in passwords.items():
            exists = db.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role})
            if exists:
                # Only the password: restating SUPERUSER/BYPASSRLS needs superuser rights.
                stmt = sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(pw)
                )
            else:
                stmt = sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS NOCREATEDB "
                    "NOCREATEROLE"
                ).format(sql.Identifier(role), sql.Literal(pw))
            with conn.cursor() as cur:
                cur.execute(stmt)
            print(f"{'updated' if exists else 'created'} role {role}")
        for role in OPTIONAL_ROLES:
            _optional_role(db, conn, role)
        # Isolation depends on these roles being unable to bypass row-level security.
        unsafe = db.scalars(
            text(
                "SELECT rolname FROM pg_roles WHERE rolname = ANY(:r) "
                "AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb)"
            ),
            {"r": [*ROLES, *OPTIONAL_ROLES]},
        ).all()
        if unsafe:
            sys.exit(f"Refusing to start: {', '.join(unsafe)} can bypass isolation.")
        db.commit()


def bootstrap_owner(a: argparse.Namespace) -> None:
    email = os.environ.get("NIGHTFALL_BOOTSTRAP_OWNER_EMAIL", "").strip()
    if not email:
        print("NIGHTFALL_BOOTSTRAP_OWNER_EMAIL not set; no owner created.")
        return
    with _db() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            print("Accounts already exist; bootstrap owner skipped.")
            return
    create_owner(
        argparse.Namespace(
            email=email,
            name=os.environ.get("NIGHTFALL_BOOTSTRAP_OWNER_NAME", "Owner"),
            workspace_name=os.environ.get("NIGHTFALL_BOOTSTRAP_WORKSPACE", "NIGHTFALL"),
            workspace_slug="main",
        )
    )


def profile_b_keygen(a: argparse.Namespace) -> None:
    """A key pair for sealing Profile B test credentials. Needs no database."""
    from nightfall.blackops.profile_b import generate_keypair

    public, private = generate_keypair()
    print("Set on the API (Vercel) and on the self-hosted worker:")
    print(f"  NIGHTFALL_PROFILE_B_PUBLIC_KEY={public}")
    print("Set on the self-hosted worker ONLY (never on the hosted platform):")
    print(f"  NIGHTFALL_PROFILE_B_PRIVATE_KEY={private}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="nightfall-admin")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-owner")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--workspace-name", required=True)
    c.add_argument("--workspace-slug", required=True)
    c.set_defaults(fn=create_owner)
    sub.add_parser("bootstrap-roles").set_defaults(fn=bootstrap_roles)
    sub.add_parser("bootstrap-owner").set_defaults(fn=bootstrap_owner)
    sub.add_parser("profile-b-keygen").set_defaults(fn=profile_b_keygen)
    for name, fn in (("reset-password", reset_password), ("reset-mfa", reset_mfa)):
        s = sub.add_parser(name)
        s.add_argument("--email", required=True)
        s.set_defaults(fn=fn)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
