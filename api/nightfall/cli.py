"""nightfall-admin: host-operator commands. Connects as the schema owner
(NIGHTFALL_MIGRATION_DATABASE_URL), so only someone with shell access to the host can run it.

  nightfall-admin create-owner --email E --name N --workspace-name W --workspace-slug S
  nightfall-admin reset-password --email E
  nightfall-admin reset-mfa --email E

Passwords are read interactively, or from NIGHTFALL_ADMIN_PASSWORD for automation.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import create_engine, select, update
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


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="nightfall-admin")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-owner")
    c.add_argument("--email", required=True)
    c.add_argument("--name", required=True)
    c.add_argument("--workspace-name", required=True)
    c.add_argument("--workspace-slug", required=True)
    c.set_defaults(fn=create_owner)
    for name, fn in (("reset-password", reset_password), ("reset-mfa", reset_mfa)):
        s = sub.add_parser(name)
        s.add_argument("--email", required=True)
        s.set_defaults(fn=fn)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
