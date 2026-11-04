"""Alembic runs as the schema owner (NIGHTFALL_MIGRATION_DATABASE_URL), never the API role."""

import os

from alembic import context
from sqlalchemy import create_engine, pool

from nightfall.config import _sqlalchemy_url


def _url() -> str:
    url = context.config.attributes.get("url") or os.environ.get("NIGHTFALL_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("NIGHTFALL_MIGRATION_DATABASE_URL is not set")
    return _sqlalchemy_url(url)


def run() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=None, transaction_per_migration=True
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("Offline migrations are not supported")
run()
