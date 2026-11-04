"""Database engine and per-request sessions.

One transaction per request. Tenant context (app.user_id / app.workspace_id) is set
with set_config(..., is_local => true), so it lives exactly as long as that
transaction and RLS policies read it. Code must not commit mid-request: the
dependency commits once, before the response is sent (scope="function").
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from nightfall.config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10)


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    with get_session_factory()() as db:
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise


DB = Annotated[Session, Depends(get_db, scope="function")]


def set_user_context(db: Session, user_id: uuid.UUID) -> None:
    db.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(user_id)})


def set_workspace_context(db: Session, workspace_id: uuid.UUID) -> None:
    db.execute(text("SELECT set_config('app.workspace_id', :v, true)"), {"v": str(workspace_id)})
