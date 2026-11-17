"""SHIELD v3 phase 2 (migration 0025): sensors, standing response authorization, and the hard
safety invariants on blocks (the allow list, and the automatic tier's authorization limits).

No API exists yet; these drive the database directly as the app role under row-level security,
to prove the invariants hold whatever the application does. Expected-failure statements run
inside a savepoint (begin_nested) so only that statement rolls back, leaving the setup intact."""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError

from nightfall.core.db.models import Role
from tests.conftest import Factory


@contextmanager
def app_ctx(engine: Engine, workspace_id: uuid.UUID, user_id: uuid.UUID) -> Iterator[Connection]:
    """An app-role connection with workspace and user context set, rolled back at the end."""
    with engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('app.workspace_id', :w, false)"), {"w": str(workspace_id)}
        )
        conn.execute(text("SELECT set_config('app.user_id', :u, false)"), {"u": str(user_id)})
        try:
            yield conn
        finally:
            conn.rollback()


def _sensor(conn: Connection, ws: uuid.UUID, user: uuid.UUID, name: str = "lab") -> uuid.UUID:
    return conn.execute(
        text(
            "INSERT INTO shield_sensors "
            "(workspace_id, name, key_prefix, key_sha256, created_by_user_id) "
            "VALUES (:w, :n, 'nfs_abcd', :h, :u) RETURNING id"
        ),
        {"w": str(ws), "n": name, "h": uuid.uuid4().bytes + uuid.uuid4().bytes, "u": str(user)},
    ).scalar_one()


def _authorize(
    conn: Connection, ws: uuid.UUID, user: uuid.UUID, sensor_ids: list[uuid.UUID], max_s: int = 3600
) -> uuid.UUID:
    return conn.execute(
        text(
            "INSERT INTO shield_response_authorizations "
            "(workspace_id, sensor_ids, actions, max_block_seconds, default_block_seconds, "
            " authorized_by_user_id, expires_at) "
            "VALUES (:w, :s, ARRAY['block_ip'], :m, 3600, :u, "
            "now() + interval '30 days') RETURNING id"
        ),
        {"w": str(ws), "s": [str(s) for s in sensor_ids], "m": max_s, "u": str(user)},
    ).scalar_one()


def _block(
    conn: Connection,
    ws: uuid.UUID,
    sensor: uuid.UUID,
    target: str,
    *,
    auth: uuid.UUID,
    seconds: int = 1800,
) -> None:
    conn.execute(
        text(
            "INSERT INTO shield_blocks (workspace_id, sensor_id, target, tier, authorization_id, "
            " created_at, expires_at) "
            "VALUES (:w, :s, :t, 'automatic', :a, now(), now() + make_interval(secs => :sec))"
        ),
        {"w": str(ws), "s": str(sensor), "t": target, "a": str(auth), "sec": seconds},
    )


def _member(factory: Factory) -> tuple[uuid.UUID, uuid.UUID]:
    ws = factory.workspace()
    m = factory.member(ws, Role.OWNER)
    return ws, m.user.id


def test_rls_isolates_sensors_between_workspaces(app_engine: Engine, factory: Factory) -> None:
    ws_a, user_a = _member(factory)
    ws_b, user_b = _member(factory)
    with app_ctx(app_engine, ws_a, user_a) as conn:
        _sensor(conn, ws_a, user_a, "a")
        conn.commit()
    with app_ctx(app_engine, ws_b, user_b) as conn:
        assert conn.execute(text("SELECT count(*) FROM shield_sensors")).scalar_one() == 0


def test_allowlisted_target_cannot_be_blocked(app_engine: Engine, factory: Factory) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        sensor = _sensor(conn, ws, user)
        conn.execute(
            text(
                "INSERT INTO shield_block_allowlist (workspace_id, cidr, added_by_user_id) "
                "VALUES (:w, '10.0.0.0/24', :u)"
            ),
            {"w": str(ws), "u": str(user)},
        )
        auth = _authorize(conn, ws, user, [sensor])
        with pytest.raises(DBAPIError, match="allow list"):
            with conn.begin_nested():
                _block(conn, ws, sensor, "10.0.0.5/32", auth=auth)
        # A non-allow-listed address is accepted.
        _block(conn, ws, sensor, "203.0.113.5/32", auth=auth)
        assert conn.execute(text("SELECT count(*) FROM shield_blocks")).scalar_one() == 1


def test_automatic_block_requires_live_covering_authorization(
    app_engine: Engine, factory: Factory
) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        sensor = _sensor(conn, ws, user)
        other = _sensor(conn, ws, user, "other")
        auth = _authorize(conn, ws, user, [sensor], max_s=3600)

        with pytest.raises(DBAPIError, match="does not cover this sensor"):
            with conn.begin_nested():
                _block(conn, ws, other, "203.0.113.9/32", auth=auth)
        with pytest.raises(DBAPIError, match="longer than the authorization"):
            with conn.begin_nested():
                _block(conn, ws, sensor, "203.0.113.9/32", auth=auth, seconds=7200)
        # Within the limit and covered: allowed.
        _block(conn, ws, sensor, "203.0.113.9/32", auth=auth, seconds=1800)
        assert conn.execute(text("SELECT count(*) FROM shield_blocks")).scalar_one() == 1


def test_ended_authorization_cannot_back_a_block(app_engine: Engine, factory: Factory) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        sensor = _sensor(conn, ws, user)
        auth = _authorize(conn, ws, user, [sensor])
        conn.execute(
            text(
                "UPDATE shield_response_authorizations "
                "SET ended_at = now(), ended_reason = 'revoked' "
                "WHERE id = :a"
            ),
            {"a": str(auth)},
        )
        with pytest.raises(DBAPIError, match="live response authorization"):
            with conn.begin_nested():
                _block(conn, ws, sensor, "203.0.113.1/32", auth=auth)


def test_one_live_authorization_per_workspace(app_engine: Engine, factory: Factory) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        sensor = _sensor(conn, ws, user)
        _authorize(conn, ws, user, [sensor])
        with pytest.raises(DBAPIError):  # partial unique index: one live row per workspace
            with conn.begin_nested():
                _authorize(conn, ws, user, [sensor])


def test_response_authorization_is_insert_only_apart_from_ending(
    app_engine: Engine, factory: Factory
) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        sensor = _sensor(conn, ws, user)
        auth = _authorize(conn, ws, user, [sensor], max_s=3600)
        # Editing a limit is refused (the grant does not include the column).
        with pytest.raises(DBAPIError):
            with conn.begin_nested():
                conn.execute(
                    text(
                        "UPDATE shield_response_authorizations "
                        "SET max_block_seconds = 14400 WHERE id = :a"
                    ),
                    {"a": str(auth)},
                )
        # Ending it is allowed.
        conn.execute(
            text(
                "UPDATE shield_response_authorizations "
                "SET ended_at = now(), ended_reason = 'revoked' "
                "WHERE id = :a"
            ),
            {"a": str(auth)},
        )
        # An ended authorization is frozen.
        with pytest.raises(DBAPIError, match="ended response authorization cannot change"):
            with conn.begin_nested():
                conn.execute(
                    text(
                        "UPDATE shield_response_authorizations "
                        "SET ended_reason = 'expired' WHERE id = :a"
                    ),
                    {"a": str(auth)},
                )


def test_sensor_authenticate_returns_only_live_sensors(
    app_engine: Engine, factory: Factory
) -> None:
    ws, user = _member(factory)
    with app_ctx(app_engine, ws, user) as conn:
        key = uuid.uuid4().bytes + uuid.uuid4().bytes
        sid = conn.execute(
            text(
                "INSERT INTO shield_sensors "
                "(workspace_id, name, key_prefix, key_sha256, created_by_user_id) "
                "VALUES (:w, 'lab', 'nfs_abcd', :h, :u) RETURNING id"
            ),
            {"w": str(ws), "h": key, "u": str(user)},
        ).scalar_one()
        row = conn.execute(
            text("SELECT sensor_id, workspace_id FROM nf_sensor_authenticate(:h)"), {"h": key}
        ).one_or_none()
        assert row is not None and row.sensor_id == sid and row.workspace_id == ws
        conn.execute(
            text(
                "UPDATE shield_sensors SET revoked_at = now(), revoked_by_user_id = :u, "
                "revoked_reason = 'rotated' WHERE id = :s"
            ),
            {"u": str(user), "s": str(sid)},
        )
        assert (
            conn.execute(
                text("SELECT count(*) FROM nf_sensor_authenticate(:h)"), {"h": key}
            ).scalar_one()
            == 0
        )
