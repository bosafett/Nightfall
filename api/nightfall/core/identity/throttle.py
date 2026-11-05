"""Sliding-window rate limits.

Two backends, chosen by NIGHTFALL_RATE_LIMIT_BACKEND:
  memory    in-process; correct only while a single API process serves all requests.
  postgres  table rate_limit_hits (migration 0007); shared by every API instance, for
            serverless hosting. Keys are stored hashed.
"""

from __future__ import annotations

import hashlib
import random
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from sqlalchemy import text


class MemoryWindow:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self.limit

    def hit(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._prune(key, now).append(now)

    def hit_and_check(self, key: str) -> bool:
        """Record a hit; True if the key is now over the limit."""
        with self._lock:
            now = time.monotonic()
            q = self._prune(key, now)
            q.append(now)
            return len(q) > self.limit

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


class PostgresWindow:
    def __init__(self, bucket: str, limit: int, window_seconds: float) -> None:
        self.bucket = bucket
        self.limit = limit
        self.window = timedelta(seconds=window_seconds)

    @staticmethod
    def _key(key: str) -> bytes:
        return hashlib.sha256(key.encode()).digest()

    def _count(self, conn: object, key: bytes) -> int:
        return int(
            conn.execute(  # type: ignore[attr-defined]
                text(
                    "SELECT count(*) FROM rate_limit_hits "
                    "WHERE bucket = :b AND key_hash = :k AND at > clock_timestamp() - :w"
                ),
                {"b": self.bucket, "k": key, "w": self.window},
            ).scalar_one()
        )

    def _insert(self, conn: object, key: bytes) -> None:
        conn.execute(  # type: ignore[attr-defined]
            text("INSERT INTO rate_limit_hits (bucket, key_hash) VALUES (:b, :k)"),
            {"b": self.bucket, "k": key},
        )
        if random.random() < 0.01:  # noqa: S311 - housekeeping, not security
            conn.execute(  # type: ignore[attr-defined]
                text("DELETE FROM rate_limit_hits WHERE at < clock_timestamp() - interval '1 day'")
            )

    def blocked(self, key: str) -> bool:
        from nightfall.core.db.session import get_engine

        with get_engine().begin() as conn:
            return self._count(conn, self._key(key)) >= self.limit

    def hit(self, key: str) -> None:
        from nightfall.core.db.session import get_engine

        with get_engine().begin() as conn:
            self._insert(conn, self._key(key))

    def hit_and_check(self, key: str) -> bool:
        from nightfall.core.db.session import get_engine

        k = self._key(key)
        with get_engine().begin() as conn:
            self._insert(conn, k)
            return self._count(conn, k) > self.limit

    def reset(self, key: str) -> None:
        from nightfall.core.db.session import get_engine

        with get_engine().begin() as conn:
            conn.execute(
                text("DELETE FROM rate_limit_hits WHERE bucket = :b AND key_hash = :k"),
                {"b": self.bucket, "k": self._key(key)},
            )

    def clear(self) -> None:
        from nightfall.core.db.session import get_engine

        with get_engine().begin() as conn:
            conn.execute(text("DELETE FROM rate_limit_hits WHERE bucket = :b"), {"b": self.bucket})


class SlidingWindow:
    """Picks the backend from the settings on first use."""

    def __init__(self, limit: int, window_seconds: float, name: str = "default") -> None:
        self.limit = limit
        self.window = window_seconds
        self.name = name
        self._memory = MemoryWindow(limit, window_seconds)
        self._postgres = PostgresWindow(name, limit, window_seconds)

    def _impl(self) -> MemoryWindow | PostgresWindow:
        from nightfall.config import get_settings

        if get_settings().rate_limit_backend == "postgres":
            return self._postgres
        return self._memory

    def blocked(self, key: str) -> bool:
        return self._impl().blocked(key)

    def hit(self, key: str) -> None:
        self._impl().hit(key)

    def hit_and_check(self, key: str) -> bool:
        return self._impl().hit_and_check(key)

    def reset(self, key: str) -> None:
        self._impl().reset(key)

    def clear(self) -> None:
        self._impl().clear()


# Failed sign-in / MFA attempts.
login_failures_by_account = SlidingWindow(limit=5, window_seconds=15 * 60, name="login_account")
login_failures_by_ip = SlidingWindow(limit=20, window_seconds=15 * 60, name="login_ip")
# All mutating API requests, per client IP.
mutations_by_ip = SlidingWindow(limit=120, window_seconds=60, name="mutations_ip")
