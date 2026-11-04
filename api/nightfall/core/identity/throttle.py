"""In-process sliding-window limiter (single API instance, per §5 of the review).
Swap for a shared store if the API is ever scaled horizontally."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindow:
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


# Failed sign-in / MFA attempts.
login_failures_by_account = SlidingWindow(limit=5, window_seconds=15 * 60)
login_failures_by_ip = SlidingWindow(limit=20, window_seconds=15 * 60)
# All mutating API requests, per client IP.
mutations_by_ip = SlidingWindow(limit=120, window_seconds=60)
