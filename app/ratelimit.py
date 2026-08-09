"""Per-principal token bucket.

In-memory on purpose: one instance, one process. It exists in Phase 1 even
though the only user is the owner, because this is the code that will later be
reachable from the internet, and a limiter bolted on afterwards always leaks.
"""
from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, per_minute: int):
        self.capacity = float(per_minute)
        self.refill_per_sec = per_minute / 60.0
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens < cost:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - cost, now)
            return True
