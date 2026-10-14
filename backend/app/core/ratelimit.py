"""In-process token-bucket rate limiter (SECURITY_REQUIREMENTS.md §8).

The MVP runs a single API process, so buckets live in memory. Each application instance owns
its own limiter; multiple API processes would need a shared store (Redis, via an ADR).
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

# Requests per minute (API_SPECIFICATION.md §8).
LIMITS = {"login": 10, "upload": 10, "job": 30, "default": 600}
MAX_BUCKETS = 50_000


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, per_minute: int) -> float | None:
        """Consume one token; return ``None`` if allowed, else seconds until one is available."""
        rate = per_minute / 60.0
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= MAX_BUCKETS:
                    self._evict(now)
                bucket = self._buckets[key] = _Bucket(float(per_minute), now)
            bucket.tokens = min(float(per_minute), bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return None
            return (1.0 - bucket.tokens) / rate

    def _evict(self, now: float) -> None:
        # Drop buckets idle for over a minute (they would be full again anyway).
        stale = [k for k, b in self._buckets.items() if now - b.updated > 60]
        for key in stale:
            del self._buckets[key]
        if len(self._buckets) >= MAX_BUCKETS:
            self._buckets.clear()


def retry_after_header(seconds: float) -> str:
    return str(max(1, math.ceil(seconds)))
