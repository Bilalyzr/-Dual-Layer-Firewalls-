"""
Fixed-window rate limiter (PDF §4.2 core/rate_limiter.py).

Uses the shared Redis client when reachable, else an in-process fallback —
same fail-open pattern as the rest of the stack: availability over strictness.
"""
from __future__ import annotations

import time

from .config import SETTINGS


class InMemoryWindow:
    """Per-key sliding-minute counter (fallback when Redis is down)."""

    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}

    def hit(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.time()
        bucket = [t for t in self._hits.get(key, []) if now - t < window_s]
        if len(bucket) >= limit:
            self._hits[key] = bucket
            return False
        bucket.append(now)
        self._hits[key] = bucket
        return True


_memory = InMemoryWindow()


def allow(key: str, limit: int | None = None) -> bool:
    """Record a hit; True when the caller is under the limit."""
    limit = limit if limit is not None else SETTINGS.rate_limit_per_min
    try:
        from services.redis_client import get_redis

        r = get_redis()
        if r is not None:
            k = f"ratelimit:{key}:{int(time.time() // 60)}"
            pipe = r.pipeline()
            pipe.incr(k)
            pipe.expire(k, 60)
            count = int(pipe.execute()[0] or 0)
            return count <= limit
    except Exception:
        pass
    return _memory.hit(key, limit)
