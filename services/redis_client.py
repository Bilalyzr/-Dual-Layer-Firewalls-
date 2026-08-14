"""
Redis state store (diagram: "REDIS / Session Risk Tracking, TTL: 30 mins").

`get_redis()` returns a live client or None — callers fail open to the
in-process fallback so L3 stays stateful even without a Redis server.
"""
from __future__ import annotations

import time

from core.config import SETTINGS

_CLIENT = None
_TRIED = False


class MemoryRedis:
    """Minimal dict-backed stand-in: get/set/expire/pipeline(incr+expire)/delete."""

    def __init__(self) -> None:
        self._store: dict[str, object] = {}
        self._ttl: dict[str, float] = {}

    def _sweep(self) -> None:
        now = time.time()
        for k in [k for k, exp in self._ttl.items() if exp and now > exp]:
            self._store.pop(k, None)
            self._ttl.pop(k, None)

    def set(self, key: str, value: object, ex: int | None = None) -> bool:
        self._sweep()
        self._store[key] = value
        self._ttl[key] = (time.time() + ex) if ex else 0.0
        return True

    def get(self, key: str):
        self._sweep()
        if key in self._ttl and self._ttl[key] and time.time() > self._ttl[key]:
            self._store.pop(key, None)
            return None
        return self._store.get(key)

    def delete(self, key: str) -> int:
        existed = key in self._store
        self._store.pop(key, None)
        self._ttl.pop(key, None)
        return 1 if existed else 0

    def incr(self, key: str) -> int:
        cur = self._store.get(key, 0)
        self._store[key] = cur + 1 if isinstance(cur, int) else 1
        return int(self._store[key])

    def expire(self, key: str, seconds: int) -> bool:
        if key in self._store:
            self._ttl[key] = time.time() + seconds
            return True
        return False

    def pipeline(self):
        return _MemoryPipeline(self)


class _MemoryPipeline:
    def __init__(self, owner: MemoryRedis) -> None:
        self._owner = owner
        self._ops: list[tuple] = []

    def incr(self, key: str):
        self._ops.append(("incr", key))
        return self

    def expire(self, key: str, seconds: int):
        self._ops.append(("expire", key, seconds))
        return self

    def execute(self):
        out = []
        for op in self._ops:
            if op[0] == "incr":
                out.append(self._owner.incr(op[1]))
            elif op[0] == "expire":
                out.append(self._owner.expire(op[1], op[2]))
        return out


def get_redis():
    """Live Redis client when reachable, else None (caller fails open)."""
    global _CLIENT, _TRIED
    if _CLIENT is not None:
        return _CLIENT
    if _TRIED:
        return None
    _TRIED = True
    try:
        import redis as _redis  # type: ignore

        client = _redis.Redis.from_url(SETTINGS.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        _CLIENT = client
    except Exception:
        _CLIENT = None
    return _CLIENT


_MEMORY = MemoryRedis()


def get_state() -> object:
    """Redis-or-memory backend with the same call surface."""
    return get_redis() or _MEMORY


def backend_name() -> str:
    return "redis" if get_redis() is not None else "memory"
