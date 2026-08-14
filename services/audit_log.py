"""
Audit log store (diagram: "POSTGRESQL — request logs, risk scores, decisions,
audit trails, user/IP bans").

PostgreSQL when AUDIT_DSN is set (and psycopg importable), else a local
SQLite file — either way the same `record()` surface, and logging NEVER
breaks the request path.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from core.config import SETTINGS

_BACKEND = "unset"
_PG = None  # psycopg connection
_SQLITE: sqlite3.Connection | None = None
_RING: list[dict[str, Any]] = []  # last-resort in-memory ring


def backend_name() -> str:
    return _BACKEND


def _init_pg():
    global _PG, _BACKEND
    try:
        import psycopg  # type: ignore

        _PG = psycopg.connect(SETTINGS.audit_dsn, autocommit=True, connect_timeout=2)
        _PG.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id BIGSERIAL PRIMARY KEY,
                ts TIMESTAMPTZ NOT NULL DEFAULT now(),
                request_id TEXT, user_id TEXT, session_id TEXT,
                decision TEXT, risk_score REAL, reason TEXT,
                layers JSONB, client_ip TEXT
            );
            CREATE TABLE IF NOT EXISTS user_bans (
                user_id TEXT PRIMARY KEY, reason TEXT, banned_at TIMESTAMPTZ DEFAULT now()
            );
            """
        )
        _BACKEND = "postgres"
    except Exception:
        _PG = None


def _init_sqlite():
    global _SQLITE, _BACKEND
    try:
        SETTINGS.audit_sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        _SQLITE = sqlite3.connect(str(SETTINGS.audit_sqlite_path), check_same_thread=False)
        _SQLITE.execute("PRAGMA journal_mode=WAL")
        _SQLITE.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, request_id TEXT, user_id TEXT, session_id TEXT,
                decision TEXT, risk_score REAL, reason TEXT,
                layers TEXT, client_ip TEXT
            )
            """
        )
        _SQLITE.commit()
        _BACKEND = "sqlite"
    except Exception:
        _SQLITE = None
        _BACKEND = "memory"


def init() -> None:
    if SETTINGS.audit_dsn:
        _init_pg()
    if _PG is None:
        _init_sqlite()


def record(*, request_id: str, user_id: str, session_id: str, decision: str,
           risk_score: float, reason: str = "", layers: dict[str, Any] | None = None,
           client_ip: str = "") -> None:
    """Persist one event; any failure silently falls back to the ring buffer."""
    row = {
        "request_id": request_id, "user_id": user_id, "session_id": session_id,
        "decision": decision, "risk_score": risk_score, "reason": reason,
        "layers": layers or {}, "client_ip": client_ip, "ts": time.time(),
    }
    try:
        if _BACKEND == "unset":
            init()
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                "INSERT INTO security_events (request_id, user_id, session_id, decision,"
                " risk_score, reason, layers, client_ip) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (request_id, user_id, session_id, decision, risk_score, reason,
                 json.dumps(layers or {}), client_ip),
            )
            return
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                "INSERT INTO security_events (ts, request_id, user_id, session_id, decision,"
                " risk_score, reason, layers, client_ip) VALUES (?,?,?,?,?,?,?,?,?)",
                (row["ts"], request_id, user_id, session_id, decision,
                 risk_score, reason, json.dumps(layers or {}), client_ip),
            )
            _SQLITE.commit()
            return
    except Exception:
        pass
    _RING.append(row)
    if len(_RING) > 500:
        del _RING[:-500]


def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    """Newest events for /admin/events (best-effort across backends)."""
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "SELECT request_id, user_id, decision, risk_score, reason, ts"
                " FROM security_events ORDER BY ts DESC LIMIT %s", (limit,))
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "SELECT request_id, user_id, decision, risk_score, reason, ts"
                " FROM security_events ORDER BY ts DESC LIMIT ?", (limit,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        pass
    return list(reversed(_RING[-limit:]))


def ban_user(user_id: str, reason: str = "cumulative risk exceeded") -> None:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                "INSERT INTO user_bans (user_id, reason) VALUES (%s,%s)"
                " ON CONFLICT (user_id) DO UPDATE SET reason = EXCLUDED.reason",
                (user_id, reason),
            )
            return
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                "CREATE TABLE IF NOT EXISTS user_bans (user_id TEXT PRIMARY KEY, reason TEXT)")
            _SQLITE.execute(
                "INSERT INTO user_bans (user_id, reason) VALUES (?,?)"
                " ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason",
                (user_id, reason))
            _SQLITE.commit()
            return
    except Exception:
        pass
    _RING.append({"decision": "ban", "user_id": user_id, "reason": reason, "ts": time.time()})


def is_banned(user_id: str) -> bool:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            return bool(_PG.execute(
                "SELECT 1 FROM user_bans WHERE user_id = %s", (user_id,)).fetchone())
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                "CREATE TABLE IF NOT EXISTS user_bans (user_id TEXT PRIMARY KEY, reason TEXT)")
            cur = _SQLITE.execute("SELECT 1 FROM user_bans WHERE user_id = ?", (user_id,))
            return cur.fetchone() is not None
    except Exception:
        pass
    return False


def unban_user(user_id: str) -> None:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute("DELETE FROM user_bans WHERE user_id = %s", (user_id,))
            return
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute("DELETE FROM user_bans WHERE user_id = ?", (user_id,))
            _SQLITE.commit()
    except Exception:
        pass
