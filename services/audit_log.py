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
            CREATE TABLE IF NOT EXISTS sessions (
                session_key TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                turns INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                max_risk REAL NOT NULL DEFAULT 0,
                last_risk REAL NOT NULL DEFAULT 0,
                sentiment_avg REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id BIGSERIAL PRIMARY KEY,
                ts TIMESTAMPTZ NOT NULL DEFAULT now(),
                prompt_text TEXT NOT NULL,
                layer TEXT, risk_score REAL,
                source TEXT NOT NULL DEFAULT 'auto',
                status TEXT NOT NULL DEFAULT 'pending'
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
        _SQLITE.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_key TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                started_at REAL, last_seen REAL,
                turns INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                max_risk REAL NOT NULL DEFAULT 0,
                last_risk REAL NOT NULL DEFAULT 0,
                sentiment_avg REAL NOT NULL DEFAULT 0
            )
            """
        )
        _SQLITE.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, prompt_text TEXT NOT NULL,
                layer TEXT, risk_score REAL,
                source TEXT NOT NULL DEFAULT 'auto',
                status TEXT NOT NULL DEFAULT 'pending'
            )
            """
        )
        _SQLITE.commit()
        _BACKEND = "sqlite"
    except Exception:
        _SQLITE = None
        _BACKEND = "memory"


# memory-fallback stores for sessions + vulnerabilities
_MEM_SESSIONS: dict[str, dict] = {}
_MEM_VULNS: list[dict] = []


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


# --------------------------------------------------------------------------- #
# Sessions (trial-update: every session persisted to the database)
# --------------------------------------------------------------------------- #
def upsert_session(*, session_key: str, user_id: str, turns: int,
                   risk: float, sentiment_avg: float,
                   status: str = "active") -> None:
    """Insert-or-update the durable session record. Never breaks the request."""
    now = time.time()
    try:
        if _BACKEND == "unset":
            init()
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                """
                INSERT INTO sessions (session_key, user_id, last_seen, turns, status,
                                      max_risk, last_risk, sentiment_avg)
                VALUES (%s,%s,now(),%s,%s,%s,%s,%s)
                ON CONFLICT (session_key) DO UPDATE SET
                    last_seen = now(), turns = EXCLUDED.turns, status = EXCLUDED.status,
                    max_risk = GREATEST(sessions.max_risk, EXCLUDED.last_risk),
                    last_risk = EXCLUDED.last_risk,
                    sentiment_avg = EXCLUDED.sentiment_avg
                """,
                (session_key, user_id, turns, status, risk, risk, sentiment_avg),
            )
            return
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                """
                INSERT INTO sessions (session_key, user_id, started_at, last_seen, turns,
                                      status, max_risk, last_risk, sentiment_avg)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_key) DO UPDATE SET
                    last_seen=excluded.last_seen, turns=excluded.turns,
                    status=excluded.status,
                    max_risk=MAX(sessions.max_risk, excluded.last_risk),
                    last_risk=excluded.last_risk,
                    sentiment_avg=excluded.sentiment_avg
                """,
                (session_key, user_id, now, now, turns, status, risk, risk, sentiment_avg),
            )
            _SQLITE.commit()
            return
    except Exception:
        pass
    row = _MEM_SESSIONS.get(session_key) or {
        "session_key": session_key, "user_id": user_id, "started_at": now,
        "status": "active", "max_risk": 0.0,
    }
    row.update({
        "last_seen": now, "turns": turns, "status": status,
        "last_risk": risk,
        "max_risk": max(float(row.get("max_risk", 0.0)), risk),
        "sentiment_avg": sentiment_avg,
    })
    _MEM_SESSIONS[session_key] = row


def list_sessions(limit: int = 50) -> list[dict[str, Any]]:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "SELECT session_key, user_id, turns, status, max_risk, last_risk,"
                " sentiment_avg, started_at, last_seen"
                " FROM sessions ORDER BY last_seen DESC LIMIT %s", (limit,))
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "SELECT session_key, user_id, turns, status, max_risk, last_risk,"
                " sentiment_avg, started_at, last_seen"
                " FROM sessions ORDER BY last_seen DESC LIMIT ?", (limit,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        pass
    rows = sorted(_MEM_SESSIONS.values(), key=lambda r: r.get("last_seen", 0),
                  reverse=True)
    return rows[:limit]


# --------------------------------------------------------------------------- #
# Vulnerabilities (trial-update: new input vulnerabilities -> retrain the model)
# --------------------------------------------------------------------------- #
def record_vulnerability(*, prompt_text: str, layer: str = "", risk: float = 0.0,
                         source: str = "auto") -> None:
    """Queue an attack input for the retraining loop (never breaks the request)."""
    if not prompt_text or not prompt_text.strip():
        return
    try:
        if _BACKEND == "unset":
            init()
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                "INSERT INTO vulnerabilities (prompt_text, layer, risk_score, source)"
                " VALUES (%s,%s,%s,%s)",
                (prompt_text[:4000], layer, risk, source),
            )
            return
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                "INSERT INTO vulnerabilities (ts, prompt_text, layer, risk_score, source)"
                " VALUES (?,?,?,?,?)",
                (time.time(), prompt_text[:4000], layer, risk, source),
            )
            _SQLITE.commit()
            return
    except Exception:
        pass
    _MEM_VULNS.append({"ts": time.time(), "prompt_text": prompt_text[:4000],
                       "layer": layer, "risk_score": risk, "source": source,
                       "status": "pending"})
    if len(_MEM_VULNS) > 500:
        del _MEM_VULNS[:-500]


def list_vulnerabilities(status: str = "pending", limit: int = 100) -> list[dict[str, Any]]:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "SELECT id, ts, prompt_text, layer, risk_score, source, status"
                " FROM vulnerabilities WHERE status = %s ORDER BY ts DESC LIMIT %s",
                (status, limit))
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "SELECT id, ts, prompt_text, layer, risk_score, source, status"
                " FROM vulnerabilities WHERE status = ? ORDER BY ts DESC LIMIT ?",
                (status, limit))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        pass
    return [v for v in reversed(_MEM_VULNS) if v.get("status") == status][:limit]


def mark_vulnerabilities_trained(ids: list[int]) -> int:
    if not ids:
        return 0
    try:
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                "UPDATE vulnerabilities SET status = 'trained'"
                " WHERE id = ANY(%s)", (list(ids),))
            return len(ids)
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.executemany(
                "UPDATE vulnerabilities SET status = 'trained' WHERE id = ?",
                [(i,) for i in ids])
            _SQLITE.commit()
            return len(ids)
    except Exception:
        pass
    for v in _MEM_VULNS:
        if v.get("id") in ids:
            v["status"] = "trained"
    return len(ids)
