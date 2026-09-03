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
            CREATE TABLE IF NOT EXISTS training_samples (
                id BIGSERIAL PRIMARY KEY,
                ts TIMESTAMPTZ NOT NULL DEFAULT now(),
                text_hash TEXT NOT NULL UNIQUE,
                text TEXT NOT NULL,
                label INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'realtime',
                scores JSONB,
                trained INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS model_versions (
                version INTEGER PRIMARY KEY,
                trained_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                source TEXT NOT NULL,
                samples INTEGER, threat INTEGER, benign INTEGER,
                metrics JSONB
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
        _SQLITE.execute(
            """
            CREATE TABLE IF NOT EXISTS training_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, text_hash TEXT NOT NULL UNIQUE,
                text TEXT NOT NULL, label INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'realtime',
                scores TEXT, trained INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        _SQLITE.execute(
            """
            CREATE TABLE IF NOT EXISTS model_versions (
                version INTEGER PRIMARY KEY,
                trained_at REAL, source TEXT NOT NULL,
                samples INTEGER, threat INTEGER, benign INTEGER,
                metrics TEXT
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
_MEM_TRAIN: dict[str, dict] = {}   # text_hash -> sample
_MEM_VERSIONS: list[dict] = []     # model version history


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


# --------------------------------------------------------------------------- #
# Real-time training samples (trial-update: model learns from live traffic)
# --------------------------------------------------------------------------- #
def record_training_sample(*, text: str, label: int, source: str = "realtime",
                           scores: dict | None = None) -> bool:
    """Store one labeled real-traffic prompt. Deduped by content hash.

    label: 1 = threat (blocked), 0 = benign (allowed). Never breaks callers.
    """
    import hashlib

    t = (text or "").strip()
    if len(t) < 8 or label not in (0, 1):
        return False
    h = hashlib.sha256(t.lower().encode()).hexdigest()
    try:
        if _BACKEND == "unset":
            init()
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "INSERT INTO training_samples (text_hash, text, label, source, scores)"
                " VALUES (%s,%s,%s,%s,%s) ON CONFLICT (text_hash) DO NOTHING",
                (h, t[:4000], label, source, json.dumps(scores or {})),
            )
            return bool(cur.rowcount)
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "INSERT OR IGNORE INTO training_samples (ts, text_hash, text, label, source, scores)"
                " VALUES (?,?,?,?,?,?)",
                (time.time(), h, t[:4000], label, source, json.dumps(scores or {})),
            )
            _SQLITE.commit()
            return bool(cur.rowcount)
    except Exception:
        pass
    if h in _MEM_TRAIN:
        return False
    _MEM_TRAIN[h] = {"ts": time.time(), "text_hash": h, "text": t[:4000],
                     "label": label, "source": source, "scores": scores or {},
                     "trained": 0}
    return True


def record_training_samples_batch(samples: list[dict]) -> dict[str, int]:
    """Bulk insert of labeled samples in ONE transaction (fast imports).

    samples: [{text, label, source?, scores?}] -> {recorded, duplicates}
    """
    import hashlib

    out = {"recorded": 0, "duplicates": 0}
    rows: list[tuple] = []
    local_seen: set[str] = set()
    for s in samples:
        t = (s.get("text") or "").strip()
        label = int(s.get("label", 1))
        if len(t) < 8 or label not in (0, 1):
            out["duplicates"] += 1
            continue
        h = hashlib.sha256(t.lower().encode()).hexdigest()
        if h in local_seen:
            out["duplicates"] += 1
            continue
        local_seen.add(h)
        rows.append((time.time(), h, t[:4000], label,
                     s.get("source") or "realtime",
                     json.dumps(s.get("scores") or {})))
    if not rows:
        return out
    try:
        if _BACKEND == "unset":
            init()
        if _BACKEND == "postgres" and _PG is not None:
            from datetime import datetime, timezone

            # PG's ts column is TIMESTAMPTZ — a raw float epoch is rejected
            # (pre-PG this fed SQLite's REAL column). Also note: psycopg2's
            # `execute_values` does not exist in psycopg 3 — executemany is
            # pipelined and fast there.
            pg_rows = [(datetime.fromtimestamp(r[0], tz=timezone.utc), *r[1:])
                       for r in rows]
            with _PG.cursor() as _cur:
                _cur.executemany(
                    "INSERT INTO training_samples"
                    " (ts, text_hash, text, label, source, scores)"
                    " VALUES (%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (text_hash) DO NOTHING",
                    pg_rows)
            out["recorded"] = len(pg_rows)
            return out
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.executemany(
                "INSERT OR IGNORE INTO training_samples (ts, text_hash, text, label, source, scores)"
                " VALUES (?,?,?,?,?,?)", rows)
            _SQLITE.commit()  # single fsync for the whole batch
            out["recorded"] = int(cur.rowcount or 0)
            out["duplicates"] += len(rows) - out["recorded"]
            return out
        # No persistent backend: bulk imports FAIL LOUDLY — a silent memory
        # fallback reads as success but loses the whole batch on restart.
        raise RuntimeError(f"audit backend '{_BACKEND}' cannot store a bulk import")
    except Exception:
        if _BACKEND == "memory":
            for r in rows:
                if r[1] in _MEM_TRAIN:
                    out["duplicates"] += 1
                else:
                    _MEM_TRAIN[r[1]] = {"ts": r[0], "text_hash": r[1], "text": r[2],
                                        "label": r[3], "source": r[4],
                                        "scores": json.loads(r[5]), "trained": 0}
                    out["recorded"] += 1
            return out
        raise


def list_training_samples(label: int | None = None, limit: int = 5000) -> list[dict[str, Any]]:
    """Labeled samples, newest first (all when label is None)."""
    sql = ("SELECT id, ts, text, label, source, scores, trained"
           " FROM training_samples")
    args: tuple = ()
    if label is not None:
        sql += " WHERE label = ?"
        args = (label,)
    sql += " ORDER BY ts DESC LIMIT ?"
    args = args + (limit,)
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(sql.replace("?", "%s"), args)
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(sql, args)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        pass
    rows = list(_MEM_TRAIN.values())
    if label is not None:
        rows = [r for r in rows if r["label"] == label]
    return sorted(rows, key=lambda r: r.get("ts", 0), reverse=True)[:limit]


def training_sample_counts() -> dict[str, int]:
    rows = list_training_samples(limit=100000)
    return {
        "total": len(rows),
        "threat": sum(1 for r in rows if r["label"] == 1),
        "benign": sum(1 for r in rows if r["label"] == 0),
        "untrained": sum(1 for r in rows if not r.get("trained")),
    }


def mark_training_samples_trained(ids: list[int]) -> int:
    if not ids:
        return 0
    try:
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute("UPDATE training_samples SET trained = 1"
                        " WHERE id = ANY(%s)", (list(ids),))
            return len(ids)
        if _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.executemany(
                "UPDATE training_samples SET trained = 1 WHERE id = ?",
                [(i,) for i in ids])
            _SQLITE.commit()
            return len(ids)
    except Exception:
        pass
    for r in _MEM_TRAIN.values():
        if r.get("id") in ids:
            r["trained"] = 1
    return len(ids)


def record_model_version(*, source: str, samples: int, threat: int,
                         benign: int, metrics: dict) -> int:
    version = latest_model_version().get("version", 0) + 1
    row = {"version": version, "trained_at": time.time(), "source": source,
           "samples": samples, "threat": threat, "benign": benign,
           "metrics": metrics}
    try:
        if _BACKEND == "postgres" and _PG is not None:
            _PG.execute(
                "INSERT INTO model_versions (version, source, samples, threat, benign, metrics)"
                " VALUES (%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (version) DO NOTHING",
                (version, source, samples, threat, benign, json.dumps(metrics)),
            )
        elif _BACKEND == "sqlite" and _SQLITE is not None:
            _SQLITE.execute(
                "INSERT OR IGNORE INTO model_versions (version, trained_at, source,"
                " samples, threat, benign, metrics) VALUES (?,?,?,?,?,?,?)",
                (version, row["trained_at"], source, samples, threat,
                 benign, json.dumps(metrics)),
            )
            _SQLITE.commit()
        else:
            _MEM_VERSIONS.append(row)
    except Exception:
        _MEM_VERSIONS.append(row)
    return version


def list_model_versions(limit: int = 40) -> list[dict[str, Any]]:
    """Oldest-first version history (for the /reports model-trend chart)."""
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "SELECT version, trained_at, source, samples, threat, benign, metrics"
                " FROM model_versions ORDER BY version ASC LIMIT %s", (limit,))
            cols = [c.name for c in cur.description]
            rows = []
            for r in cur.fetchall():
                d = dict(zip(cols, r))
                if isinstance(d.get("metrics"), str):
                    d["metrics"] = json.loads(d["metrics"] or "{}")
                rows.append(d)
            return rows
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "SELECT version, trained_at, source, samples, threat, benign, metrics"
                " FROM model_versions ORDER BY version ASC LIMIT ?", (limit,))
            return [{"version": r[0], "trained_at": r[1], "source": r[2],
                     "samples": r[3], "threat": r[4], "benign": r[5],
                     "metrics": json.loads(r[6] or "{}")} for r in cur.fetchall()]
    except Exception:
        pass
    return list(_MEM_VERSIONS)[-limit:]


def latest_model_version() -> dict[str, Any]:
    try:
        if _BACKEND == "postgres" and _PG is not None:
            cur = _PG.execute(
                "SELECT version, trained_at, source, samples, threat, benign, metrics"
                " FROM model_versions ORDER BY version DESC LIMIT 1")
            cols = [c.name for c in cur.description]
            r = cur.fetchone()
            return dict(zip(cols, r)) if r else {}
        if _BACKEND == "sqlite" and _SQLITE is not None:
            cur = _SQLITE.execute(
                "SELECT version, trained_at, source, samples, threat, benign, metrics"
                " FROM model_versions ORDER BY version DESC LIMIT 1")
            r = cur.fetchone()
            if r:
                return {"version": r[0], "trained_at": r[1], "source": r[2],
                        "samples": r[3], "threat": r[4], "benign": r[5],
                        "metrics": json.loads(r[6] or "{}")}
            return {}
    except Exception:
        pass
    return dict(_MEM_VERSIONS[-1]) if _MEM_VERSIONS else {}
