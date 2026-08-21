"""
One-shot migration: SQLite audit store -> PostgreSQL.

Reads data/security_audit.db and writes every row into the PG database
given by AUDIT_DSN (schema is created by services.audit_log.init()).

    python scripts/migrate_sqlite_to_pg.py          # migrate
    python scripts/migrate_sqlite_to_pg.py --check   # compare counts only
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config import SETTINGS  # noqa: E402  (also loads .env)

import psycopg  # noqa: E402

SQLITE_PATH = SETTINGS.audit_sqlite_path
CHECK_ONLY = "--check" in sys.argv


def ts(v):
    """unix epoch seconds -> timestamptz SQL literal arg."""
    return v  # psycopg adapts datetime; for floats we cast in SQL


def js(v):
    """TEXT json -> JSONB arg (pass through; NULL stays NULL)."""
    if v is None or v == "":
        return None
    json.loads(v)  # validate; raises on garbage
    return v


def main() -> int:
    lite = sqlite3.connect(str(SQLITE_PATH))
    lite.row_factory = sqlite3.Row
    pg = psycopg.connect(SETTINGS.audit_dsn, autocommit=False)

    tables = ["security_events", "sessions", "vulnerabilities",
              "training_samples", "model_versions", "user_bans"]
    src = {t: lite.execute(f"SELECT * FROM {t}").fetchall() for t in tables}

    if CHECK_ONLY:
        for t in tables:
            n_pg = pg.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"{t:18s} sqlite={len(src[t]):>5}  pg={n_pg:>5}")
        return 0

    with pg.cursor() as cur:
        # security_events ------------------------------------------------- #
        rows = src["security_events"]
        for r in rows:
            cur.execute(
                """INSERT INTO security_events
                   (ts, request_id, user_id, session_id, decision, risk_score,
                    reason, layers, client_ip)
                   VALUES (to_timestamp(%s), %s,%s,%s,%s,%s,%s,%s::jsonb,%s)""",
                (r["ts"], r["request_id"], r["user_id"], r["session_id"],
                 r["decision"], r["risk_score"], r["reason"], r["layers"],
                 r["client_ip"]))
        print(f"security_events        {len(rows)} rows")

        # sessions --------------------------------------------------------- #
        rows = src["sessions"]
        for r in rows:
            cur.execute(
                """INSERT INTO sessions
                   (session_key, user_id, started_at, last_seen, turns, status,
                    max_risk, last_risk, sentiment_avg)
                   VALUES (%s,%s, to_timestamp(%s), to_timestamp(%s), %s,%s,%s,%s,%s)
                   ON CONFLICT (session_key) DO NOTHING""",
                (r["session_key"], r["user_id"], r["started_at"], r["last_seen"],
                 r["turns"], r["status"], r["max_risk"], r["last_risk"],
                 r["sentiment_avg"]))
        print(f"sessions               {len(rows)} rows")

        # vulnerabilities -------------------------------------------------- #
        rows = src["vulnerabilities"]
        for r in rows:
            cur.execute(
                """INSERT INTO vulnerabilities (ts, prompt_text, layer, risk_score, source, status)
                   VALUES (to_timestamp(%s), %s,%s,%s,%s,%s)""",
                (r["ts"], r["prompt_text"], r["layer"], r["risk_score"],
                 r["source"], r["status"]))
        print(f"vulnerabilities        {len(rows)} rows")

        # training_samples -------------------------------------------------- #
        rows = src["training_samples"]
        for r in rows:
            cur.execute(
                """INSERT INTO training_samples
                   (ts, text_hash, text, label, source, scores, trained)
                   VALUES (to_timestamp(%s), %s,%s,%s,%s,%s::jsonb,%s)
                   ON CONFLICT (text_hash) DO NOTHING""",
                (r["ts"], r["text_hash"], r["text"], r["label"], r["source"],
                 r["scores"], r["trained"]))
        print(f"training_samples       {len(rows)} rows")

        # model_versions ---------------------------------------------------- #
        rows = src["model_versions"]
        for r in rows:
            cur.execute(
                """INSERT INTO model_versions
                   (version, trained_at, source, samples, threat, benign, metrics)
                   VALUES (%s, to_timestamp(%s), %s,%s,%s,%s,%s::jsonb)
                   ON CONFLICT (version) DO NOTHING""",
                (r["version"], r["trained_at"], r["source"], r["samples"],
                 r["threat"], r["benign"], r["metrics"]))
        print(f"model_versions         {len(rows)} rows")

        # user_bans ---------------------------------------------------------- #
        rows = src["user_bans"]
        for r in rows:
            cur.execute(
                "INSERT INTO user_bans (user_id, reason) VALUES (%s,%s) "
                "ON CONFLICT (user_id) DO NOTHING",
                (r["user_id"], r["reason"]))
        print(f"user_bans              {len(rows)} rows")

        # keep BIGSERIAL sequences ahead of any explicit ids ------------------ #
        for t in ("security_events", "vulnerabilities", "training_samples"):
            cur.execute(
                f"SELECT setval(pg_get_serial_sequence('{t}','id'), "
                f"GREATEST((SELECT COALESCE(MAX(id),0) FROM {t}), 1))")
    pg.commit()

    print("\n-- migrated counts (sqlite -> pg) --")
    for t in tables:
        n_pg = pg.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"{t:18s} {len(src[t]):>5} -> {n_pg:>5}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
