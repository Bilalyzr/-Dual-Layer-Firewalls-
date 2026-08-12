"""
Behavioral Security Event Store (PRD §20 Database Design, FR-12, §25, §27).

Persists behavioral decisions/scores so the platform can satisfy:
  - FR-12  Security Logging — record behavioral analysis + security decisions
  - §20    access_events / behavior_scores / security_decisions tables
  - §25    Behavioral Risk Command Center aggregate stats
  - §27    GET /api/behavior/events  and  POST /api/behavior/event

This is an in-process, bounded ring buffer (the same pragmatic pattern the rest
of the engine uses for demo/single-node runs). It is intentionally swappable:
in production the same ``record()``/``query()``/``stats()`` surface would be
backed by PostgreSQL/Mongo per the PRD database design. Kept dependency-free so
it never blocks the hot path.
"""
from __future__ import annotations
import threading
import time
from collections import deque
from typing import Any

# Bounded history — newest last. Sized for a demo/single node.
_MAX_EVENTS = 5000
_events: deque[dict] = deque(maxlen=_MAX_EVENTS)
_lock = threading.Lock()
_seq = 0

# Active-session tracking for the command center (§25). session_id -> last-seen.
_SESSION_TTL = 1800.0  # seconds a session counts as "active" after last event
_sessions: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def record(decision: dict) -> dict:
    """Persist one analyzed behavioral decision. Returns the stored record.

    ``decision`` is the Behavioral Decision Object produced by the pipeline.
    Never raises — logging must not break the analysis path.
    """
    global _seq
    try:
        with _lock:
            _seq += 1
            rec = {
                "event_id": _seq,
                "ts": _now(),
                "user_id": decision.get("user_id", ""),
                "session_id": decision.get("session_id", ""),
                "risk_score": decision.get("risk_score", 0.0),
                "risk_level": decision.get("risk_level", "LOW"),
                "decision": decision.get("decision", "ALLOW"),
                "required_authentication": decision.get("required_authentication", "NORMAL"),
                "behavior_anomaly_score": decision.get("behavior_anomaly_score", 0.0),
                "llm_context_score": decision.get("llm_context_score", 0.0),
                "resource_risk": decision.get("resource_risk", "low"),
                "model_used": (decision.get("threat") or {}).get("model_used", "unknown"),
                "reasons": decision.get("reasons", []),
            }
            _events.append(rec)
            sid = rec["session_id"]
            if sid:
                _sessions[sid] = {
                    "user_id": rec["user_id"],
                    "last_seen": rec["ts"],
                    "risk_level": rec["risk_level"],
                    "decision": rec["decision"],
                }
        return rec
    except Exception:
        return {}


def query(
    *,
    user_id: str | None = None,
    risk_level: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Return recent events (newest first), optionally filtered (§27 GET /events)."""
    with _lock:
        items = list(_events)
    items.reverse()  # newest first
    if user_id:
        items = [e for e in items if e["user_id"] == user_id]
    if risk_level:
        rl = risk_level.upper()
        items = [e for e in items if e["risk_level"] == rl]
    return items[: max(1, min(limit, _MAX_EVENTS))]


def _active_sessions() -> list[dict]:
    now = _now()
    with _lock:
        # Drop expired sessions and return the live ones.
        live = {sid: s for sid, s in _sessions.items() if now - s["last_seen"] <= _SESSION_TTL}
        _sessions.clear()
        _sessions.update(live)
        return list(live.values())


def stats() -> dict[str, Any]:
    """Command-center aggregates (PRD §25)."""
    with _lock:
        items = list(_events)
    sessions = _active_sessions()

    by_level = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for s in sessions:
        by_level[s.get("risk_level", "LOW")] = by_level.get(s.get("risk_level", "LOW"), 0) + 1
    blocked = sum(1 for s in sessions if s.get("decision") in ("RESTRICT", "DENY"))

    recent = list(reversed(items))[:20]
    recent_anomalies = [e for e in recent if e["risk_level"] in ("MEDIUM", "HIGH")][:10]

    # Per-user rollup for the user-level risk table (§25).
    users: dict[str, dict] = {}
    for e in items:
        u = users.setdefault(e["user_id"], {"user_id": e["user_id"], "events": 0, "max_risk": 0.0, "last_level": "LOW", "last_ts": 0.0})
        u["events"] += 1
        u["max_risk"] = max(u["max_risk"], e["risk_score"])
        if e["ts"] >= u["last_ts"]:
            u["last_ts"] = e["ts"]
            u["last_level"] = e["risk_level"]
    user_table = sorted(users.values(), key=lambda x: x["max_risk"], reverse=True)[:25]

    return {
        "active_users": len({s["user_id"] for s in sessions}),
        "active_sessions": len(sessions),
        "low_risk_sessions": by_level.get("LOW", 0),
        "medium_risk_sessions": by_level.get("MEDIUM", 0),
        "high_risk_sessions": by_level.get("HIGH", 0),
        "blocked_sessions": blocked,
        "total_events": len(items),
        "recent_anomalies": recent_anomalies,
        "user_risk_table": user_table,
    }


def reset() -> None:
    """Clear all state (tests)."""
    global _seq
    with _lock:
        _events.clear()
        _sessions.clear()
        _seq = 0
