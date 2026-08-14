"""
LAYER 3 — BEHAVIORAL SESSION LAYER, stateful (diagram: "Redis Risk Engine";
PDF §2.1 Session State Manager).

Redis schema (exactly as diagrammed):
    key    : session_risk:{user_id}
    value  : {cumulative: float, count: int, history: [embedding, ...]}
    TTL    : 30 minutes (refreshed each turn)

Per turn it computes:
  - semantic drift     : cosine distance of this turn's embedding from the
                         session baseline mean — "slow steering" detection
                         (PDF: "user slowly steers the conversation toward
                         prohibited topics across multiple turns")
  - attack proximity   : cosine similarity to the trained attack centroid
  - cumulative risk    : EWMA over turns -> blocked when it exceeds the
                         threshold ("cumulative risk exceeded")
"""
from __future__ import annotations

import json

import numpy as np

from core.config import SETTINGS
from models.schemas import SessionRiskResult
from services import redis_client
from services.embedding_service import cosine


def _key(user_id: str) -> str:
    return f"session_risk:{user_id}"


def _load_state(user_id: str) -> dict:
    state = redis_client.get_state()
    try:
        raw = state.get(_key(user_id))
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"cumulative": 0.0, "count": 0, "history": []}


def _save_state(user_id: str, data: dict) -> None:
    state = redis_client.get_state()
    try:
        state.set(_key(user_id), json.dumps(data), ex=SETTINGS.session_risk_ttl_s)
    except Exception:
        pass


def reset(user_id: str) -> None:
    """Session termination hook (PDF §3.3: terminate + reset session state)."""
    try:
        redis_client.get_state().delete(_key(user_id))
    except Exception:
        pass


def track(user_id: str, embedding: list[float], intent_score: float,
          injection_weightage: float = 0.0) -> SessionRiskResult:
    """Record this turn and evaluate cumulative risk.

    `injection_weightage` (trial-update #1/#3): the word-level attack weight
    of this turn's prompt — blended into the per-turn risk, so prompts dense
    with attack vocabulary escalate the cumulative behavioral risk even when
    the semantic classifier score alone would not.
    """
    prev = _load_state(user_id)
    history: list[list[float]] = list(prev.get("history", []))[-SETTINGS.session_window:]
    sentiment_history: list[float] = list(prev.get("sentiment_history", []))[-SETTINGS.session_window:]

    # --- semantic drift from the session baseline ------------------------ #
    drift = 0.0
    if history:
        baseline = np.mean(np.asarray(history, dtype=np.float32), axis=0)
        drift = max(0.0, 1.0 - cosine(embedding, baseline))

    # --- proximity to the trained attack centroid ------------------------- #
    from guardrails.input_filter import centroids

    attack_proximity = 0.0
    _, attack_c = centroids()
    if attack_c is not None and len(embedding) == len(attack_c):
        attack_proximity = max(0.0, cosine(embedding, attack_c))

    # --- per-turn risk + EWMA cumulative ---------------------------------- #
    drift_risk = max(0.0, drift - SETTINGS.drift_free_tolerance) / max(
        1e-6, 1.0 - SETTINGS.drift_free_tolerance
    )
    per_turn = max(
        intent_score,
        attack_proximity * 0.9,
        drift_risk * 0.8,
        injection_weightage,   # trial-update #3: saturated attack vocab = full-risk turn
    )
    cumulative = SETTINGS.risk_decay * float(prev.get("cumulative", 0.0)) \
        + (1.0 - SETTINGS.risk_decay) * per_turn

    # --- aggregate average sentiment across the session (trial-update #2) -- #
    sentiment_history.append(round(float(injection_weightage), 4))
    sentiment_avg = float(np.mean(sentiment_history)) if sentiment_history else 0.0

    history.append(list(embedding))
    _save_state(user_id, {
        "cumulative": cumulative,
        "count": int(prev.get("count", 0)) + 1,
        "history": history[-SETTINGS.session_window:],
        "sentiment_history": sentiment_history[-SETTINGS.session_window:],
    })

    blocked = cumulative >= SETTINGS.cumulative_risk_threshold
    if blocked:
        # Terminating the session = wiping its risk state (PDF §3.3).
        reset(user_id)

    return SessionRiskResult(
        cumulative_risk=round(cumulative, 4),
        drift=round(drift, 4),
        turn_count=int(prev.get("count", 0)) + 1,
        attack_proximity=round(attack_proximity, 4),
        injection_weightage=round(float(injection_weightage), 4),
        sentiment_avg=round(sentiment_avg, 4),
        blocked=blocked,
    )


def peek(user_id: str) -> SessionRiskResult:
    """Read-only view for GET /session/risk/{user_id}."""
    data = _load_state(user_id)
    sentiment_history = data.get("sentiment_history", [])
    return SessionRiskResult(
        cumulative_risk=float(data.get("cumulative", 0.0)),
        drift=0.0,
        turn_count=int(data.get("count", 0)),
        sentiment_avg=round(float(np.mean(sentiment_history)), 4) if sentiment_history else 0.0,
    )
