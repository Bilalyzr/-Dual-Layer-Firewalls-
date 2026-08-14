"""
LAYER 2 — SEMANTIC INTENT GUARDRAIL (diagram: "Embeddings + XGBoost";
PDF §2.3: all-MiniLM-L6-v2 embedding, frozen XGBoost head, sub-ms decision).

  sanitized_prompt -> embedding_vector -> intent_score = P(threat)

Fails open: when the trained artifact is missing the score is 0.0 with
degraded=True (same convention as engine/classifier/embedding_firewall.py).
"""
from __future__ import annotations

import time

import numpy as np

from core.config import SETTINGS
from models.schemas import IntentResult
from services.embedding_service import embed

_MODEL = None          # xgboost.Booster
_STATS: dict = {}      # {benign_centroid, attack_centroid}
_STATUS: dict = {"ready": False, "reason": "not loaded"}


def status() -> dict:
    return dict(_STATUS)


def _load():
    global _MODEL, _STATS
    if _MODEL is not None:
        return _MODEL
    if not SETTINGS.threat_model_path.exists():
        _STATUS.update(ready=False, reason=f"missing {SETTINGS.threat_model_path.name} — run train/train_threat_model.py")
        _MODEL = False
        return None
    try:
        import joblib
        import xgboost as xgb

        _MODEL = xgb.Booster()
        _MODEL.load_model(str(SETTINGS.threat_model_path))
        if SETTINGS.embed_stats_path.exists():
            _STATS = joblib.load(SETTINGS.embed_stats_path)
        _STATUS.update(ready=True, reason="ok")
        return _MODEL
    except Exception as exc:
        _MODEL = False
        _STATUS.update(ready=False, reason=f"{type(exc).__name__}: {exc}")
        return None


def ready() -> bool:
    _load()
    return _STATUS["ready"]


def reload() -> bool:
    """Drop cached artifacts so the next classify() picks up a retrained
    threat_model.json (used by the vulnerability-retrain loop)."""
    global _MODEL, _STATS
    _MODEL = None
    _STATS = {}
    return ready()


def classify(sanitized_prompt: str) -> IntentResult:
    """Embed + XGBoost -> P(threat) in [0,1] plus the vector for L3/L4."""
    vec = embed(sanitized_prompt)
    booster = _load()
    if booster is None:
        from services.embedding_service import status as emb_status

        return IntentResult(
            intent_score=0.0,
            embedding_vector=vec.tolist(),
            model_used="fallback-hash" if emb_status()["degraded"] else "none",
            degraded=True,
        )
    t0 = time.perf_counter()
    try:
        import xgboost as xgb

        dx = xgb.DMatrix(vec.reshape(1, -1))
        proba = float(booster.predict(dx)[0])
        _STATUS.update(ready=True, reason=f"ok (infer {1000*(time.perf_counter()-t0):.1f}ms)")
        from services.embedding_service import status as emb_status

        return IntentResult(
            intent_score=min(max(proba, 0.0), 1.0),
            embedding_vector=vec.tolist(),
            model_used="semantic",
            degraded=emb_status()["degraded"],
        )
    except Exception as exc:
        _STATUS.update(ready=False, reason=f"{type(exc).__name__}: {exc}")
        return IntentResult(intent_score=0.0, embedding_vector=vec.tolist(),
                             model_used="none", degraded=True)


def centroids() -> tuple[np.ndarray | None, np.ndarray | None]:
    """(benign_centroid, attack_centroid) from training — used by L3 drift."""
    _load()
    return _STATS.get("benign_centroid"), _STATS.get("attack_centroid")


def block_threshold() -> float:
    return SETTINGS.intent_block_threshold
