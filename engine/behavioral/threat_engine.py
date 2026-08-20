"""
Component 6 — Threat Determination via Random Forest (PRD §21-23).

Input: anomaly_score + contextual features → risk_score (0-100) → LOW/MEDIUM/HIGH.
The BA-ZTA paper uses a DNN with 3 outputs; the MVP uses Random Forest
(recommended by Paper 2 for strong experimental performance).
"""
from __future__ import annotations
import os
from pathlib import Path

import joblib
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
RF_PATH = MODEL_DIR / "behavioral_rf.joblib"


def _dnn_enabled() -> bool:
    """Advanced DNN threat model is opt-in via env (PRD §22.3, roadmap Phase 3).

    BEHAVIORAL_THREAT_MODEL=dnn selects the deep 3-class model when its artifact
    is present; otherwise we transparently fall back to the RF/heuristic path.
    """
    return os.getenv("BEHAVIORAL_THREAT_MODEL", "rf").lower() == "dnn"

# Risk thresholds (PRD §23 — proposed policy values, not from papers).
RISK_THRESHOLDS = {
    "low": (0, 30, "ALLOW"),
    "medium": (31, 70, "STEP_UP"),
    "high": (71, 100, "RESTRICT"),
}

_rf = None


def model_ready() -> bool:
    return RF_PATH.exists()


def _load():
    global _rf
    if _rf is None:
        if not model_ready():
            raise FileNotFoundError(
                f"behavioral RF not found at {RF_PATH}. Run: python -m engine.behavioral.train_behavioral"
            )
        _rf = joblib.load(RF_PATH)
    return _rf


def classify_risk(features: np.ndarray, anomaly_score: float) -> dict:
    """Classify the threat level from features + anomaly score.

    Returns { risk_score (0-100), risk_level, action }.
    """
    # Advanced path: deep 3-class threat DNN (PRD §22.3) when selected + present.
    if _dnn_enabled():
        try:
            from .dnn_threat import model_ready as dnn_ready, classify_risk_dnn
            if dnn_ready():
                return classify_risk_dnn(features, anomaly_score)
        except Exception:
            pass  # fall through to RF/heuristic — DNN is never the sole authority

    if not model_ready():
        # Fallback: derive risk from anomaly_score alone when model isn't trained.
        risk = round(anomaly_score * 100, 1)
        level = _score_to_level(risk)
        return {"risk_score": risk, "risk_level": level, "action": _level_to_action(level), "model_used": "heuristic"}

    rf = _load()
    # Append anomaly_score as an extra feature.
    X = np.append(features, anomaly_score).reshape(1, -1)
    proba = rf.predict_proba(X)[0]
    # Binary RF: proba has 2 entries [P(normal), P(anomalous)]
    p_normal = float(proba[0]) if len(proba) > 0 else 1.0
    p_anom = float(proba[1]) if len(proba) > 1 else 0.0
    # Risk score: blend anomaly probability + anomaly_score
    risk = round((p_anom * 0.5 + anomaly_score * 0.5) * 100, 1)
    risk = min(100, max(0, risk))
    level = _score_to_level(risk)
    return {
        "risk_score": risk,
        "risk_level": level,
        "action": _level_to_action(level),
        "model_used": "random_forest",
        "probabilities": {"normal": round(p_normal, 3), "anomalous": round(p_anom, 3)},
    }


def _score_to_level(score: float) -> str:
    if score <= 30:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    return "HIGH"


def _level_to_action(level: str) -> str:
    return RISK_THRESHOLDS.get(level.lower(), (0, 0, "ALLOW"))[2]
