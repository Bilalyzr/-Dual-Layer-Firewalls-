"""
Component 4 — Constant Behavior Analysis via One-Class SVM (PRD §15-17).

The BA-ZTA paper's core anomaly detector. Trained on NORMAL user activity
only — learns "what is normal?" rather than requiring attack examples.

Output: anomaly_score (0..1, where 1 = far outside normal boundary).
"""
from __future__ import annotations
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.svm import OneClassSVM

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
SVM_PATH = MODEL_DIR / "behavioral_svm.joblib"
SCALER_PATH = MODEL_DIR / "behavioral_scaler.joblib"

_svm = None
_scaler = None


def model_ready() -> bool:
    return SVM_PATH.exists() and SCALER_PATH.exists()


def _load():
    global _svm, _scaler
    if _svm is None:
        if not model_ready():
            raise FileNotFoundError(
                f"behavioral SVM not found at {SVM_PATH}. Run: python -m engine.behavioral.train_behavioral"
            )
        _svm = joblib.load(SVM_PATH)
        _scaler = joblib.load(SCALER_PATH)
    return _svm, _scaler


def score_anomaly(features: np.ndarray) -> float:
    """Score a feature vector — returns anomaly_score 0..1 (1 = very anomalous)."""
    if not model_ready():
        return 0.0
    svm, scaler = _load()
    X = scaler.transform(np.atleast_2d(features))
    raw = svm.score_samples(X)[0]
    # Sigmoid mapping: raw=0 → 0.5, raw=+large → ~0, raw=-large → ~1
    anomaly = 1.0 / (1.0 + np.exp(raw * 5))
    return float(anomaly)


def predict(features: np.ndarray) -> dict:
    """Full SVM prediction — anomaly_score + inlier/outlier label."""
    if not model_ready():
        return {"anomaly_score": 0.0, "is_anomaly": False, "ready": False}
    svm, scaler = _load()
    X = scaler.transform(np.atleast_2d(features))
    raw = svm.score_samples(X)[0]
    pred = svm.predict(X)[0]  # +1 = inlier, -1 = outlier
    # Sigmoid mapping + outlier bonus: if SVM predicts outlier, floor at 0.6
    anomaly = 1.0 / (1.0 + np.exp(raw * 5))
    if pred == -1:
        anomaly = max(0.6, anomaly)  # outliers are at least 0.6 anomalous
    return {
        "anomaly_score": round(float(anomaly), 4),
        "is_anomaly": bool(pred == -1),
        "raw_score": round(float(raw), 4),
        "ready": True,
    }
