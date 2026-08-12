"""
Component 6 (advanced) — DNN Threat Determination (PRD §22.3, §28, roadmap Phase 3).

The BA-ZTA paper uses a Deep Neural Network with three threat outputs
(LOW / MEDIUM / HIGH). The MVP threat layer (``threat_engine.py``) uses a
binary Random Forest; this module adds the deeper 3-class classifier that the
research describes as the advanced threat-determination model.

Design goals (mirrors the biometric LSTM — lightweight, CPU-only):
  - trains in seconds on CPU, ~few-K params
  - input  = behavioral feature vector (FEATURE_DIM) + anomaly_score  (25 + 1)
  - output = softmax over 3 classes [LOW, MEDIUM, HIGH]

The DNN is NOT the final security authority — it produces a risk level/score
that the policy engine (``response.py``) turns into an ALLOW/STEP_UP/RESTRICT
decision, exactly like the RF path. When the artifact is absent, callers fall
back to the RF/heuristic path, so the DNN is a drop-in advanced upgrade.
"""
from __future__ import annotations
from pathlib import Path

import numpy as np

try:
    import torch
    import torch.nn as nn
    _TORCH_OK = True
except Exception:  # pragma: no cover — torch optional at import time
    _TORCH_OK = False

from .features import FEATURE_DIM

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
DNN_PATH = MODEL_DIR / "behavioral_dnn.pt"

# Input = feature vector + the One-Class SVM anomaly score (appended).
INPUT_DIM = FEATURE_DIM + 1
CLASSES = ["LOW", "MEDIUM", "HIGH"]
# Representative risk score per class (0-100) — used to emit a numeric score
# consistent with the RF path when the DNN is the active model.
CLASS_SCORE = {"LOW": 15.0, "MEDIUM": 55.0, "HIGH": 90.0}


if _TORCH_OK:

    class ThreatDNN(nn.Module):
        """A small MLP: input -> 64 -> 32 -> 3 (LOW/MEDIUM/HIGH logits)."""

        def __init__(self, input_dim: int = INPUT_DIM, n_classes: int = 3):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(32, n_classes),
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            return self.net(x)


# --------------------------------------------------------------------------- #
# Singleton loader
# --------------------------------------------------------------------------- #
_model = None
_mean = None
_std = None


def model_ready() -> bool:
    return _TORCH_OK and DNN_PATH.exists()


def _load():
    """Lazy-load the trained DNN + its input-normalization stats."""
    global _model, _mean, _std
    if _model is None:
        if not model_ready():
            raise FileNotFoundError(
                f"behavioral DNN not found at {DNN_PATH}. "
                "Run: python -m engine.behavioral.generate_behavioral_data --dnn"
            )
        ckpt = torch.load(DNN_PATH, map_location="cpu", weights_only=False)
        m = ThreatDNN(input_dim=ckpt.get("input_dim", INPUT_DIM))
        m.load_state_dict(ckpt["state_dict"])
        m.eval()
        _model = m
        _mean = np.asarray(ckpt["mean"], dtype=np.float32)
        _std = np.asarray(ckpt["std"], dtype=np.float32)
    return _model, _mean, _std


def classify_risk_dnn(features: np.ndarray, anomaly_score: float) -> dict:
    """Classify LOW/MEDIUM/HIGH threat using the DNN.

    Returns { risk_score (0-100), risk_level, action, model_used, probabilities }.
    Shape-compatible with ``threat_engine.classify_risk``.
    """
    model, mean, std = _load()
    x = np.append(features.astype(np.float32), np.float32(anomaly_score))
    x = (x - mean) / std
    with torch.no_grad():
        logits = model(torch.from_numpy(x).float().unsqueeze(0))
        probs = torch.softmax(logits, dim=1).numpy()[0]

    idx = int(np.argmax(probs))
    level = CLASSES[idx]
    # Continuous score: probability-weighted blend of per-class anchor scores,
    # nudged by the raw anomaly signal so the gauge still moves within a class.
    base = float(sum(probs[i] * CLASS_SCORE[CLASSES[i]] for i in range(len(CLASSES))))
    risk = round(min(100.0, max(0.0, 0.85 * base + 0.15 * anomaly_score * 100)), 1)

    from .threat_engine import _level_to_action

    return {
        "risk_score": risk,
        "risk_level": level,
        "action": _level_to_action(level),
        "model_used": "dnn",
        "probabilities": {
            "low": round(float(probs[0]), 3),
            "medium": round(float(probs[1]), 3),
            "high": round(float(probs[2]), 3),
        },
    }
