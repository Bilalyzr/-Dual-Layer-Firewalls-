"""
EPIC F — Ensemble prompt classifier (Tier 3 Wave 3).

Replaces the single TF-IDF+LogReg with a soft-voting ensemble:
  - LogisticRegression  (fast linear baseline)
  - LinearSVC (calibrated) (margin-based)
  - RandomForest         (non-linear)
soft-voted on P(threat).

Plus a DistilBERT embedding-outlier path (`embedding_firewall.py`) that catches
novel injections the lexical models miss (OWASP LLM08 gap).

The TF-IDF vectorizer is SHARED across the three sklearn estimators (fit once).
DistilBERT runs only when `EMBEDDING_FIREWALL_ENABLED=true` AND the model is
available (heavy; CPU-fallback slow but correct).
"""
from __future__ import annotations
import joblib
from pathlib import Path

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
VECT_PATH = MODEL_DIR / "tfidf.joblib"          # shared, same as Tier 1
ENSEMBLE_PATH = MODEL_DIR / "clf_ensemble.joblib"  # dict of fitted estimators
CALIB_PATH = MODEL_DIR / "calib.joblib"         # optional isotonic map (vote -> true P(threat))
THREAT_LABEL = 0


def build_estimators(random_state: int = 42) -> dict:
    """Construct the (unfitted) estimator set."""
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state)
    # LinearSVC has no predict_proba → calibrate it (Platt scaling via CV).
    svc = CalibratedClassifierCV(
        LinearSVC(class_weight="balanced", random_state=random_state, max_iter=2000),
        cv=3,
    )
    rf = RandomForestClassifier(
        n_estimators=120, max_depth=8, class_weight="balanced", random_state=random_state
    )
    return {"lr": lr, "svc": svc, "rf": rf}


class EnsembleClassifier:
    """Loads shared vectorizer + the three fitted estimators; soft-votes."""

    def __init__(self) -> None:
        self.vectorizer = joblib.load(VECT_PATH)
        ests = joblib.load(ENSEMBLE_PATH)
        self.estimators = ests
        self.classes_ = ests["lr"].classes_  # all share the same label space
        # Optional isotonic calibration: raw soft-votes are over-confident
        # near the boundary; calib.joblib maps them to honest probabilities.
        self.calibrator = joblib.load(CALIB_PATH) if CALIB_PATH.exists() else None

    def predict_proba(self, text: str) -> float:
        """Soft-voted P(threat), isotonic-calibrated when calib.joblib exists."""
        if not text or not text.strip():
            return 0.0
        X = self.vectorizer.transform([text])
        probs = []
        for name in ("lr", "svc", "rf"):
            est = self.estimators[name]
            p = est.predict_proba(X)[0]
            idx = list(est.classes_).index(THREAT_LABEL)
            probs.append(float(p[idx]))
        # simple mean soft-vote
        vote = sum(probs) / len(probs)
        if self.calibrator is not None:
            return float(min(1.0, max(0.0, self.calibrator.predict([vote])[0])))
        return vote


_singleton: EnsembleClassifier | None = None
_MTIME: float = 0.0  # artifact mtime at last load — hot-reload after retrain


def _artifacts_mtime() -> float:
    paths = [VECT_PATH, ENSEMBLE_PATH]
    if CALIB_PATH.exists():
        paths.append(CALIB_PATH)
    try:
        return max(p.stat().st_mtime for p in paths)
    except OSError:
        return 0.0


def get_ensemble() -> EnsembleClassifier:
    global _singleton, _MTIME
    mtime = _artifacts_mtime()
    if _singleton is None or (mtime and mtime != _MTIME):
        _singleton = EnsembleClassifier()
        _MTIME = mtime
    return _singleton


def ensemble_ready() -> bool:
    return VECT_PATH.exists() and ENSEMBLE_PATH.exists()
