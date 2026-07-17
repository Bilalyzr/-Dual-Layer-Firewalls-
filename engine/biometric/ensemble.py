"""
Soft-voting ensemble for keystroke impostor detection (Req 3.3).

RandomForest + GradientBoosting (XGBoost-equivalent without the extra dep) +
MLP, averaged via VotingClassifier(voting='soft'). Input: LSTM embeddings (16d)
concatenated with hand-crafted stats (17d) = 33 features. Output: P(genuine).

Label convention (matches generate_keystrokes): 1 = genuine, 0 = impostor.
"""
from __future__ import annotations
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.neural_network import MLPClassifier

from .lstm_model import EMBED_DIM
from .features import FEATURE_NAMES

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "biometric_ensemble.joblib"

# Feature order: [LSTM embedding (EMBED_DIM)] + [stats]
FEATURE_ORDER = [f"lstm_{i}" for i in range(EMBED_DIM)] + FEATURE_NAMES


def build_ensemble(random_state: int = 42) -> VotingClassifier:
    """Construct the (untrained) soft-voting ensemble."""
    rf = RandomForestClassifier(
        n_estimators=120, max_depth=8, random_state=random_state, class_weight="balanced"
    )
    gb = GradientBoostingClassifier(
        n_estimators=120, max_depth=3, learning_rate=0.1, random_state=random_state
    )
    mlp = MLPClassifier(
        hidden_layer_sizes=(32,),
        max_iter=400,
        early_stopping=True,
        random_state=random_state,
    )
    return VotingClassifier(
        estimators=[("rf", rf), ("gb", gb), ("mlp", mlp)],
        voting="soft",
        weights=[1.0, 1.0, 0.7],
        n_jobs=None,
    )


# --------------------------------------------------------------------------- #
# Singleton loader
# --------------------------------------------------------------------------- #
_ensemble: VotingClassifier | None = None


def get_ensemble() -> VotingClassifier:
    global _ensemble
    if _ensemble is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"biometric ensemble artifact not found at {MODEL_PATH}. "
                "Run: python -m engine.biometric.train_biometric"
            )
        _ensemble = joblib.load(MODEL_PATH)
    return _ensemble


def ensemble_ready() -> bool:
    return MODEL_PATH.exists()


def predict_proba(features: np.ndarray) -> float:
    """
    Return P(genuine) for a single feature vector (1D or batched 2D).
    Mirrors the rest of the codebase's "score" semantics.
    """
    clf = get_ensemble()
    X = np.atleast_2d(features.astype(np.float32))
    proba = clf.predict_proba(X)[0]
    # classes_ ordering: Voting sorts labels ascending → [0=impostor, 1=genuine]
    idx = list(clf.classes_).index(1)
    return float(proba[idx])
