"""
Feature extraction for the biometric ensemble (Tier 2).

The ensemble sees, per sample:
  - LSTM embedding of the (seq_len, 2) sequence            → 16d
  - hand-crafted stats of the sequence                     → 17d
  - deviation of the sample's dwell/flight means from the
    CLAIMED baseline means (the actual biometric signal)   → 2d

The deviation features are what carry the genuine-vs-impostor signal — absolute
timings alone don't separate the classes (a "different user" still types in the
same global range).
"""
from __future__ import annotations
from pathlib import Path

import joblib
import numpy as np

FEATURE_NAMES = [
    "lstm_0", "lstm_1", "lstm_2", "lstm_3", "lstm_4", "lstm_5", "lstm_6", "lstm_7",
    "lstm_8", "lstm_9", "lstm_10", "lstm_11", "lstm_12", "lstm_13", "lstm_14", "lstm_15",
    "dwell_mean", "dwell_std", "dwell_min", "dwell_max", "dwell_median",
    "dwell_skew", "dwell_p25", "dwell_p75",
    "flight_mean", "flight_std", "flight_min", "flight_max", "flight_median",
    "flight_skew", "flight_p25", "flight_p75",
    "dwell_flight_corr",
    "dwell_dev_from_baseline", "flight_dev_from_baseline",
]

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
SEQ_NORM_PATH = MODEL_DIR / "biometric_seq_norm.joblib"
STATS_NORM_PATH = MODEL_DIR / "biometric_stats_norm.joblib"


def _moments(x: np.ndarray) -> list[float]:
    mu = float(np.mean(x))
    sd = float(np.std(x)) or 1e-6
    sk = float(np.mean(((x - mu) / sd) ** 3)) if sd > 1e-6 else 0.0
    return [
        mu, sd,
        float(np.min(x)), float(np.max(x)), float(np.median(x)),
        sk,
        float(np.percentile(x, 25)), float(np.percentile(x, 75)),
    ]


def sequence_stats(seq: np.ndarray, baseline_dwell_mean: float = 0.0, baseline_flight_mean: float = 0.0) -> np.ndarray:
    """Stats + deviation features for one (seq_len, 2) sample.

    baseline_*_mean are the claimed user's baseline means; the deviation
    features (sample_mean − baseline_mean) are the core biometric signal.
    """
    d, f = seq[:, 0], seq[:, 1]
    feats = _moments(d) + _moments(f)
    if np.std(d) > 1e-6 and np.std(f) > 1e-6:
        corr = float(np.corrcoef(d, f)[0, 1])
    else:
        corr = 0.0
    feats.append(corr)
    # Deviation from claimed baseline (the signal). Signed so the model can tell
    # "faster" from "slower" impostor typing, not just "different".
    feats.append(float(np.mean(d)) - baseline_dwell_mean)
    feats.append(float(np.mean(f)) - baseline_flight_mean)
    return np.array(feats, dtype=np.float32)


def batch_stats(seqs: np.ndarray, baseline_means: np.ndarray | None = None) -> np.ndarray:
    """sequence_stats over a batch. baseline_means: (N, 2) or None."""
    out = []
    for i, s in enumerate(seqs):
        if baseline_means is not None:
            bdm, bfm = float(baseline_means[i, 0]), float(baseline_means[i, 1])
        else:
            bdm = bfm = 0.0
        out.append(sequence_stats(s, bdm, bfm))
    return np.stack(out).astype(np.float32)


class SeqNormalizer:
    """Per-channel (dwell/flight) z-normalization for LSTM inputs."""

    def __init__(self, mean=(90.0, 80.0), std=(25.0, 35.0)):
        self.mean = np.asarray(mean, dtype=np.float32)
        self.std = np.asarray(std, dtype=np.float32)

    def transform(self, seq: np.ndarray) -> np.ndarray:
        return (seq - self.mean) / self.std

    def fit(self, seqs: np.ndarray) -> "SeqNormalizer":
        flat = seqs.reshape(-1, 2)
        self.mean = flat.mean(axis=0).astype(np.float32)
        self.std = (flat.std(axis=0) + 1e-6).astype(np.float32)
        return self


def load_seq_normalizer() -> SeqNormalizer | None:
    if SEQ_NORM_PATH.exists():
        return joblib.load(SEQ_NORM_PATH)
    return None


def load_stats_scaler():
    if STATS_NORM_PATH.exists():
        return joblib.load(STATS_NORM_PATH)
    return None
