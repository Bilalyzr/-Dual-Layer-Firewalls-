"""
Synthetic keystroke-dynamics dataset generator (Tier 2).

Key insight (corrected): the biometric signal is NOT absolute timing — it's the
*deviation between a typing sample and the claimed user's baseline*. Pooled
absolute timings are statistically identical for genuine vs impostor users, so
the model must see deltas. This mirrors how score_batch actually scores: a
batch against a per-user Baseline.

Each training example is a (baseline_seq, sample_seq) pair from one user:
  - Genuine pair: baseline + sample both drawn from the SAME user → small deltas.
  - Impostor pair: baseline from user A, sample from user B → deltas reflect a
    different typing distribution.

Features passed to the ensemble are computed from the SAMPLE sequence plus the
delta against the baseline mean — exactly what the live scorer has available.

Labels: 1 = genuine, 0 = impostor.

Output: engine/biometric/keystrokes_dataset.npz
Run:  python -m engine.biometric.generate_keystrokes
"""
from __future__ import annotations
import random
from pathlib import Path

import numpy as np

OUT = Path(__file__).resolve().parent / "keystrokes_dataset.npz"

SEQ_LEN = 60
N_USERS = 40
GENUINE_PER_USER = 80
IMPOSTOR_PER_USER = 80
TRAIN_SPLIT = 0.8

DWELL_RANGE = (60.0, 130.0)
FLIGHT_RANGE = (40.0, 160.0)


def _make_user(rng: random.Random) -> dict:
    return {
        "dwell_mean": rng.uniform(*DWELL_RANGE),
        "flight_mean": rng.uniform(*FLIGHT_RANGE),
        "dwell_std": rng.uniform(8.0, 22.0),
        "flight_std": rng.uniform(10.0, 35.0),
        "drift": rng.uniform(-0.0008, 0.0008),
    }


def _sample_sequence(user: dict, rng: random.Random, length: int = SEQ_LEN) -> np.ndarray:
    out = np.zeros((length, 2), dtype=np.float32)
    dm, fm = user["dwell_mean"], user["flight_mean"]
    ds, fs = user["dwell_std"], user["flight_std"]
    drift = user["drift"]
    for t in range(length):
        m_d = dm * (1.0 + drift * t)
        m_f = fm * (1.0 + drift * t)
        d = max(20.0, min(400.0, float(rng.gauss(m_d, ds))))
        f = max(10.0, min(500.0, float(rng.gauss(m_f, fs))))
        out[t, 0] = d
        out[t, 1] = f
    return out


def build_dataset(seed: int = 42):
    """Build (sample_seq, baseline_mean_vec) pairs with genuine/impostor labels.

    Returns split dict + feature_names. The sample sequence is what the LSTM
    sees; the baseline-mean vector is appended as 2 extra features so the
    ensemble can model deviation. This is the minimal info the live scorer has.
    """
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    users = [_make_user(rng) for _ in range(N_USERS)]

    X_seq, X_extra, y = [], [], []
    # extra = [baseline_dwell_mean, baseline_flight_mean] — lets the model
    # learn deviation from the claimed user.

    for i, user in enumerate(users):
        baseline_seq = _sample_sequence(user, rng)
        bl_dm, bl_fm = float(baseline_seq[:, 0].mean()), float(baseline_seq[:, 1].mean())
        # Genuine: sample from same user.
        for _ in range(GENUINE_PER_USER):
            seq = _sample_sequence(user, rng)
            X_seq.append(seq)
            X_extra.append([bl_dm, bl_fm])
            y.append(1)
        # Impostor: sample from a different user's distribution, but the
        # *claimed baseline* is still this user's.
        for _ in range(IMPOSTOR_PER_USER):
            other = users[(i + 1 + rng.randint(1, N_USERS - 1)) % N_USERS]
            seq = _sample_sequence(other, rng)
            X_seq.append(seq)
            X_extra.append([bl_dm, bl_fm])
            y.append(0)

    X_seq = np.stack(X_seq).astype(np.float32)
    X_extra = np.array(X_extra, dtype=np.float32)
    y = np.array(y, dtype=np.int32)

    idx = np_rng.permutation(len(y))
    X_seq, X_extra, y = X_seq[idx], X_extra[idx], y[idx]

    n = len(y)
    cut = int(n * TRAIN_SPLIT)
    return {
        "train": (X_seq[:cut], X_extra[:cut], y[:cut]),
        "test": (X_seq[cut:], X_extra[cut:], y[cut:]),
    }, FEATURE_NAMES


FEATURE_NAMES = [
    "lstm_" + str(i) for i in range(16)
] + [
    "dwell_mean", "dwell_std", "dwell_min", "dwell_max", "dwell_median",
    "dwell_skew", "dwell_p25", "dwell_p75",
    "flight_mean", "flight_std", "flight_min", "flight_max", "flight_median",
    "flight_skew", "flight_p25", "flight_p75",
    "dwell_flight_corr",
    # deviation features (the actual biometric signal):
    "dwell_dev_from_baseline", "flight_dev_from_baseline",
]


def main() -> None:
    split, names = build_dataset()
    (Xtr_seq, Xtr_extra, ytr), (Xte_seq, Xte_extra, yte) = split["train"], split["test"]
    np.savez_compressed(
        OUT,
        X_train_seq=Xtr_seq, X_train_extra=Xtr_extra, y_train=ytr,
        X_test_seq=Xte_seq, X_test_extra=Xte_extra, y_test=yte,
        feature_names=np.array(names),
    )
    genuine = int((ytr == 1).sum()) + int((yte == 1).sum())
    impostor = int((ytr == 0).sum()) + int((yte == 0).sum())
    print(f"[keystrokes] wrote {len(ytr) + len(yte)} pairs -> {OUT}")
    print(f"[keystrokes] genuine={genuine} impostor={impostor} features={len(names)} seq_len={Xtr_seq.shape[1]}")


if __name__ == "__main__":
    main()
