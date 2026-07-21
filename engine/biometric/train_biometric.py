"""
Train the Tier-2 biometric model: LSTM (feature extractor) + soft-voting
ensemble (RF + GB + MLP). Persists artifacts to engine/models/.

Two-stage training:
  Stage 1 — train the LSTM as an impostor classifier. With deviation-aware
            data it learns temporal consistency relative to a baseline.
  Stage 2 — freeze the LSTM, embed sequences, concatenate with stats (incl.
            deviation features), train the ensemble.

Run:  python -m engine.biometric.train_biometric
"""
from __future__ import annotations
import json
import random
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

from .features import (
    FEATURE_NAMES,
    MODEL_DIR,
    STATS_NORM_PATH,
    SEQ_NORM_PATH,
    SeqNormalizer,
    batch_stats,
)
from .lstm_model import EMBED_DIM, MODEL_PATH, KeystrokeLSTM, embed_batch
from .ensemble import MODEL_PATH as ENSEMBLE_PATH, build_ensemble
from .generate_keystrokes import build_dataset

EPOCHS = 15
BATCH = 64
LR = 3e-3
SEED = 42
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def _seed_everything(seed: int = SEED) -> None:
    """Make training reproducible across runs.

    Without this the LSTM weight init, the Adam updates, and the minibatch
    shuffle all draw from un-seeded global RNGs, so each training run produces a
    slightly different model. The Tier-2 discrimination margin then varies
    run-to-run and the genuine-vs-impostor tests flake in CI. Seeding every RNG
    the pipeline touches pins the model — and the margin — deterministically.
    """
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)


def _iterate_minibatches(*arrays, batch_size: int, shuffle: bool = True, rng=None):
    n = arrays[0].shape[0]
    idx = np.arange(n)
    if shuffle:
        (rng or np.random).shuffle(idx)
    for start in range(0, n, batch_size):
        sl = idx[start : start + batch_size]
        yield tuple(a[sl] for a in arrays)


def train_lstm(X_train, y_train, X_test, y_test) -> KeystrokeLSTM:
    model = KeystrokeLSTM().to(DEVICE)
    clf_head = nn.Linear(EMBED_DIM, 2).to(DEVICE)
    params = list(model.parameters()) + list(clf_head.parameters())
    opt = torch.optim.Adam(params, lr=LR, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss()

    Xtr = torch.from_numpy(X_train).to(DEVICE)
    ytr = torch.from_numpy(y_train.astype(np.int64)).to(DEVICE)

    for epoch in range(EPOCHS):
        model.train(); clf_head.train()
        total = 0.0
        for xb, yb in _iterate_minibatches(Xtr, ytr, batch_size=BATCH):
            opt.zero_grad()
            emb = model(xb)
            logits = clf_head(emb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()
            total += loss.item() * xb.size(0)
        if (epoch + 1) % 3 == 0:
            model.eval()
            with torch.no_grad():
                emb_te = model(torch.from_numpy(X_test).to(DEVICE))
                logits_te = clf_head(emb_te)
                pred = logits_te.argmax(1).cpu().numpy()
            acc = float((pred == y_test).mean())
            print(f"  [lstm] epoch {epoch+1:02d}  loss={total/len(ytr):.4f}  test_acc={acc:.3f}")
    return model


def main() -> dict:
    _seed_everything()
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    print("[biometric] generating synthetic keystroke dataset...")
    split, names = build_dataset()
    (Xtr_seq, Xtr_extra, ytr), (Xte_seq, Xte_extra, yte) = split["train"], split["test"]
    print(f"[biometric] train={len(ytr)} test={len(yte)} seq_len={Xtr_seq.shape[1]}")

    # ---- Fit normalizers --------------------------------------------------
    print("[biometric] fitting normalizers...")
    seq_norm = SeqNormalizer().fit(Xtr_seq)
    Xtr_seq_n = seq_norm.transform(Xtr_seq)
    Xte_seq_n = seq_norm.transform(Xte_seq)

    # Stats (now deviation-aware) + scaler
    Xtr_stats = batch_stats(Xtr_seq, Xtr_extra)
    Xte_stats = batch_stats(Xte_seq, Xte_extra)
    stats_scaler = StandardScaler().fit(Xtr_stats)
    Xtr_stats_n = stats_scaler.transform(Xtr_stats).astype(np.float32)
    Xte_stats_n = stats_scaler.transform(Xte_stats).astype(np.float32)

    # ---- Stage 1: LSTM ----------------------------------------------------
    print("[biometric] stage 1: training LSTM feature extractor...")
    model = train_lstm(Xtr_seq_n, ytr, Xte_seq_n, yte)
    torch.save(model.state_dict(), MODEL_PATH)
    joblib.dump(seq_norm, SEQ_NORM_PATH)
    joblib.dump(stats_scaler, STATS_NORM_PATH)

    # ---- Stage 2: ensemble on embeddings + stats -------------------------
    print("[biometric] stage 2: training RF+GB+MLP ensemble...")
    import engine.biometric.lstm_model as L
    L._model = None  # reload singleton with fresh weights

    Xtr_emb = embed_batch(Xtr_seq_n)
    Xte_emb = embed_batch(Xte_seq_n)
    Xtr_full = np.concatenate([Xtr_emb, Xtr_stats_n], axis=1).astype(np.float32)
    Xte_full = np.concatenate([Xte_emb, Xte_stats_n], axis=1).astype(np.float32)

    clf = build_ensemble()
    clf.fit(Xtr_full, ytr)
    joblib.dump(clf, ENSEMBLE_PATH)

    # ---- Report -----------------------------------------------------------
    ypred = clf.predict(Xte_full)
    report = classification_report(yte, ypred, output_dict=True, zero_division=0)
    metrics = {
        "test_support": int(len(yte)),
        "genuine_f1": round(report.get("1", {}).get("f1-score", 0.0), 3),
        "impostor_f1": round(report.get("0", {}).get("f1-score", 0.0), 3),
        "macro_f1": round(report.get("macro avg", {}).get("f1-score", 0.0), 3),
        "accuracy": round(float((ypred == yte).mean()), 3),
        "lstm_embed_dim": EMBED_DIM,
        "feature_count": Xtr_full.shape[1],
    }
    (MODEL_DIR / "biometric_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[biometric] done. metrics: {metrics}")
    print(f"[biometric] artifacts -> {MODEL_PATH.name}, {ENSEMBLE_PATH.name}, seq_norm, stats_norm")
    return metrics


if __name__ == "__main__":
    main()
