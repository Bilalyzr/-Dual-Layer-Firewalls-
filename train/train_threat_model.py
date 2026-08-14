"""
Train the semantic threat model (PDF §2.3.1 — two-stage methodology).

Stage 1 (optional, CONTRASTIVE_FINE_TUNE=true): contrastive fine-tuning of the
MiniLM encoder with Triplet Loss  L = max(0, d(A,P) - d(A,N) + a)
(anchor & positive = same-intent attacks, negative = benign) so attack vectors
cluster together in embedding space, cleanly separated from benign queries.

Stage 2 (default): FREEZE the embedding model and train an XGBoost binary
head on the resulting vectors -> models/threat_model.json. Also persists the
benign/attack centroids (models/embed_stats.joblib) used by L3 for
semantic-drift / attack-proximity scoring.

Reports the hold-out confusion matrix — the false-positive rate is the
#1 production risk (PDF §3.2).

Run from repo root:
    python -m train.train_threat_model
    CONTRASTIVE_FINE_TUNE=true python -m train.train_threat_model   # + stage 1
"""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config import SETTINGS  # noqa: E402
from services.embedding_service import _load  # noqa: E402

DATASET = ROOT / "engine" / "classifier" / "jailbreak_dataset.csv"
THREAT_LABEL = 0  # dataset convention: 0 = threat/jailbreak, 1 = benign
SEED = 42
random.seed(SEED)

CONTRASTIVE = os.getenv("CONTRASTIVE_FINE_TUNE", "false").lower() in ("1", "true", "yes")
CONTRASTIVE_EPOCHS = int(os.getenv("CONTRASTIVE_EPOCHS", "1"))
MARGIN = 0.5  # triplet margin a


def load_dataset() -> list[tuple[str, int]]:
    import csv

    rows: list[tuple[str, int]] = []
    with open(DATASET, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            text = (r.get("text") or "").strip()
            label = r.get("label")
            if text and label not in (None, ""):
                rows.append((text, int(float(label))))
    return rows


def embed_all(texts: list[str], model) -> np.ndarray:
    out = model.encode(texts, convert_to_numpy=True, normalize_embeddings=True,
                       show_progress_bar=False, batch_size=64)
    return np.asarray(out, dtype=np.float32)


# --------------------------------------------------------------------------- #
# Stage 1 — contrastive triplet fine-tuning (PDF formula in module docstring)
# --------------------------------------------------------------------------- #
def contrastive_finetune(model, rows: list[tuple[str, int]]) -> dict:
    attacks = [t for t, l in rows if l == THREAT_LABEL]
    benigns = [t for t, l in rows if l != THREAT_LABEL]
    if len(attacks) < 2 or not benigns:
        return {"skipped": "insufficient data for triplets"}

    # Build triplets: anchor/positive = two distinct attacks, negative = benign.
    n_trip = min(len(attacks) * 2, 2000)
    triplets = []
    for _ in range(n_trip):
        a, p = random.sample(attacks, 2)
        triplets.append([a, p, random.choice(benigns)])

    try:
        from sentence_transformers import InputExample, losses
        from torch.utils.data import DataLoader
    except Exception as exc:
        return {"skipped": f"torch/sentence-transformers unavailable: {exc}"}

    examples = [InputExample(texts=t) for t in triplets]
    dl = DataLoader(examples, shuffle=True, batch_size=32)
    loss = losses.TripletLoss(model=model, distance_metric=losses.TripletDistanceMetric.COSINE,
                              margin=MARGIN)
    model.fit(train_objectives=[(dl, loss)], epochs=CONTRASTIVE_EPOCHS,
              warmup_steps=10, show_progress_bar=False)
    return {"triplets": len(triplets), "epochs": CONTRASTIVE_EPOCHS, "margin": MARGIN}


# --------------------------------------------------------------------------- #
# Stage 2 — frozen embeddings + XGBoost head
# --------------------------------------------------------------------------- #
def train_xgboost(X: np.ndarray, y: np.ndarray) -> tuple[object, dict]:
    import xgboost as xgb
    from sklearn.metrics import confusion_matrix
    from sklearn.model_selection import train_test_split

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=SEED, stratify=y)
    dtrain = xgb.DMatrix(Xtr, label=ytr)
    dtest = xgb.DMatrix(Xte, label=yte)
    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 6,
        "eta": 0.2,
        "subsample": 0.9,
        "colsample_bytree": 0.9,
        "seed": SEED,
    }
    booster = xgb.train(params, dtrain, num_boost_round=300,
                        evals=[(dtest, "holdout")], early_stopping_rounds=20, verbose_eval=False)
    proba = booster.predict(dtest)
    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    metrics = {
        "holdout_support": int(len(yte)),
        "accuracy": round(float((tp + tn) / max(1, tp + tn + fp + fn)), 4),
        "false_positive_rate": round(float(fp / max(1, fp + tn)), 4),
        "false_negative_rate": round(float(fn / max(1, fn + tp)), 4),
    }
    return booster, metrics


def main() -> dict:
    if not DATASET.exists():
        raise SystemExit(f"dataset missing: {DATASET}")

    model = _load()
    if not model:
        raise SystemExit("embedding model unavailable — check network / model cache")

    rows = load_dataset()
    texts = [t for t, _ in rows]
    labels = np.array([1 if l == THREAT_LABEL else 0 for _, l in rows], dtype=int)
    print(f"[train] {len(rows)} rows ({int(labels.sum())} threat / {int((1-labels).sum())} benign)")

    stage1: dict = {"skipped": "disabled (set CONTRASTIVE_FINE_TUNE=true)"}
    if CONTRASTIVE:
        print("[train] stage 1: contrastive triplet fine-tuning …")
        stage1 = contrastive_finetune(model, rows)
        print(f"[train] stage 1 result: {stage1}")
    else:
        print("[train] stage 1 skipped (frozen encoder — PDF stage 2 path)")

    print("[train] embedding corpus (frozen) …")
    X = embed_all(texts, model)

    print("[train] stage 2: XGBoost head …")
    booster, m = train_xgboost(X, labels)
    print(f"[train] holdout: {m}")

    SETTINGS.threat_model_path.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(SETTINGS.threat_model_path))

    import joblib

    stats = {
        "benign_centroid": X[labels == 0].mean(axis=0),
        "attack_centroid": X[labels == 1].mean(axis=0),
    }
    joblib.dump(stats, SETTINGS.embed_stats_path)

    result = {
        "rows": len(rows),
        "embedding_dim": int(X.shape[1]),
        "stage1_contrastive": stage1,
        "stage2_xgboost": m,
        "artifacts": {
            "threat_model": str(SETTINGS.threat_model_path),
            "embed_stats": str(SETTINGS.embed_stats_path),
        },
    }
    print(f"[train] done -> {SETTINGS.threat_model_path.name}")
    return result


if __name__ == "__main__":
    print(main())
