"""
Synthetic behavioral data generator + model trainer (PRD §31-32).

Generates normal + anomalous behavioral events, then trains:
  1. One-Class SVM on NORMAL data only (learns "what is normal")
  2. Random Forest on normal (label=0) vs anomalous (label=1) data
  3. (--dnn) 3-class DNN threat model on LOW/MEDIUM/HIGH data (PRD §22.3)

Persists to engine/models/behavioral_svm.joblib + behavioral_rf.joblib +
behavioral_scaler.joblib (+ behavioral_dnn.pt when --dnn is passed).
"""
from __future__ import annotations
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .telemetry import Telemetry
from .features import extract_features, FEATURE_DIM

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
N_USERS = 30
NORMAL_PER_USER = 100
ANOMALOUS_PER_USER = 100


def _make_normal(rng: random.Random, user_id: str) -> Telemetry:
    """Generate a normal behavioral event for this user."""
    hour = rng.randint(9, 17)
    day = rng.randint(0, 4)  # Mon-Fri
    devices = [f"laptop-{user_id}", f"desktop-{user_id}"]
    res_types = ["web_page", "report", "crm", "api"]
    res_sens = ["low", "medium"]
    return Telemetry(
        user_id=user_id,
        role=rng.choice(["user", "developer", "manager"]),
        device_id=rng.choice(devices),
        device_type="laptop",
        device_trust=rng.uniform(0.7, 1.0),
        registered_device=True,
        device_change=False,
        country="IN",
        region="TN",
        location_change=False,
        location_frequency=rng.uniform(0.7, 1.0),
        hour=hour,
        day_of_week=day,
        working_hours=True,
        working_day=True,
        time_since_prev_request=rng.uniform(60, 600),
        session_duration=rng.uniform(300, 3600),
        request_count=rng.randint(1, 30),
        failed_auth_count=0,
        resource_type=rng.choice(res_types),
        resource_sensitivity=rng.choice(res_sens),
        request_frequency=rng.uniform(5, 25),
        resource_access_frequency=rng.uniform(2, 15),
    )


def _make_anomalous(rng: random.Random, user_id: str) -> Telemetry:
    """Generate an anomalous behavioral event — contextually suspicious."""
    hour = rng.choice([rng.randint(0, 5), rng.randint(22, 23)])  # off-hours
    day = rng.choice([5, 6])  # weekend
    res_types = ["database", "credential_vault", "admin_panel", "export"]
    res_sens = ["high", "critical"]
    return Telemetry(
        user_id=user_id,
        role=rng.choice(["user", "developer"]),
        device_id=f"unknown-{rng.randint(1000, 9999)}",
        device_type=rng.choice(["mobile", "unknown"]),
        device_trust=rng.uniform(0.0, 0.3),
        registered_device=False,
        device_change=True,
        country=rng.choice(["US", "RU", "CN", "XX"]),
        region="UNKNOWN",
        location_change=True,
        location_frequency=rng.uniform(0.0, 0.2),
        hour=hour,
        day_of_week=day,
        working_hours=False,
        working_day=False,
        time_since_prev_request=rng.uniform(0.1, 5),
        session_duration=rng.uniform(10, 60),
        request_count=rng.randint(50, 200),
        failed_auth_count=rng.randint(1, 5),
        resource_type=rng.choice(res_types),
        resource_sensitivity=rng.choice(res_sens),
        request_frequency=rng.uniform(50, 200),
        resource_access_frequency=rng.uniform(20, 80),
    )


def _make_medium(rng: random.Random, user_id: str) -> Telemetry:
    """Generate a MEDIUM-risk event — meaningful but non-severe deviation.

    One or two signals are off (e.g. slightly off-hours OR a new-but-plausible
    device OR elevated frequency), but not the full anomalous combination.
    Used to train the 3-class DNN's middle class (PRD §22.3).
    """
    off_hours = rng.random() < 0.5
    hour = rng.choice([7, 8, 18, 19, 20]) if off_hours else rng.randint(9, 17)
    day = rng.randint(0, 4)
    device_change = rng.random() < 0.5
    return Telemetry(
        user_id=user_id,
        role=rng.choice(["user", "developer", "manager"]),
        device_id=(f"newlaptop-{rng.randint(10, 99)}" if device_change else f"laptop-{user_id}"),
        device_type="laptop",
        device_trust=rng.uniform(0.4, 0.7),
        registered_device=not device_change,
        device_change=device_change,
        country="IN",
        region="TN",
        location_change=rng.random() < 0.3,
        location_frequency=rng.uniform(0.3, 0.6),
        hour=hour,
        day_of_week=day,
        working_hours=not off_hours,
        working_day=True,
        time_since_prev_request=rng.uniform(10, 120),
        session_duration=rng.uniform(120, 1800),
        request_count=rng.randint(20, 60),
        failed_auth_count=rng.choice([0, 0, 1]),
        resource_type=rng.choice(["report", "crm", "api", "export"]),
        resource_sensitivity=rng.choice(["medium", "high"]),
        request_frequency=rng.uniform(25, 55),
        resource_access_frequency=rng.uniform(10, 30),
    )


def generate_dataset(seed: int = 42):
    """Generate (X_normal, X_anomalous) feature arrays."""
    rng = random.Random(seed)
    users = [f"U{i:03d}" for i in range(N_USERS)]

    normal_feats = []
    anomalous_feats = []

    for uid in users:
        for _ in range(NORMAL_PER_USER):
            t = _make_normal(rng, uid)
            normal_feats.append(extract_features(t))
        for _ in range(ANOMALOUS_PER_USER):
            t = _make_anomalous(rng, uid)
            anomalous_feats.append(extract_features(t))

    X_normal = np.stack(normal_feats).astype(np.float32)
    X_anomalous = np.stack(anomalous_feats).astype(np.float32)
    return X_normal, X_anomalous


def train():
    """Train One-Class SVM (on normal) + Random Forest (on labeled)."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    print("[behavioral] generating dataset...")
    X_normal, X_anomalous = generate_dataset()
    print(f"[behavioral] normal={len(X_normal)} anomalous={len(X_anomalous)} features={FEATURE_DIM}")

    # Fit scaler on normal data
    print("[behavioral] fitting scaler...")
    scaler = StandardScaler().fit(X_normal)
    X_normal_s = scaler.transform(X_normal)
    X_anomalous_s = scaler.transform(X_anomalous)

    # Train One-Class SVM on normal data only
    print("[behavioral] training One-Class SVM...")
    svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
    svm.fit(X_normal_s)

    # Train Random Forest on labeled data (0=normal, 1=anomalous)
    print("[behavioral] training Random Forest...")
    X_all = np.vstack([X_normal, X_anomalous])
    # Append SVM anomaly score as extra feature
    svm_scores = svm.score_samples(scaler.transform(X_all))
    X_all_enhanced = np.column_stack([X_all, 0.5 - svm_scores])  # anomaly_score column
    y_all = np.array([0] * len(X_normal) + [1] * len(X_anomalous))

    rf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42, class_weight="balanced")
    rf.fit(X_all_enhanced, y_all)

    # Evaluate
    from sklearn.metrics import classification_report
    y_pred = rf.predict(X_all_enhanced)
    report = classification_report(y_all, y_pred, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": round(report["accuracy"], 3),
        "normal_f1": round(report["0"]["f1-score"], 3),
        "anomaly_f1": round(report["1"]["f1-score"], 3),
        "macro_f1": round(report["macro avg"]["f1-score"], 3),
    }
    print(f"[behavioral] done. metrics: {metrics}")

    # Persist
    joblib.dump(svm, MODEL_DIR / "behavioral_svm.joblib")
    joblib.dump(rf, MODEL_DIR / "behavioral_rf.joblib")
    joblib.dump(scaler, MODEL_DIR / "behavioral_scaler.joblib")
    import json
    (MODEL_DIR / "behavioral_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[behavioral] artifacts → behavioral_svm.joblib, behavioral_rf.joblib, behavioral_scaler.joblib")
    return metrics


def _anomaly_scores(svm, scaler, X: np.ndarray) -> np.ndarray:
    """Compute per-sample anomaly scores exactly as anomaly_svm.predict does
    (sigmoid mapping + outlier floor) so DNN training input matches inference."""
    Xs = scaler.transform(X)
    raw = svm.score_samples(Xs)
    pred = svm.predict(Xs)
    anomaly = 1.0 / (1.0 + np.exp(raw * 5))
    anomaly = np.where(pred == -1, np.maximum(0.6, anomaly), anomaly)
    return anomaly.astype(np.float32)


def train_dnn(seed: int = 42, epochs: int = 120):
    """Train the advanced 3-class threat DNN (PRD §22.3, roadmap Phase 3).

    Requires the SVM + scaler artifacts (from ``train()``) to compute the
    anomaly-score input feature. Persists behavioral_dnn.pt.
    """
    import torch
    import torch.nn as nn
    from .dnn_threat import ThreatDNN, INPUT_DIM, DNN_PATH

    svm_path = MODEL_DIR / "behavioral_svm.joblib"
    scaler_path = MODEL_DIR / "behavioral_scaler.joblib"
    if not (svm_path.exists() and scaler_path.exists()):
        print("[behavioral] SVM/scaler missing — running train() first...")
        train()
    svm = joblib.load(svm_path)
    scaler = joblib.load(scaler_path)

    print("[behavioral] generating 3-class (LOW/MEDIUM/HIGH) dataset...")
    rng = random.Random(seed)
    users = [f"U{i:03d}" for i in range(N_USERS)]
    feats, labels = [], []
    makers = [(_make_normal, 0), (_make_medium, 1), (_make_anomalous, 2)]
    for uid in users:
        for maker, label in makers:
            for _ in range(NORMAL_PER_USER):
                feats.append(extract_features(maker(rng, uid)))
                labels.append(label)

    X = np.stack(feats).astype(np.float32)
    y = np.array(labels, dtype=np.int64)
    # Append the anomaly score column → matches classify_risk_dnn input.
    anomaly = _anomaly_scores(svm, scaler, X)
    X_in = np.column_stack([X, anomaly]).astype(np.float32)
    assert X_in.shape[1] == INPUT_DIM, f"input dim {X_in.shape[1]} != {INPUT_DIM}"

    # Normalize inputs; stash mean/std in the checkpoint for inference parity.
    mean = X_in.mean(axis=0)
    std = X_in.std(axis=0) + 1e-6

    # Shuffle + train/val split.
    idx = np.arange(len(X_in))
    rng2 = np.random.RandomState(seed)
    rng2.shuffle(idx)
    X_in, y = X_in[idx], y[idx]
    n_val = len(X_in) // 5
    Xtr = torch.from_numpy(((X_in[n_val:] - mean) / std).astype(np.float32))
    ytr = torch.from_numpy(y[n_val:])
    Xva = torch.from_numpy(((X_in[:n_val] - mean) / std).astype(np.float32))
    yva = y[:n_val]

    torch.manual_seed(seed)
    model = ThreatDNN(input_dim=INPUT_DIM)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    loss_fn = nn.CrossEntropyLoss()

    print(f"[behavioral] training DNN ({INPUT_DIM}-64-32-3) for {epochs} epochs...")
    model.train()
    for ep in range(epochs):
        opt.zero_grad()
        out = model(Xtr)
        loss = loss_fn(out, ytr)
        loss.backward()
        opt.step()

    model.eval()
    with torch.no_grad():
        pred = model(Xva).argmax(dim=1).numpy()
    from sklearn.metrics import classification_report, accuracy_score
    acc = round(float(accuracy_score(yva, pred)), 3)
    rep = classification_report(yva, pred, output_dict=True, zero_division=0)
    metrics = {
        "accuracy": acc,
        "low_f1": round(rep.get("0", {}).get("f1-score", 0.0), 3),
        "medium_f1": round(rep.get("1", {}).get("f1-score", 0.0), 3),
        "high_f1": round(rep.get("2", {}).get("f1-score", 0.0), 3),
        "macro_f1": round(rep["macro avg"]["f1-score"], 3),
    }
    print(f"[behavioral] DNN done. metrics: {metrics}")

    torch.save(
        {
            "state_dict": model.state_dict(),
            "input_dim": INPUT_DIM,
            "mean": mean.tolist(),
            "std": std.tolist(),
        },
        DNN_PATH,
    )
    import json
    (MODEL_DIR / "behavioral_dnn_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[behavioral] artifact -> {DNN_PATH.name}")
    return metrics


if __name__ == "__main__":
    import sys
    if "--dnn" in sys.argv:
        train_dnn()
    else:
        train()
        if "--all" in sys.argv:
            train_dnn()

