"""
Tier-2 biometric tests (Req 3.2–3.5, 3.7).

Covers: model artifacts present, ensemble discriminates genuine vs impostor,
contract preservation (ScoreResult fields/types, cold-start gate, trust range),
drift reason codes, async SHAP returns features, and the /score-batch endpoint
exposes model_used + shap_request_id.
"""
import asyncio
import math
import os

import numpy as np
import pytest

from engine.biometric.anomaly import (
    DEFAULT_MIN_SAMPLES,
    DEFAULT_Z_THRESHOLD,
    DRIFT_TOLERANCE,
    Baseline,
    ScoreResult,
    build_baseline,
    score_batch,
)
from engine.biometric.ensemble import ensemble_ready, predict_proba
from engine.biometric.features import FEATURE_NAMES, sequence_stats
from engine.biometric.lstm_model import model_ready


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _history(means, n, jitter_d=3, jitter_f=2):
    """Realistic per-user baseline history with natural jitter."""
    d = [means[0] + ((i % 7) - jitter_d) for i in range(n)]
    f = [means[1] + ((i % 5) - jitter_f) for i in range(n)]
    return d, f


@pytest.fixture(scope="module")
def trained():
    """Skip the whole module if models aren't trained."""
    if not (model_ready() and ensemble_ready()):
        pytest.skip("Tier-2 models not trained — run: python -m engine.biometric.train_biometric")
    return True


# --------------------------------------------------------------------------- #
# Model artifacts
# --------------------------------------------------------------------------- #
def test_model_artifacts_present(trained):
    assert model_ready()
    assert ensemble_ready()


def test_ensemble_predict_proba_in_range(trained):
    feats = np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)
    p = predict_proba(feats)
    assert 0.0 <= p <= 1.0


def test_feature_vector_dimension(trained):
    """sequence_stats must return exactly len(FEATURE_NAMES) - 16 (LSTM) features."""
    seq = np.array([[90.0, 40.0]] * 10, dtype=np.float32)
    stats = sequence_stats(seq, 90.0, 40.0)
    # 17 hand-crafted + 2 deviation = 19
    assert stats.shape == (19,)


# --------------------------------------------------------------------------- #
# Contract preservation — score_batch
# --------------------------------------------------------------------------- #
def test_score_batch_returns_scoreresult_shape(trained):
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    result = score_batch(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=len(d_hist)),
        dwell_times=[90, 91, 89], flight_times=[40, 41, 39],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        dwell_history=d_hist, flight_history=f_hist,
    )
    # Every downstream consumer depends on these fields existing.
    for field in ("risk_score", "trust_score", "z", "cold_start", "reason", "dwell_mean", "flight_mean"):
        assert hasattr(result, field), f"missing contract field: {field}"
    assert isinstance(result.cold_start, bool)
    assert isinstance(result.reason, str)
    assert 0.0 <= result.risk_score <= 1.0
    assert 0.0 <= result.trust_score <= 100.0


def test_cold_start_still_gated_when_model_present(trained):
    """Req 3.6: cold-start must hold even with Tier-2 models loaded."""
    d_hist, f_hist = _history([90, 40], 20)  # well below min_samples
    result = score_batch(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=20),
        dwell_times=[90, 91], flight_times=[40, 41],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        dwell_history=d_hist, flight_history=f_hist,
    )
    assert result.cold_start is True
    assert result.trust_score == 100.0
    assert result.risk_score == 0.0


def test_model_path_used_when_history_provided(trained):
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    result = score_batch(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=len(d_hist)),
        dwell_times=[90, 91, 89], flight_times=[40, 41, 39],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        dwell_history=d_hist, flight_history=f_hist,
    )
    assert result.model_used == "ensemble"
    assert result.p_genuine is not None
    assert 0.0 <= result.p_genuine <= 1.0


def test_falls_back_to_zscore_without_history(trained):
    """When history isn't supplied, the model path can't run → z-score fallback."""
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    result = score_batch(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=len(d_hist)),
        dwell_times=[90, 91, 89], flight_times=[40, 41, 39],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        # no dwell_history/flight_history kwargs
    )
    assert result.model_used == "zscore"


# --------------------------------------------------------------------------- #
# Discrimination — the core Tier-2 capability
# --------------------------------------------------------------------------- #
def test_ensemble_discriminates_genuine_vs_impostor(trained):
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    common = dict(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=len(d_hist)),
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        dwell_history=d_hist, flight_history=f_hist,
    )
    genuine = score_batch(
        dwell_times=[90, 91, 89, 92, 90, 88, 91, 93, 89, 90],
        flight_times=[40, 41, 39, 42, 40, 38, 41, 43, 39, 40],
        **common,
    )
    impostor = score_batch(
        dwell_times=[200, 210, 205, 215, 208, 202, 212, 207, 204, 211],
        flight_times=[160, 165, 158, 170, 163, 168, 161, 166, 159, 164],
        **common,
    )
    assert genuine.trust_score > impostor.trust_score
    assert impostor.trust_score < genuine.trust_score - 20


def test_drift_reason_does_not_hard_lock(trained, monkeypatch):
    """Req 3.7: borderline cases get a 're-verify' reason, not a hard anomaly."""
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    # Craft a P(genuine) in the drift band by mocking predict_proba.
    import engine.biometric.ensemble as ens
    monkeypatch.setattr(ens, "predict_proba", lambda feats: 0.45)  # in drift band
    result = score_batch(
        baseline=build_baseline(dwell_history=d_hist, flight_history=f_hist, prior_n=len(d_hist)),
        dwell_times=[90, 91, 89], flight_times=[40, 41, 39],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        dwell_history=d_hist, flight_history=f_hist,
    )
    assert "re-verify" in result.reason or "shifted" in result.reason


# --------------------------------------------------------------------------- #
# Async SHAP (Req 3.4)
# --------------------------------------------------------------------------- #
def test_explain_returns_top_features(trained):
    from engine.biometric.explain import explain

    feats = np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)
    out = explain(feats, top_k=5)
    assert "features" in out
    assert len(out["features"]) <= 5
    for row in out["features"]:
        assert {"name", "value", "shap", "direction"} <= set(row)
        assert row["direction"] in ("genuine", "impostor")


def test_explain_async_off_path(trained):
    """Req 3.4: SHAP runs in a thread, returns the same shape as sync."""
    from engine.biometric.explain import explain_async

    feats = np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)
    out = asyncio.run(explain_async(feats, top_k=4))
    assert "features" in out
    assert len(out["features"]) <= 4


# --------------------------------------------------------------------------- #
# Endpoint contract — /score-batch exposes Tier-2 fields
# --------------------------------------------------------------------------- #
def test_score_batch_endpoint_returns_model_fields(trained):
    from fastapi.testclient import TestClient
    from engine.app import app

    client = TestClient(app)
    d_hist, f_hist = _history([90, 40], DEFAULT_MIN_SAMPLES + 50)
    r = client.post("/score-batch", json={
        "dwell_history": d_hist, "flight_history": f_hist, "prior_n": len(d_hist),
        "dwell_times": [90, 91, 89], "flight_times": [40, 41, 39],
    })
    body = r.json()
    assert body["model_used"] == "ensemble"
    assert "p_genuine" in body
    # SHAP is async — request id may or may not be present yet, but if present it's a string.
    if "shap_request_id" in body:
        assert isinstance(body["shap_request_id"], str)


def test_shap_endpoint_roundtrip(trained):
    from fastapi.testclient import TestClient
    from engine.app import app, _SHAP_STORE

    client = TestClient(app)
    # Inject a fake completed result and retrieve it.
    _SHAP_STORE["test-rid"] = {"status": "done", "result": {"features": []}}
    r = client.get("/shap/test-rid")
    body = r.json()
    assert body["status"] == "done"
    assert body["request_id"] == "test-rid"

    # Unknown id → pending.
    assert client.get("/shap/unknown-id").json()["status"] == "pending"
