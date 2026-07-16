"""
Tests for the keystroke-dynamics anomaly scorer (Req 3.2*, 3.6).

* Tier-1 uses a rolling-average z-score; the LSTM ensemble is Tier 2.

Covers: cold-start gating (insufficient baseline => no score, MFA only),
baseline vs anomalous separation, and trust-score bounds.
"""
import statistics

import pytest

from engine.biometric.anomaly import (
    DEFAULT_MIN_SAMPLES,
    DEFAULT_Z_THRESHOLD,
    build_baseline,
    score_batch,
)


def _baseline(means, n):
    """Build a realistic baseline around the given dwell/flight means, with the
    kind of small natural variance real typing produces (~±3ms jitter)."""
    dwell = [means[0] + ((i % 7) - 3) for i in range(n)]
    flight = [means[1] + ((i % 5) - 2) for i in range(n)]
    return build_baseline(dwell_history=dwell, flight_history=flight, prior_n=n)


# ---- Cold-start (Req 3.6) ------------------------------------------------ #
def test_cold_start_when_baseline_too_small():
    baseline = _baseline([90, 40], n=20)  # < MIN_SAMPLES
    result = score_batch(
        baseline=baseline,
        dwell_times=[90, 91, 92],
        flight_times=[40, 41, 42],
        min_samples=DEFAULT_MIN_SAMPLES,
        z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.cold_start is True
    assert result.trust_score == 100.0
    assert result.risk_score == 0.0
    assert "cold-start" in result.reason


def test_cold_start_respects_custom_min_samples():
    baseline = _baseline([90, 40], n=50)
    result = score_batch(
        baseline=baseline,
        dwell_times=[90],
        flight_times=[40],
        min_samples=200,  # higher bar
        z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.cold_start is True


# ---- Scoring behavior ---------------------------------------------------- #
def _normal_batch():
    return [90, 91, 89, 92, 90], [40, 41, 39, 42, 40]


def _anomalous_batch():
    return [200, 210, 205, 215, 208], [120, 130, 125, 135, 128]


def test_normal_batch_scores_high_trust():
    baseline = _baseline([90, 40], n=DEFAULT_MIN_SAMPLES)
    d, f = _normal_batch()
    result = score_batch(
        baseline=baseline, dwell_times=d, flight_times=f,
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.cold_start is False
    assert result.trust_score >= 80
    assert result.risk_score <= 0.2


def test_anomalous_batch_scores_low_trust():
    baseline = _baseline([90, 40], n=DEFAULT_MIN_SAMPLES)
    d, f = _anomalous_batch()
    result = score_batch(
        baseline=baseline, dwell_times=d, flight_times=f,
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.cold_start is False
    assert result.trust_score <= 5
    assert result.risk_score >= 0.95
    assert "anomalous" in result.reason.lower()


def test_anomalous_z_exceeds_threshold():
    baseline = _baseline([90, 40], n=DEFAULT_MIN_SAMPLES)
    d, f = _anomalous_batch()
    result = score_batch(
        baseline=baseline, dwell_times=d, flight_times=f,
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.z >= DEFAULT_Z_THRESHOLD


def test_trust_score_in_bounds():
    """Trust must always be 0..100."""
    baseline = _baseline([90, 40], n=DEFAULT_MIN_SAMPLES)
    for d, f in [(_normal_batch()), (_anomalous_batch()), ([3000], [3000])]:
        result = score_batch(
            baseline=baseline, dwell_times=d, flight_times=f,
            min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
        )
        assert 0.0 <= result.trust_score <= 100.0


def test_empty_batch_is_neutral():
    baseline = _baseline([90, 40], n=DEFAULT_MIN_SAMPLES)
    result = score_batch(
        baseline=baseline, dwell_times=[], flight_times=[],
        min_samples=DEFAULT_MIN_SAMPLES, z_threshold=DEFAULT_Z_THRESHOLD,
    )
    assert result.risk_score == 0.0
    assert result.trust_score == 100.0
