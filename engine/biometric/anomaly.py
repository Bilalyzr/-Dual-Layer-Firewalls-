"""
Tier-1 keystroke-dynamics anomaly scoring (Phase 2 of the plan).

Approach: per-user rolling baseline of two raw timing signals —
  * dwell time  = keyup - keydown        (how long a key is held)
  * flight time = keydown[N+1] - keyup[N] (gap between consecutive keys)

For each new batch we compute the user's mean/std per signal, then score a
fresh batch as a z-score magnitude. This is deliberately simple — the LSTM +
RF/XGBoost/MLP ensemble is Tier 2 (Phase 4).

Cold-start (Req 3.6): until the user has contributed >= MIN_SAMPLES events we
do not emit a risk score; the session is treated as "standard MFA" only.
"""
from __future__ import annotations
import math
import statistics
from dataclasses import dataclass, field

# Tunable via env (mirrored in proxy/.env). Defaults chosen for clarity.
DEFAULT_MIN_SAMPLES = 120
DEFAULT_Z_THRESHOLD = 2.5

EPS = 1e-6


@dataclass
class SignalStats:
    mean: float
    std: float

    @classmethod
    def from_series(cls, xs: list[float]) -> "SignalStats":
        if not xs:
            return cls(0.0, 0.0)
        return cls(statistics.fmean(xs), statistics.pstdev(xs) or 0.0)


def _deviation(value: float, stats: SignalStats) -> float:
    """
    z-score-like deviation, robust to a zero-variance baseline.

    When the baseline std is ~0 (e.g. a perfectly constant baseline, common in
    synthetic tests or very early baselines), a plain z-score would always be 0
    and could never flag anything. We fall back to mean-absolute-deviation:
    treat the batch mean's distance from the baseline mean, scaled by the mean
    itself, so a constant [90]*n baseline still flags a batch at 200.
    """
    if stats.std >= EPS:
        return abs(value - stats.mean) / stats.std
    # Zero-variance fallback: relative deviation from the mean.
    base = abs(stats.mean) if abs(stats.mean) > EPS else 1.0
    return abs(value - stats.mean) / base


@dataclass
class Baseline:
    """A user's accumulated keystroke statistics."""

    dwell: SignalStats = field(default_factory=lambda: SignalStats(0.0, 0.0))
    flight: SignalStats = field(default_factory=lambda: SignalStats(0.0, 0.0))
    n: int = 0  # total events ever seen


@dataclass
class ScoreResult:
    risk_score: float          # 0..1 normalized trust complement (1 = trusted)
    trust_score: float         # alias, matches dashboard vocabulary
    z: float                   # raw mean-z magnitude
    cold_start: bool           # True => insufficient baseline, MFA only
    reason: str
    dwell_mean: float
    flight_mean: float


def score_batch(
    *,
    baseline: Baseline,
    dwell_times: list[float],
    flight_times: list[float],
    min_samples: int = DEFAULT_MIN_SAMPLES,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
) -> ScoreResult:
    """Score a new batch of keystroke timings against the user's baseline."""

    n = baseline.n
    if n < min_samples:
        return ScoreResult(
            risk_score=0.0,
            trust_score=100.0,
            z=0.0,
            cold_start=True,
            reason=f"cold-start: {n}/{min_samples} baseline samples, MFA only",
            dwell_mean=baseline.dwell.mean,
            flight_mean=baseline.flight.mean,
        )

    if not dwell_times:
        return ScoreResult(
            risk_score=0.0,
            trust_score=100.0,
            z=0.0,
            cold_start=False,
            reason="empty batch",
            dwell_mean=baseline.dwell.mean,
            flight_mean=baseline.flight.mean,
        )

    batch_dwell = SignalStats.from_series(dwell_times)
    batch_flight = SignalStats.from_series(flight_times)

    z_d = _deviation(batch_dwell.mean, baseline.dwell)
    z_f = _deviation(batch_flight.mean, baseline.flight)
    z = (z_d + z_f) / 2.0  # combined deviation magnitude

    # Map z to a 0..1 risk: 0 at z=0, saturating near the threshold.
    risk = min(1.0, z / max(z_threshold, EPS))
    trust = round(max(0.0, 100.0 * (1.0 - risk)), 1)

    if z >= z_threshold:
        reason = (
            f"anomalous typing: z={z:.2f} >= {z_threshold} "
            f"(dwell z={z_d:.2f}, flight z={z_f:.2f})"
        )
    elif z >= z_threshold * 0.6:
        reason = f"elevated typing deviation (z={z:.2f})"
    else:
        reason = f"within baseline (z={z:.2f})"

    return ScoreResult(
        risk_score=round(risk, 3),
        trust_score=trust,
        z=round(z, 3),
        cold_start=False,
        reason=reason,
        dwell_mean=round(batch_dwell.mean, 2),
        flight_mean=round(batch_flight.mean, 2),
    )


def build_baseline(
    *,
    dwell_history: list[float],
    flight_history: list[float],
    prior_n: int = 0,
) -> Baseline:
    """Build a Baseline from stored history (used after loading from Mongo)."""
    return Baseline(
        dwell=SignalStats.from_series(dwell_history),
        flight=SignalStats.from_series(flight_history),
        n=prior_n or len(dwell_history),
    )
