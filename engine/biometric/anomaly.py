"""
Keystroke-dynamics anomaly scoring.

Tier 1: rolling-average z-score over dwell/flight signals.
Tier 2 (when model artifacts are present): LSTM + RF/GB/MLP soft-voting ensemble
         produces P(genuine), which drives trust/risk; SHAP runs async off-path.
         Req 3.7 drift is handled by a rolling re-calibration tolerance and
         user-facing appeal/re-verify reason codes (no hard permanent lockout).

The public contract is unchanged: score_batch() returns a ScoreResult with the
same fields the proxy/Mongo/SSE/frontend already consume. Tier 2 only changes
*how* trust/risk are computed.
"""
from __future__ import annotations
import statistics
from dataclasses import dataclass, field

# Tunable via env (mirrored in proxy/.env).
DEFAULT_MIN_SAMPLES = 120
DEFAULT_Z_THRESHOLD = 2.5
EPS = 1e-6

# Req 3.7 drift tolerance: legitimate baseline drift (injury, fatigue, new
# device) shouldn't instantly lock a user out. We allow a generosity band where
# trust degrades gracefully and the reason nudges toward re-verification instead
# of "anomaly".
DRIFT_TOLERANCE = 0.15  # extra P(genuine) headroom before hard anomaly reason
SEQ_LEN = 60           # LSTM window length (matches training)


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
    risk_score: float          # 0..1 anomaly probability (1 = max anomaly)
    trust_score: float         # 0..100 (100 = trusted)
    z: float                   # legacy z-score magnitude (retained for dashboard)
    cold_start: bool           # True => insufficient baseline, MFA only
    reason: str
    dwell_mean: float
    flight_mean: float
    model_used: str = "zscore"  # "zscore" | "ensemble" — provenance
    p_genuine: float | None = None


# --------------------------------------------------------------------------- #
# Legacy z-score path (kept as fallback + sanity baseline)
# --------------------------------------------------------------------------- #
def _zscore_score(
    *,
    baseline: Baseline,
    dwell_times: list[float],
    flight_times: list[float],
    z_threshold: float,
) -> tuple[float, float, str, float, float]:
    """Returns (z, trust, reason, dwell_mean, flight_mean)."""
    batch_dwell = SignalStats.from_series(dwell_times)
    batch_flight = SignalStats.from_series(flight_times)

    z_d = _deviation(batch_dwell.mean, baseline.dwell)
    z_f = _deviation(batch_flight.mean, baseline.flight)
    z = (z_d + z_f) / 2.0

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
    return z, trust, reason, batch_dwell.mean, batch_flight.mean


# --------------------------------------------------------------------------- #
# Tier-2 model path
# --------------------------------------------------------------------------- #
def _build_sequence(
    dwell_history: list[float], flight_history: list[float],
    dwell_times: list[float], flight_times: list[float],
    seq_len: int = SEQ_LEN,
) -> list[tuple[float, float]]:
    """
    Build a (seq_len, 2) sequence for the LSTM. The NEW batch is the signal we're
    scoring, so it goes FIRST and we only backfill enough recent history to reach
    seq_len. This keeps small batches from being drowned by a long baseline.
    """
    need = max(0, seq_len - len(dwell_times))
    hist_d = list(reversed(dwell_history))[:need]
    hist_f = list(reversed(flight_history))[:need]
    dwell = list(dwell_times) + hist_d
    flight = list(flight_times) + hist_f
    n = min(len(dwell), len(flight))
    pairs = list(zip(dwell[:n], flight[:n]))
    if len(pairs) >= seq_len:
        pairs = pairs[:seq_len]
    else:
        pad = pairs[-1] if pairs else (0.0, 0.0)
        pairs = pairs + [pad] * (seq_len - len(pairs))
    return pairs


def _models_available() -> bool:
    try:
        from .lstm_model import model_ready
        from .ensemble import ensemble_ready
        return model_ready() and ensemble_ready()
    except Exception:
        return False


def _score_with_model(
    *,
    dwell_history: list[float],
    flight_history: list[float],
    dwell_times: list[float],
    flight_times: list[float],
    z_threshold: float,
) -> tuple[float, float, str, float, float, float]:
    """Returns (trust, risk, reason, dwell_mean, flight_mean, p_genuine)."""
    import numpy as np
    from .features import (
        STATS_NORM_PATH,
        SEQ_NORM_PATH,
        load_seq_normalizer,
        load_stats_scaler,
        sequence_stats,
    )
    from .lstm_model import embed_batch
    from .ensemble import predict_proba

    pairs = _build_sequence(dwell_history, flight_history, dwell_times, flight_times)
    seq = np.array(pairs, dtype=np.float32).reshape(1, SEQ_LEN, 2)

    seq_norm = load_seq_normalizer()
    stats_scaler = load_stats_scaler()
    if seq_norm is not None:
        seq_n = seq_norm.transform(seq)
    else:
        seq_n = seq
    # Deviation features need the CLAIMED baseline means — derived from the
    # user's accumulated history (the same Baseline the z-score uses).
    bl_dwell_mean = float(np.mean(dwell_history)) if dwell_history else 0.0
    bl_flight_mean = float(np.mean(flight_history)) if flight_history else 0.0
    stats_v = sequence_stats(seq[0], bl_dwell_mean, bl_flight_mean).reshape(1, -1)
    if stats_scaler is not None:
        stats_n = stats_scaler.transform(stats_v).astype(np.float32)
    else:
        stats_n = stats_v.astype(np.float32)

    emb = embed_batch(seq_n)
    feats = np.concatenate([emb, stats_n], axis=1).astype(np.float32)
    p_genuine = predict_proba(feats)

    # Map P(genuine) -> risk/trust. Generosity band (Req 3.7 drift) prevents
    # hard lockout on borderline cases — reason nudges to re-verify instead.
    risk = max(0.0, min(1.0, 1.0 - p_genuine))
    trust = round(max(0.0, 100.0 * p_genuine), 1)

    dwell_mean = float(np.mean([p[0] for p in pairs[-len(dwell_times):]])) if dwell_times else 0.0
    flight_mean = float(np.mean([p[1] for p in pairs[-len(flight_times):]])) if flight_times else 0.0

    # Reason bands — graceful for borderline (drift), hard for clear impostor.
    if p_genuine >= 0.7:
        reason = f"verified by ensemble (P(genuine)={p_genuine:.2f})"
    elif p_genuine >= (0.5 - DRIFT_TOLERANCE):
        # Drift band: legitimate drift (fatigue/new device) — re-verify, don't lock out.
        reason = (
            f"typing shifted — re-verify recommended (P(genuine)={p_genuine:.2f}). "
            f"Use the appeal path if this persists."
        )
    else:
        reason = f"anomalous typing — likely impostor (P(genuine)={p_genuine:.2f})"
    return trust, risk, reason, dwell_mean, flight_mean, float(p_genuine)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def score_batch(
    *,
    baseline: Baseline,
    dwell_times: list[float],
    flight_times: list[float],
    min_samples: int = DEFAULT_MIN_SAMPLES,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    dwell_history: list[float] | None = None,
    flight_history: list[float] | None = None,
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

    # Legacy z-score — always computed (cheap, retained for `z` field + fallback).
    z, z_trust, z_reason, d_mean, f_mean = _zscore_score(
        baseline=baseline, dwell_times=dwell_times, flight_times=flight_times,
        z_threshold=z_threshold,
    )

    # Tier-2 model path — used when artifacts are present.
    use_model = _models_available() and dwell_history is not None and flight_history is not None
    if use_model:
        try:
            trust, risk, reason, dm, fm, p_genuine = _score_with_model(
                dwell_history=dwell_history or [],
                flight_history=flight_history or [],
                dwell_times=dwell_times,
                flight_times=flight_times,
                z_threshold=z_threshold,
            )
            return ScoreResult(
                risk_score=round(risk, 3),
                trust_score=trust,
                z=round(z, 3),
                cold_start=False,
                reason=reason,
                dwell_mean=round(dm, 2),
                flight_mean=round(fm, 2),
                model_used="ensemble",
                p_genuine=round(p_genuine, 4),
            )
        except Exception as exc:  # never let the model path break scoring
            reason = f"ensemble fallback to z-score ({type(exc).__name__}); {z_reason}"

    return ScoreResult(
        risk_score=round(min(1.0, z / max(z_threshold, EPS)), 3),
        trust_score=z_trust,
        z=round(z, 3),
        cold_start=False,
        reason=z_reason if not use_model else reason,
        dwell_mean=round(d_mean, 2),
        flight_mean=round(f_mean, 2),
        model_used="zscore",
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
