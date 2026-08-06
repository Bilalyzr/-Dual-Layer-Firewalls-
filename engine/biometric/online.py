"""
EPIC G — Online / incremental baseline adaptation.

Handles legitimate drift (fatigue, new keyboard, mild injury) without forcing a
full re-enrollment. Maintains an exponentially-weighted moving average (EWMA) of
the user's dwell/flight distribution that nudges toward recent confirmed-genuine
batches. Confirmed-genuine = a batch that scored above the trust threshold AND
wasn't followed by a step-up challenge within the session.

This is intentionally conservative: EWMA weight (alpha) is small so an attacker
can't rapidly repivot the baseline with a few well-typed batches.
"""
from __future__ import annotations
import statistics
from dataclasses import dataclass, field

ALPHA = 0.05  # how much recent genuine batches pull the baseline (5%)


@dataclass
class AdaptiveBaseline:
    dwell_mean: float
    dwell_std: float
    flight_mean: float
    flight_std: float
    n_updates: int = 0
    # rolling history for inspection (capped)
    history: list = field(default_factory=list)

    def update(self, dwell_times: list[float], flight_times: list[float]) -> "AdaptiveBaseline":
        """EWMA update using a confirmed-genuine batch."""
        if not dwell_times or not flight_times:
            return self
        d_mean = statistics.fmean(dwell_times)
        d_std = statistics.pstdev(dwell_times) or 1e-6
        f_mean = statistics.fmean(flight_times)
        f_std = statistics.pstdev(flight_times) or 1e-6

        a = ALPHA
        self.dwell_mean = (1 - a) * self.dwell_mean + a * d_mean
        self.dwell_std = (1 - a) * self.dwell_std + a * d_std
        self.flight_mean = (1 - a) * self.flight_mean + a * f_mean
        self.flight_std = (1 - a) * self.flight_std + a * f_std
        self.n_updates += 1
        self.history.append({"d": round(self.dwell_mean, 2), "f": round(self.flight_mean, 2)})
        self.history = self.history[-50:]
        return self

    def to_dict(self) -> dict:
        return {
            "dwell_mean": round(self.dwell_mean, 2),
            "dwell_std": round(self.dwell_std, 2),
            "flight_mean": round(self.flight_mean, 2),
            "flight_std": round(self.flight_std, 2),
            "n_updates": self.n_updates,
        }


# Per-user adaptive baselines (in-process; could persist to Mongo).
_baselines: dict[str, AdaptiveBaseline] = {}


def get_adaptive_baseline(userId: str, seed_dwell: float = 90.0, seed_flight: float = 40.0) -> AdaptiveBaseline:
    if userId not in _baselines:
        _baselines[userId] = AdaptiveBaseline(seed_dwell, 20.0, seed_flight, 25.0)
    return _baselines[userId]


def update_on_genuine(userId: str, dwell_times: list[float], flight_times: list[float]) -> dict:
    """Called after a batch is confirmed genuine. Returns the new baseline snapshot."""
    b = get_adaptive_baseline(userId)
    b.update(dwell_times, flight_times)
    return b.to_dict()
