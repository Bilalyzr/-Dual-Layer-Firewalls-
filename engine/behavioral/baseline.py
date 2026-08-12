"""
Component 3 — Behavioral Baseline Manager (PRD §13-14).

Maintains per-user + per-role behavioral profiles. Updated from confirmed-
legitimate activity via EWMA (controlled — attacker can't repivot fast).

Per the PRD: USER + ROLE + RESOURCE CONTEXT → baseline (not just USER).
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class BehavioralBaseline:
    """A user's normal behavioral profile."""
    user_id: str
    role: str = "user"
    normal_hours: tuple[int, int] = (9, 18)       # working hours
    normal_days: set[int] = field(default_factory=lambda: {0, 1, 2, 3, 4})
    normal_device_id: str = ""
    normal_location: str = ""
    normal_resources: set[str] = field(default_factory=set)
    normal_frequency: float = 15.0                 # requests/hour
    normal_frequency_std: float = 8.0
    n_updates: int = 0

    def is_off_hours(self, hour: int, day: int) -> bool:
        return hour < self.normal_hours[0] or hour >= self.normal_hours[1] or day not in self.normal_days

    def is_device_change(self, device_id: str) -> bool:
        return self.normal_device_id and device_id != self.normal_device_id

    def is_location_change(self, location: str) -> bool:
        return self.normal_location and location != self.normal_location

    def frequency_deviation(self, current_freq: float) -> float:
        """Z-score of current frequency vs baseline."""
        if self.normal_frequency_std < 1e-6:
            return 0.0
        return abs(current_freq - self.normal_frequency) / self.normal_frequency_std

    def update(self, telemetry) -> "BehavioralBaseline":
        """EWMA update from confirmed-genuine activity (α=0.05 — conservative)."""
        alpha = 0.05
        self.normal_frequency = (1 - alpha) * self.normal_frequency + alpha * telemetry.request_frequency
        if not self.normal_device_id:
            self.normal_device_id = telemetry.device_id
        elif telemetry.device_id and telemetry.device_id != self.normal_device_id:
            # gradual adoption of new device (very slow)
            pass  # don't auto-adopt — admin must confirm device changes
        if not self.normal_location:
            self.normal_location = f"{telemetry.country}/{telemetry.region}"
        if telemetry.resource_id:
            self.normal_resources.add(telemetry.resource_id)
            if len(self.normal_resources) > 50:
                self.normal_resources = set(list(self.normal_resources)[-50:])
        self.n_updates += 1
        return self

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "normal_hours": list(self.normal_hours),
            "normal_days": sorted(self.normal_days),
            "normal_device_id": self.normal_device_id,
            "normal_location": self.normal_location,
            "normal_resources": sorted(self.normal_resources),
            "normal_frequency": round(self.normal_frequency, 1),
            "n_updates": self.n_updates,
        }


# Per-user in-process baselines (would persist to Mongo in production).
_baselines: dict[str, BehavioralBaseline] = {}


def get_baseline(user_id: str, role: str = "user") -> BehavioralBaseline:
    if user_id not in _baselines:
        _baselines[user_id] = BehavioralBaseline(user_id=user_id, role=role)
    return _baselines[user_id]


def update_baseline(user_id: str, telemetry) -> dict:
    b = get_baseline(user_id, getattr(telemetry, "role", "user"))
    b.update(telemetry)
    return b.to_dict()
