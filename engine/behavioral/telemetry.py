"""
Component 1 — Behavioral Telemetry Collector (PRD §8).

Collects contextual signals per the PRD's 7 categories:
  Identity, Device, Location, Time, Session, Resource, Activity.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Telemetry:
    """A single behavioral telemetry snapshot — the input to the risk pipeline."""
    # Identity
    user_id: str = ""
    role: str = "user"
    privilege_level: str = "standard"
    auth_status: str = "authenticated"
    # Device
    device_id: str = ""
    device_type: str = "laptop"
    device_trust: float = 0.5          # 0..1
    registered_device: bool = True
    device_change: bool = False         # different from last session?
    # Location
    country: str = "IN"
    region: str = "TN"
    location_change: bool = False       # different from last access?
    location_frequency: float = 0.8     # 0..1 — how often we see this location
    # Time
    timestamp: str = ""                 # ISO; computed at collection time if empty
    hour: int | None = None             # None → filled from the collection clock
    day_of_week: int | None = None      # None → filled from the collection clock (0=Mon)
    working_hours: bool = True
    working_day: bool = True
    time_since_prev_request: float = 300.0  # seconds
    # Session
    session_id: str = ""
    session_duration: float = 600.0     # seconds
    request_count: int = 5
    failed_auth_count: int = 0
    # Resource
    resource_id: str = ""
    resource_type: str = "web_page"
    resource_sensitivity: str = "low"   # low/medium/high/critical
    # Activity
    request_frequency: float = 10.0     # requests/hour
    resource_access_frequency: float = 5.0  # resources/hour
    # Optional: raw prompt text for LLM context enrichment
    prompt_text: str = ""
    # Layer-1 bridge: the firewall's classifier/heuristics flagged this
    # prompt as an injection attempt (drives the §35 explainability reason
    # and a risk boost — the injection IS the behavioral signal).
    prompt_injection: bool = False
    # Word-injection breakdown from the v2 firewall's sentiment engine
    # ({negative_terms: [{term, weight}], positive_terms: [...], weightage})
    # so §35 EXPLAINABILITY can quote the exact attack vocabulary found.
    word_scores: dict = field(default_factory=dict)

    def __post_init__(self):
        # Auto-fill time fields only when the caller omitted them (None) —
        # an explicit value always wins, including a genuine midnight (hour=0).
        if not self.timestamp or self.hour is None or self.day_of_week is None:
            now = datetime.now()
            if not self.timestamp:
                self.timestamp = now.isoformat()
            if self.hour is None:
                self.hour = now.hour
                self.working_hours = 9 <= now.hour < 18
            if self.day_of_week is None:
                self.day_of_week = now.weekday()
                self.working_day = now.weekday() < 5


RESOURCE_SENSITIVITY_MAP = {
    "low": 0.1,
    "medium": 0.4,
    "high": 0.75,
    "critical": 1.0,
}

ROLE_PRIVILEGE_MAP = {
    "user": 0.2,
    "developer": 0.4,
    "manager": 0.6,
    "admin": 0.9,
    "superadmin": 1.0,
}


def from_dict(d: dict) -> Telemetry:
    """Build a Telemetry from a raw API request dict, filling defaults.

    ``None`` values (pydantic optional fields the caller omitted) are dropped
    so the dataclass defaults + collection-time fill apply instead of
    overriding them with None.
    """
    known = {f for f in Telemetry.__dataclass_fields__}
    kwargs = {k: v for k, v in d.items() if k in known and v is not None}
    return Telemetry(**kwargs)
