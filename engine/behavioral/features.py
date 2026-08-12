"""
Component 2 — Context & Feature Engineering (PRD §9-12).

Converts raw telemetry into a numerical feature vector.
The PRD example:
  Raw: "User_102 accessed database_7 at 02:14 AM from new device from new location"
  Features: { new_device=1, new_location=1, off_hours=1, resource_risk=0.75, ... }
"""
from __future__ import annotations
import numpy as np

from .telemetry import Telemetry, RESOURCE_SENSITIVITY_MAP, ROLE_PRIVILEGE_MAP

# The canonical feature names — order matters (must match training).
FEATURE_NAMES = [
    # Device (5)
    "device_trust",
    "registered_device",
    "device_change",
    "device_trust_change",          # device_trust * device_change
    # Location (3)
    "location_change",
    "location_frequency",
    "location_risk",                # (1 - location_frequency) * location_change
    # Time (5)
    "off_hours",                    # 1 if NOT working_hours
    "off_day",                      # 1 if NOT working_day
    "hour_normalized",              # 0..1 around the clock
    "time_since_prev_req_norm",     # log-scaled
    "after_midnight",               # 1 if 0..5 AM
    # Session (4)
    "request_count_norm",
    "session_duration_norm",
    "failed_auth_count",
    "failed_auth_flag",             # 1 if failed_auth_count > 0
    # Resource (3)
    "resource_risk",
    "resource_sensitivity_high",    # 1 if high/critical
    "resource_type_risk",           # heuristic per type
    # Activity (3)
    "request_frequency_norm",
    "resource_access_freq_norm",
    "frequency_spike",              # request_frequency relative to baseline
    # Identity (2)
    "privilege_level",
    "high_privilege_resource",      # privilege * resource_risk
]

FEATURE_DIM = len(FEATURE_NAMES)  # 25

RESOURCE_TYPE_RISK = {
    "web_page": 0.1,
    "report": 0.3,
    "crm": 0.3,
    "api": 0.4,
    "database": 0.7,
    "credential_vault": 1.0,
    "admin_panel": 0.9,
    "export": 0.8,
    "chat": 0.2,
}


def extract_features(t: Telemetry, baseline_frequency: float | None = None) -> np.ndarray:
    """Extract the numerical feature vector from a Telemetry object.

    Returns a (FEATURE_DIM,) float32 array.
    """
    res_risk = RESOURCE_SENSITIVITY_MAP.get(t.resource_sensitivity, 0.1)
    priv = ROLE_PRIVILEGE_MAP.get(t.role, 0.2)
    res_type_risk = RESOURCE_TYPE_RISK.get(t.resource_type, 0.3)
    base_freq = baseline_frequency or t.request_frequency

    freq_spike = min(5.0, t.request_frequency / max(base_freq, 0.1)) - 1.0
    freq_spike = max(0.0, freq_spike)

    features = [
        # Device
        t.device_trust,
        float(t.registered_device),
        float(t.device_change),
        t.device_trust * float(t.device_change),
        # Location
        float(t.location_change),
        t.location_frequency,
        (1.0 - t.location_frequency) * float(t.location_change),
        # Time
        float(not t.working_hours),
        float(not t.working_day),
        (t.hour % 24) / 24.0,
        min(1.0, np.log1p(t.time_since_prev_request) / 10.0),
        float(0 <= t.hour < 6),
        # Session
        min(1.0, t.request_count / 100.0),
        min(1.0, np.log1p(t.session_duration) / 10.0),
        float(t.failed_auth_count),
        float(t.failed_auth_count > 0),
        # Resource
        res_risk,
        float(t.resource_sensitivity in ("high", "critical")),
        res_type_risk,
        # Activity
        min(1.0, t.request_frequency / 100.0),
        min(1.0, t.resource_access_frequency / 50.0),
        min(1.0, freq_spike),
        # Identity
        priv,
        priv * res_risk,
    ]
    return np.array(features, dtype=np.float32)
