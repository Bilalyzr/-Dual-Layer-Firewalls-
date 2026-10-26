"""
Regression tests for the behavioral hardening fixes:

1. /behavior/analyze used to 500 when `hour` was omitted (pydantic None →
   features.py None % 24 TypeError).
2. Telemetry's auto-fill ran on hour == 0 (never for the real default) and
   stomped a genuine midnight — sent hour=0, got the current hour back.
3. risk_level and action could disagree after the LLM-context boost
   (HIGH risk with a stale STEP_UP action).
4. Nothing ever produced a DENY decision (no CRITICAL band).
5. normal_frequency_std was never updated; baselines and failed-auth counts
   lived only in memory.
"""
from datetime import datetime

import numpy as np

from engine.behavioral.baseline import BehavioralBaseline, get_baseline
from engine.behavioral.features import extract_features
from engine.behavioral.response import build_decision
from engine.behavioral.telemetry import Telemetry, from_dict
from engine.behavioral.threat_engine import _level_to_action, _score_to_level


# ---- 1. omitted hour must not crash feature extraction ---------------------
def test_from_dict_drops_none_optionals():
    """A minimal API body (hour/working_hours/working_day = None) must fall
    back to dataclass defaults, never override them with None."""
    t = from_dict({"user_id": "U1", "hour": None, "working_hours": None, "working_day": None})
    assert t.hour is not None and isinstance(t.hour, int)
    assert isinstance(t.working_hours, bool)
    feats = extract_features(t)
    assert np.all(np.isfinite(feats))


def test_analyze_level_action_consistent_after_llm_boost():
    """The LLM-context boost must keep risk_level and action in lockstep."""
    from unittest.mock import patch

    from engine.behavioral.pipeline import analyze

    t = Telemetry(user_id="U-consist", device_change=True, location_change=True,
                  working_hours=False, hour=2, day_of_week=6,
                  failed_auth_count=3, request_frequency=90,
                  resource_sensitivity="critical", prompt_text="x")

    with patch("engine.behavioral.pipeline.llm_enrich",
               return_value={"context_score": 0.9, "reasons": ["exfil"]}):
        result = analyze(t)

    assert result["threat"]["risk_level"] in ("HIGH", "CRITICAL")
    # action must match the level band, never a stale STEP_UP under HIGH+
    assert result["threat"]["action"] == _level_to_action(result["threat"]["risk_level"])


# ---- 2. collection-time fill honors explicit values ------------------------
def test_bare_telemetry_fills_current_time():
    t = Telemetry(user_id="U2")
    now = datetime.now()
    assert isinstance(t.hour, int) and 0 <= t.hour <= 23
    assert isinstance(t.day_of_week, int) and 0 <= t.day_of_week <= 6
    assert t.working_hours == (9 <= now.hour < 18)
    assert t.timestamp  # ISO filled too


def test_explicit_midnight_is_preserved():
    t = Telemetry(user_id="U3", hour=0, day_of_week=2)
    assert t.hour == 0
    assert t.day_of_week == 2


# ---- 4. CRITICAL band → DENY ------------------------------------------------
def test_score_to_level_bands():
    assert _score_to_level(0) == "LOW"
    assert _score_to_level(30) == "LOW"
    assert _score_to_level(31) == "MEDIUM"
    assert _score_to_level(70) == "MEDIUM"
    assert _score_to_level(71) == "HIGH"
    assert _score_to_level(84) == "HIGH"
    assert _score_to_level(85) == "CRITICAL"
    assert _score_to_level(100) == "CRITICAL"


def test_critical_maps_to_deny_action():
    assert _level_to_action("critical") == "DENY"
    assert _level_to_action("CRITICAL") == "DENY"


def test_build_decision_maps_deny():
    t = Telemetry(user_id="U4", hour=3, day_of_week=1)
    d = build_decision(
        telemetry=t,
        anomaly_result={"anomaly_score": 0.95},
        threat_result={"risk_score": 95, "risk_level": "CRITICAL", "action": "DENY"},
        llm_context={"context_score": 0.2},
        reasons=["hostile"],
    )
    assert d.decision == "DENY"
    assert d.required_authentication == "BLOCK"


# ---- 5. baseline std adapts; persistence round-trips -----------------------
def test_baseline_std_updates():
    b = BehavioralBaseline(user_id="U5")
    std_before = b.normal_frequency_std
    freq = b.normal_frequency + 60  # large deviation from the current mean
    fake = Telemetry(user_id="U5", request_frequency=freq, hour=10, day_of_week=1)
    b.update(fake)
    b.update(fake)
    b.update(fake)
    assert b.normal_frequency_std > std_before


def test_baseline_persistence_roundtrip(tmp_path, monkeypatch):
    import engine.behavioral.baseline as bl

    path = tmp_path / "behavioral_baselines.json"
    monkeypatch.setattr(bl, "_BASELINE_PATH", path)
    bl._baselines.clear()

    t = Telemetry(user_id="U-persist", device_id="dev-1", country="US", region="CA",
                  request_frequency=42.0, hour=10, day_of_week=1)
    bl.update_baseline("U-persist", t)
    assert path.exists()

    bl._baselines.clear()          # simulate a restart
    bl._load_baselines()
    b = get_baseline("U-persist")
    assert b.normal_device_id == "dev-1"
    assert abs(b.normal_frequency - 15.0) < 15.0  # moved toward 42 from 15
    assert b.n_updates == 1


def test_failcount_persistence_roundtrip(tmp_path, monkeypatch):
    import engine.behavioral.response as resp

    path = tmp_path / "behavioral_failcounts.json"
    monkeypatch.setattr(resp, "_FAILCOUNT_PATH", path)
    resp._fail_counts.clear()

    assert resp.escalate_failures("U-fail") == 1
    resp.escalate_failures("U-fail")
    resp.escalate_failures("U-fail")
    assert path.exists()

    resp._fail_counts.clear()      # simulate a restart
    resp._load_failcounts()
    assert resp.get_failure_count("U-fail") == 3
    resp.reset_failures("U-fail")
    assert resp.get_failure_count("U-fail") == 0
