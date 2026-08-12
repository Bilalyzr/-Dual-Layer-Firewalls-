"""
Tests for the advanced modules added on top of the behavioral pipeline:
  - DNN 3-class threat determination (PRD §22.3)
  - Behavioral event store + /event, /events, /stats (PRD §20, §25, §27, FR-12)
"""
import pytest
import numpy as np

from engine.behavioral.telemetry import Telemetry
from engine.behavioral.features import extract_features
from engine.behavioral import store
from engine.behavioral import dnn_threat
from engine.behavioral.anomaly_svm import model_ready as svm_ready, predict as svm_predict


# ---- Event store ----------------------------------------------------------
def test_store_record_and_query():
    store.reset()
    rec = store.record({
        "user_id": "U9", "session_id": "S1", "risk_score": 80.0,
        "risk_level": "HIGH", "decision": "RESTRICT",
    })
    assert rec["event_id"] == 1
    events = store.query(limit=10)
    assert len(events) == 1
    assert events[0]["user_id"] == "U9"


def test_store_filters():
    store.reset()
    store.record({"user_id": "A", "session_id": "sa", "risk_level": "LOW", "risk_score": 10, "decision": "ALLOW"})
    store.record({"user_id": "B", "session_id": "sb", "risk_level": "HIGH", "risk_score": 90, "decision": "RESTRICT"})
    assert len(store.query(user_id="A")) == 1
    assert len(store.query(risk_level="high")) == 1
    assert store.query(user_id="A")[0]["user_id"] == "A"


def test_store_newest_first():
    store.reset()
    for i in range(5):
        store.record({"user_id": f"U{i}", "session_id": f"s{i}", "risk_level": "LOW", "risk_score": i, "decision": "ALLOW"})
    events = store.query(limit=10)
    assert events[0]["user_id"] == "U4"  # newest first


def test_store_stats_command_center():
    store.reset()
    store.record({"user_id": "A", "session_id": "sa", "risk_level": "LOW", "risk_score": 10, "decision": "ALLOW"})
    store.record({"user_id": "B", "session_id": "sb", "risk_level": "HIGH", "risk_score": 90, "decision": "RESTRICT"})
    st = store.stats()
    for key in ("active_users", "active_sessions", "low_risk_sessions",
                "medium_risk_sessions", "high_risk_sessions", "blocked_sessions",
                "total_events", "recent_anomalies", "user_risk_table"):
        assert key in st
    assert st["total_events"] == 2
    assert st["active_sessions"] == 2
    assert st["high_risk_sessions"] == 1
    assert st["blocked_sessions"] == 1
    assert len(st["recent_anomalies"]) == 1  # only the HIGH one


def test_pipeline_records_to_store():
    store.reset()
    if not svm_ready():
        pytest.skip("behavioral models not trained")
    from engine.behavioral.pipeline import analyze
    analyze(Telemetry(user_id="Z1", session_id="zsess"))
    assert store.stats()["total_events"] == 1


# ---- DNN threat model -----------------------------------------------------
def test_dnn_graceful_when_absent():
    # model_ready must never raise; returns False if artifact/torch missing.
    assert isinstance(dnn_threat.model_ready(), bool)


def test_dnn_classifies_when_trained():
    if not (svm_ready() and dnn_threat.model_ready()):
        pytest.skip("DNN not trained — run: python -m engine.behavioral.generate_behavioral_data --dnn")
    t = Telemetry(user_id="U1", hour=3, working_hours=False, registered_device=False,
                  device_change=True, device_trust=0.1, location_change=True,
                  location_frequency=0.05, request_frequency=150,
                  resource_sensitivity="critical", resource_type="database",
                  failed_auth_count=2)
    feats = extract_features(t)
    anomaly = svm_predict(feats)
    result = dnn_threat.classify_risk_dnn(feats, anomaly["anomaly_score"])
    assert result["model_used"] == "dnn"
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert 0 <= result["risk_score"] <= 100
    probs = result["probabilities"]
    assert abs(probs["low"] + probs["medium"] + probs["high"] - 1.0) < 0.05


def test_threat_engine_dnn_toggle(monkeypatch):
    """When BEHAVIORAL_THREAT_MODEL=dnn and the DNN is present, threat_engine
    routes through it; otherwise it falls back without raising."""
    if not svm_ready():
        pytest.skip("behavioral models not trained")
    from engine.behavioral import threat_engine
    monkeypatch.setenv("BEHAVIORAL_THREAT_MODEL", "dnn")
    t = Telemetry(user_id="U1", hour=12, working_hours=True, registered_device=True,
                  device_trust=0.9, request_frequency=10, resource_sensitivity="low")
    feats = extract_features(t)
    anomaly = svm_predict(feats)
    result = threat_engine.classify_risk(feats, anomaly["anomaly_score"])
    # Either the DNN handled it, or we fell back cleanly to RF/heuristic.
    assert result["model_used"] in ("dnn", "random_forest", "heuristic")
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH")
