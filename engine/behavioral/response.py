"""
Component 7 — Adaptive Response / Authentication (PRD §24-26).

Maps risk_level → action with escalation logic for failed authentications.
Generates the Behavioral Decision Object (PRD §29).
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class BehavioralDecision:
    """The structured decision object (PRD §29)."""
    user_id: str
    session_id: str = ""
    device_trusted: bool = True
    location_change: bool = False
    off_hours: bool = False
    resource_risk: str = "low"
    request_frequency: float = 0.0
    behavior_anomaly_score: float = 0.0
    llm_context_score: float = 0.0
    risk_score: float = 0.0
    risk_level: str = "LOW"
    required_authentication: str = "NORMAL"
    decision: str = "ALLOW"
    reasons: list[str] = None
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items()}


# Failed-auth escalation state per user: {userId: fail_count}
_fail_counts: dict[str, int] = {}


def escalate_failures(user_id: str) -> int:
    """Increment and return the failed-auth count for a user."""
    _fail_counts[user_id] = _fail_counts.get(user_id, 0) + 1
    return _fail_counts[user_id]


def reset_failures(user_id: str):
    _fail_counts.pop(user_id, None)


def get_failure_count(user_id: str) -> int:
    return _fail_counts.get(user_id, 0)


def build_decision(
    *,
    telemetry,
    anomaly_result: dict,
    threat_result: dict,
    llm_context: dict | None = None,
    reasons: list[str] | None = None,
) -> BehavioralDecision:
    """Assemble the full Behavioral Decision Object from all pipeline outputs."""
    risk_level = threat_result.get("risk_level", "LOW")
    action = threat_result.get("action", "ALLOW")

    # Escalation: if the user has prior failed auths, bump the response.
    fails = get_failure_count(telemetry.user_id)
    if fails >= 3 and action != "DENY":
        action = "RESTRICT"
        risk_level = "HIGH"
        if reasons:
            reasons.append(f"escalated due to {fails} prior failed authentications")

    auth_map = {"LOW": "NORMAL", "MEDIUM": "STEP_UP", "HIGH": "STRONG_MFA"}
    decision_map = {"ALLOW": "ALLOW", "STEP_UP": "STEP_UP", "RESTRICT": "RESTRICT"}

    return BehavioralDecision(
        user_id=telemetry.user_id,
        session_id=telemetry.session_id,
        device_trusted=telemetry.registered_device and not telemetry.device_change,
        location_change=telemetry.location_change,
        off_hours=not telemetry.working_hours,
        resource_risk=telemetry.resource_sensitivity,
        request_frequency=telemetry.request_frequency,
        behavior_anomaly_score=anomaly_result.get("anomaly_score", 0.0),
        llm_context_score=(llm_context or {}).get("context_score", 0.0),
        risk_score=threat_result.get("risk_score", 0.0),
        risk_level=risk_level,
        required_authentication=auth_map.get(risk_level, "NORMAL"),
        decision=decision_map.get(action, "ALLOW"),
        reasons=reasons or [],
        timestamp=telemetry.timestamp,
    )
