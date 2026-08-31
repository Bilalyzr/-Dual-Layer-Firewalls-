"""
End-to-end Behavioral Risk Pipeline (PRD §27).

Orchestrates all 7 components:
  Telemetry → Features → Baseline → One-Class SVM → LLM Context → RF Threat → Adaptive Response

Produces the Behavioral Decision Object (PRD §29).
"""
from __future__ import annotations
import time

from .telemetry import Telemetry
from .features import extract_features
from .baseline import get_baseline
from .anomaly_svm import score_anomaly, predict as svm_predict
from .threat_engine import classify_risk
from .context_enrichment import enrich as llm_enrich
from .response import build_decision


def analyze(telemetry: Telemetry) -> dict:
    """Run the full behavioral risk pipeline on a telemetry event.

    Returns the Behavioral Decision Object (PRD §29) as a dict.
    """
    t0 = time.perf_counter()

    # Component 3: Load baseline for this user
    baseline = get_baseline(telemetry.user_id, telemetry.role)

    # Component 2: Feature engineering
    features = extract_features(telemetry, baseline_frequency=baseline.normal_frequency)

    # Component 4: One-Class SVM anomaly detection
    anomaly = svm_predict(features)

    # Component 5: LLM context enrichment (optional, off-path)
    llm_ctx = llm_enrich({
        "user_id": telemetry.user_id,
        "role": telemetry.role,
        "registered_device": telemetry.registered_device,
        "device_trust": telemetry.device_trust,
        "country": telemetry.country,
        "region": telemetry.region,
        "location_change": telemetry.location_change,
        "hour": telemetry.hour,
        "working_hours": telemetry.working_hours,
        "resource_type": telemetry.resource_type,
        "resource_sensitivity": telemetry.resource_sensitivity,
        "request_frequency": telemetry.request_frequency,
        "failed_auth_count": telemetry.failed_auth_count,
        "prompt_text": telemetry.prompt_text,
    })

    # Component 6: Threat Determination (Random Forest)
    threat = classify_risk(features, anomaly["anomaly_score"])

    # Boost risk if LLM context flagged exfiltration/unusual
    if llm_ctx.get("context_score", 0) > 0.5:
        threat["risk_score"] = min(100, threat["risk_score"] + llm_ctx["context_score"] * 20)
        from .threat_engine import _score_to_level
        threat["risk_level"] = _score_to_level(threat["risk_score"])

    # Layer-1 bridge: a confirmed prompt injection is itself a hostile
    # behavioral signal — boost the risk and let §35 explain it.
    if telemetry.prompt_injection:
        threat["risk_score"] = min(100, threat["risk_score"] + 30)
        from .threat_engine import _score_to_level
        threat["risk_level"] = _score_to_level(threat["risk_score"])

    # Generate explainability reasons (PRD §35)
    reasons = _generate_reasons(telemetry, anomaly, baseline, llm_ctx)

    # Component 7: Adaptive Response
    decision = build_decision(
        telemetry=telemetry,
        anomaly_result=anomaly,
        threat_result=threat,
        llm_context=llm_ctx,
        reasons=reasons,
    )

    latency_ms = (time.perf_counter() - t0) * 1000.0
    result = decision.to_dict()
    result["anomaly"] = anomaly
    result["llm_context"] = llm_ctx
    result["threat"] = threat
    result["latency_ms"] = round(latency_ms, 2)

    # FR-12 Security Logging — persist the decision for /events + command center.
    from .store import record
    record(result)
    return result


def _generate_reasons(telemetry: Telemetry, anomaly: dict, baseline, llm_ctx: dict) -> list[str]:
    """Explainability — why is this behavior flagged? (PRD §35)

    Injection reasons are PROMPT-SPECIFIC: they quote the offending prompt
    and the exact attack vocabulary with weights, so the dashboard's
    EXPLAINABILITY block explains the prompt itself, not just context.
    """
    reasons = []
    if telemetry.prompt_injection:
        snippet = (telemetry.prompt_text or "").strip()
        if snippet:
            shown = snippet[:70] + ("…" if len(snippet) > 70 else "")
            reasons.append(f'Prompt injection detected: "{shown}"')
        else:
            reasons.append("Prompt injection detected in user input (Layer-1 firewall)")
        neg = (telemetry.word_scores or {}).get("negative_terms") or []
        if neg:
            top = sorted(neg, key=lambda t: -float(t.get("weight", 0)))[:4]
            terms = ", ".join(f"{t.get('term')} ({float(t.get('weight', 0)):.2f})" for t in top)
            reasons.append(f"Attack vocabulary in prompt: {terms}")
        w = (telemetry.word_scores or {}).get("weightage")
        if w is not None:
            reasons.append(f"Word-injection weightage: {float(w) * 100:.0f}%")
        pos = (telemetry.word_scores or {}).get("positive_terms") or []
        if pos:
            terms = ", ".join(str(t.get("term")) for t in pos[:3])
            reasons.append(f"Benign-context terms present (dampeners): {terms}")
    if telemetry.device_change:
        reasons.append("New device detected")
    if telemetry.location_change:
        reasons.append("New location detected")
    if not telemetry.working_hours:
        reasons.append("Access outside normal working hours")
    if telemetry.resource_sensitivity in ("high", "critical"):
        reasons.append(f"Sensitive resource requested ({telemetry.resource_sensitivity})")
    if telemetry.request_frequency > baseline.normal_frequency + 2 * baseline.normal_frequency_std:
        reasons.append(
            f"Request frequency ({telemetry.request_frequency:.0f}/hr) "
            f"significantly above baseline ({baseline.normal_frequency:.0f}/hr)"
        )
    if telemetry.failed_auth_count > 0:
        reasons.append(f"{telemetry.failed_auth_count} prior failed authentications")
    if anomaly.get("anomaly_score", 0) > 0.5:
        reasons.append(f"Behavioral anomaly detected (score={anomaly['anomaly_score']:.2f})")
    if llm_ctx.get("signals", {}).get("potential_exfiltration"):
        reasons.append("LLM context: potential data exfiltration pattern")
    if not reasons:
        reasons.append("Behavior within established baseline")
    return reasons
