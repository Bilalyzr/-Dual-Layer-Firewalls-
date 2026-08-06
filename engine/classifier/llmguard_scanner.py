"""
LLM Guard integration (Protect AI) — production-grade prompt-injection scanner.

Wraps the DeBERTa-v3-based PromptInjection scanner from the `llm-guard` library.
This is a deeper, model-based detector than our TF-IDF + LogReg ensemble — it
catches subtle semantic injections that keyword/regex approaches miss.

Usage in /classify: runs ALONGSIDE the existing ensemble; the final threat
probability is the max(ensemble_proba, llmguard_risk) so either detector
flagging a threat is enough to block it.

Enabled when `LLMGUARD_ENABLED=true` (default off — the model is ~400MB and
needs first-use download). Falls back to the ensemble when disabled.
"""
from __future__ import annotations
import os
import time

_scanner = None


def enabled() -> bool:
    return os.getenv("LLMGUARD_ENABLED", "false").lower() == "true"


def _get_scanner():
    global _scanner
    if _scanner is None:
        from llm_guard.input_scanners import PromptInjection

        _scanner = PromptInjection()
    return _scanner


def scan(text: str) -> dict:
    """
    Scan text for prompt injection via LLM Guard.

    Returns { risk_score: float (-1..1, higher=more dangerous), detected: bool,
              latency_ms: float }.
    Never throws — on any error returns risk_score=0 (fail-open).
    """
    if not enabled():
        return {"risk_score": 0.0, "detected": False, "latency_ms": 0.0, "enabled": False}
    if not text or not text.strip():
        return {"risk_score": 0.0, "detected": False, "latency_ms": 0.0, "enabled": True}

    t0 = time.perf_counter()
    try:
        scanner = _get_scanner()
        _sanitized, _valid, risk = scanner.scan(text)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        # LLM Guard risk: -1 = no injection, 0..1 = injection probability
        threat_prob = max(0.0, float(risk)) if risk > 0 else 0.0
        return {
            "risk_score": round(threat_prob, 4),
            "detected": threat_prob >= 0.5,
            "latency_ms": round(latency_ms, 2),
            "enabled": True,
        }
    except Exception as exc:
        return {"risk_score": 0.0, "detected": False, "latency_ms": 0.0, "enabled": True, "error": str(exc)}
