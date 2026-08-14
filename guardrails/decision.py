"""
LAYER 5 — PIPELINE DECISION (diagram: "If any layer blocks (Rejected)
Return 403 ... Else Proceed").

Pure function over the layer results — no I/O — so it is trivially testable.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.config import SETTINGS
from guardrails.input_filter import block_threshold
from models.schemas import (IntentResult, RagValidationResult, SanitizeResult,
                            SessionRiskResult)


@dataclass
class Decision:
    blocked: bool
    reason: str = ""            # exact diagram string on block
    risk_score: float = 0.0     # composite shown in the response guardrails block
    layer: str = ""             # which layer owns the block (metrics)


def evaluate(sanitized: SanitizeResult, intent: IntentResult,
             session: SessionRiskResult, rag: RagValidationResult,
             injection_weightage: float = 0.0) -> Decision:
    # Composite risk: the strongest signal any layer produced this turn
    # (trial-update #3: word-injection weightage is part of the composite).
    risk = max(
        intent.intent_score,
        session.cumulative_risk,
        rag.risk,
        injection_weightage * 0.9,
    )

    # L2 — single-turn semantic kill-shot (PDF §3.3: instant termination).
    if intent.intent_score >= block_threshold():
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "intent")

    # L3 — multi-turn cumulative risk (the diagram's block reason verbatim).
    if session.blocked:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "behavioral")

    # L4 — poisoned context is dropped by the validator itself; only a fully
    # poisoned retrieval escalates to a block.
    if rag.risk >= 0.95:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "rag")

    # Policy guard: explicitly denied topics (optional, off by default).
    if SETTINGS.policy_enforce_denied_topics:
        from services import policy_engine

        if policy_engine.denied_topic_hits(sanitized.sanitized_prompt):
            return Decision(True, "cumulative risk exceeded", round(risk, 4), "policy")

    return Decision(False, "", round(risk, 4), "")
