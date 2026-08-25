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
             injection_weightage: float = 0.0,
             memory_similarity: float = 0.0) -> Decision:
    # Composite risk: the strongest signal any layer produced this turn
    # (trial-update #3: word-injection weightage is part of the composite;
    #  T9: memory-similarity and attack-proximity now included too, so a
    #  pure memory/proximity block can't display a misleadingly low risk).
    risk = max(
        intent.intent_score,
        session.cumulative_risk,
        rag.risk,
        injection_weightage * 0.9,
        memory_similarity,
        session.attack_proximity * 0.9,
    )

    # L2 — single-turn semantic kill-shot (PDF §3.3: instant termination).
    if intent.intent_score >= block_threshold():
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "intent")

    # Defense-in-depth (trial requirement: ANY user-crafted attack blocks):
    # a single overwhelming signal OR corroborated signals are enough —
    # novel phrasings that dodge the classifier alone still get caught.
    sanitizer_hit = any(r.startswith("jailbreak") for r in sanitized.removed)
    if injection_weightage >= 0.95:  # saturated attack vocabulary (e.g. 0.98)
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "sentiment")
    if injection_weightage >= 0.5 and intent.intent_score >= 0.5:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "sentiment+intent")
    if session.attack_proximity >= 0.85 and intent.intent_score >= 0.5:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "proximity+intent")
    # L1 caught an instruction-override pattern (incl. obfuscated forms) and
    # the semantic score is at least ambivalent — benign users don't leetspeak
    # "ignore prior constraints", so the pair is damning together.
    if sanitizer_hit and intent.intent_score >= 0.4:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "sanitizer+intent")
    # A smuggled base64 payload that DECODES to an instruction override is an
    # attack outright — no benign reason to encode "ignore all rules".
    if any(r.startswith("base64-payload") for r in sanitized.removed):
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "sanitizer")
    # SEMANTIC MEMORY: a near-duplicate (cosine >= threshold) of an attack we
    # already blocked. Repeat attacks are recognized on sight.
    if memory_similarity >= SETTINGS.memory_block_threshold:
        return Decision(True, "cumulative risk exceeded", round(risk, 4), "memory")

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
