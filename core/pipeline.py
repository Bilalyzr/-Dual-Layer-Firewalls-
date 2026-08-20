r"""
FIREWALL PIPELINE — Layers 1..7 orchestration (diagram "FIREWALL PIPELINE
(Layers 2 → 5)" plus ingress/egress).

    ingest -> L1 sanitize -> L2 intent -> L3 behavioral -> L4 rag
           -> L5 decision --block--> 403 {"error": "Request blocked by firewall",
                                           "reason": "cumulative risk exceeded"}
                        \--pass--> L6 LiteLLM -> L7 output filter -> 200 OK

Every stage is fail-open and independently observable; the whole bus is
attached to the response's `guardrails` block and the audit trail.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

from core.config import SETTINGS
from guardrails import behavioral, decision as decision_mod, input_filter
from guardrails import cascade as cascade_mod
from guardrails import output_filter as output_filter_mod
from guardrails import rag_validator, sanitizer
from models.schemas import (BlockedResponse, ChatCompletionRequest,
                            ChatCompletionResponse, GuardrailStatus)
from services import audit_log, litellm_client, metrics
from services.redis_client import backend_name as redis_backend


@dataclass
class PipelineOutcome:
    blocked: bool = False
    status_code: int = 200
    body: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    latency_ms: float = 0.0


def _layer_meta(**kw) -> dict[str, Any]:
    return {k: v for k, v in kw.items()}


def execute_firewall_pipeline(req: ChatCompletionRequest,
                              client_ip: str = "") -> PipelineOutcome:
    """Run the full 7-layer flow. Pure orchestration — logic lives in layers."""
    t_start = time.perf_counter()
    request_id = f"fw-{os.urandom(6).hex()}"
    user_id = req.user_id or "anon"

    layers: dict[str, Any] = {}

    # ---- Ingress: bans + rate limit ------------------------------------- #
    session_key = req.session_id or f"user:{user_id}"
    try:
        if audit_log.is_banned(user_id):
            return _finish(request_id, user_id, req, PipelineOutcome(
                blocked=True, status_code=403,
                body=BlockedResponse(
                    reason="user banned",
                    request_id=request_id,
                    latency_ms=0.0,
                ).model_dump(),
            ), layers, client_ip, t_start, decision_label="block", block_layer="ban")
    except Exception:
        pass

    prompt = req.effective_prompt()

    # ---- L1: Prompt Sanitization ----------------------------------------- #
    t0 = time.perf_counter()
    sanitized = sanitizer.sanitize(prompt)
    layers["sanitizer"] = _layer_meta(removed=sanitized.removed)
    metrics.observe_latency("sanitizer", time.perf_counter() - t0)

    # ---- Trial-update #1: word-injection sentiment (display during input) - #
    t0 = time.perf_counter()
    from services.policy_engine import word_sentiment

    sentiment = word_sentiment(sanitized.sanitized_prompt)
    layers["sentiment"] = _layer_meta(
        negative_terms=sentiment["negative_terms"],
        positive_terms=sentiment["positive_terms"],
        negative_total=sentiment["negative_total"],
        positive_total=sentiment["positive_total"],
        weightage=sentiment["weightage"],
        average_score=sentiment["average_score"],
        matched_terms=sentiment["matched_terms"],
    )
    metrics.observe_latency("sentiment", time.perf_counter() - t0)

    # ---- L2: Two-tier cascade (TF-IDF screening -> MiniLM depth) --------- #
    t0 = time.perf_counter()
    sanitizer_clean = not sanitized.removed
    screen = (cascade_mod.fast_classify(
        sanitized.sanitized_prompt,
        weightage=sentiment["weightage"],
        sanitizer_clean=sanitizer_clean,
    ) if SETTINGS.cascade_enabled
    else {"tier": "deep", "tfidf_score": None, "reason": "cascade disabled",
          "latency_ms": 0.0})
    metrics.observe_latency("cascade", time.perf_counter() - t0)
    if hasattr(metrics, "inc_cascade_tier"):
        metrics.inc_cascade_tier(screen["tier"])

    # FAST tiers skip the ~33ms MiniLM embed; DEEP runs it for the verdict.
    t0 = time.perf_counter()
    if screen["tier"] == "deep":
        intent = input_filter.classify(sanitized.sanitized_prompt)
    else:
        from models.schemas import IntentResult

        intent = IntentResult(
            intent_score=max(screen["tfidf_score"] or 0.0,
                             sentiment["weightage"] * 0.9),
            embedding_vector=[],     # no embed on fast tiers
            model_used=f"cascade-{screen['tier']}",
            degraded=False,
        )
    layers["cascade"] = _layer_meta(**screen)
    layers["intent"] = _layer_meta(
        intent_score=round(intent.intent_score, 4),
        model=intent.model_used,
        degraded=intent.degraded,
    )
    metrics.observe_latency("intent", time.perf_counter() - t0)

    # ---- L3: Behavioral Session Layer (stateful) -------------------------- #
    t0 = time.perf_counter()
    session = behavioral.track(
        user_id, intent.embedding_vector, intent.intent_score,
        injection_weightage=sentiment["weightage"],   # trial-update #3
    )
    layers["behavioral"] = _layer_meta(
        cumulative_risk=session.cumulative_risk,
        drift=session.drift,
        turn_count=session.turn_count,
        attack_proximity=session.attack_proximity,
        injection_weightage=session.injection_weightage,
        sentiment_avg=session.sentiment_avg,           # trial-update #2
        backend=redis_backend(),
    )
    metrics.observe_latency("behavioral", time.perf_counter() - t0)

    # ---- L4: RAG Context Validation --------------------------------------- #
    t0 = time.perf_counter()
    rag = rag_validator.validate(intent.embedding_vector, sanitized.sanitized_prompt)
    layers["rag"] = _layer_meta(
        safe_docs=len(rag.safe_rag_docs),
        dropped=rag.dropped_docs,
        imperative_flags=rag.imperative_flags,
        risk=rag.risk,
    )
    metrics.observe_latency("rag", time.perf_counter() - t0)

    # ---- L5: Pipeline Decision -------------------------------------------- #
    dec = decision_mod.evaluate(sanitized, intent, session, rag,
                                injection_weightage=sentiment["weightage"])

    # ---- Persist the session record (trial-update: sessions in the DB) ---- #
    try:
        audit_log.upsert_session(
            session_key=session_key, user_id=user_id, turns=session.turn_count,
            risk=dec.risk_score, sentiment_avg=session.sentiment_avg,
            status="blocked" if dec.blocked else "active",
        )
    except Exception:
        pass

    if dec.blocked:
        behavioral.reset(user_id)          # PDF §3.3: terminate + reset session
        metrics.inc_layer_block(dec.layer)
        # Vulnerability capture: the blocked input becomes retraining material
        try:
            audit_log.record_vulnerability(
                prompt_text=sanitized.sanitized_prompt,
                layer=dec.layer, risk=dec.risk_score, source="auto",
            )
        except Exception:
            pass
        outcome = PipelineOutcome(
            blocked=True, status_code=403,
            body=BlockedResponse(
                reason=dec.reason, risk_score=dec.risk_score, layers=layers,
                request_id=request_id,
                latency_ms=round(1000 * (time.perf_counter() - t_start), 2),
                session={
                    "status": "blocked",
                    "turns": session.turn_count,
                    "cumulative_risk": session.cumulative_risk,
                    "sentiment_avg": session.sentiment_avg,
                },
            ).model_dump(),
        )
        return _finish(request_id, user_id, req, outcome, layers, client_ip,
                       t_start, decision_label="block", block_layer=dec.layer,
                       risk=dec.risk_score,
                       training_text=sanitized.sanitized_prompt)

    # ---- L6: Upstream LLM Execution (LiteLLM router) ---------------------- #
    t0 = time.perf_counter()
    llm_response = litellm_client.complete(
        sanitized.sanitized_prompt, rag.safe_rag_docs, model=req.model
    )
    layers["llm"] = _layer_meta(router=litellm_client.status()["mode"],
                                model=req.model or SETTINGS.default_llm_model)
    metrics.observe_latency("llm", time.perf_counter() - t0)

    # ---- L7: Egress Output Guardrail -------------------------------------- #
    t0 = time.perf_counter()
    out = output_filter_mod.filter_response(llm_response)
    layers["output"] = _layer_meta(
        safe=out.safe, toxicity=out.toxicity_score,
        pii_leak=out.pii_leak, violations=out.policy_violations,
    )
    metrics.observe_latency("output", time.perf_counter() - t0)

    body = ChatCompletionResponse(
        response=out.filtered_response,
        model=req.model or SETTINGS.default_llm_model,
        guardrails=GuardrailStatus(
            status="passed" if out.safe else "filtered",
            risk_score=dec.risk_score,
            layers=layers,
            latency_ms=round(1000 * (time.perf_counter() - t_start), 2),
            request_id=request_id,
        ),
    ).model_dump()

    # Adversarial sampling (PDF §3.1): allowed-but-risky prompts are queued
    # for review so borderline evasions become tomorrow's training data.
    if 0.5 <= dec.risk_score < SETTINGS.intent_block_threshold:
        try:
            audit_log.record_vulnerability(
                prompt_text=sanitized.sanitized_prompt, layer="sampling",
                risk=dec.risk_score, source="sampling",
            )
        except Exception:
            pass

    outcome = PipelineOutcome(blocked=False, status_code=200, body=body)
    return _finish(request_id, user_id, req, outcome, layers, client_ip,
                   t_start, decision_label="filtered" if not out.safe else "allow",
                   risk=dec.risk_score,
                   training_text=sanitized.sanitized_prompt)


# --------------------------------------------------------------------------- #
def _finish(request_id: str, user_id: str, req: ChatCompletionRequest,
            outcome: PipelineOutcome, layers: dict, client_ip: str,
            t_start: float, *, decision_label: str, risk: float = 0.0,
            block_layer: str = "", training_text: str = "") -> PipelineOutcome:
    outcome.request_id = request_id
    outcome.latency_ms = round(1000 * (time.perf_counter() - t_start), 2)
    metrics.inc_requests(decision_label)
    metrics.observe_risk(risk)
    # Real-time learning capture (trial-update): the FINAL verdict labels the
    # real prompt — blocked => threat, allowed => benign — so the model keeps
    # training on live traffic, never a predefined set.
    # POISONING GUARD: allowed-but-risky traffic (0.5..0.9) is NOT stored as
    # benign — those are near-miss attacks, and training on them as benign
    # makes the model FORGET the attack (observed live). Borderline traffic
    # goes to the 'sampling' vulnerability queue for review instead; only
    # confident allows teach the benign class.
    if training_text:
        confident_benign = decision_label != "block" and risk < 0.5
        if decision_label == "block" or confident_benign:
            try:
                from services import realtime_learner

                realtime_learner.record(
                    text=training_text,
                    label=1 if decision_label == "block" else 0,
                    source="realtime",
                    scores={"risk": round(risk, 4)},
                )
            except Exception:
                pass
    try:
        audit_log.record(
            request_id=request_id, user_id=user_id, session_id=req.session_id,
            decision=decision_label, risk_score=risk,
            reason=block_layer or "", layers=layers, client_ip=client_ip,
        )
    except Exception:
        pass
    # Ban only on *behavioral* blocks — the repeated-abuse pattern — not on a
    # single-turn intent hit (the PDF's #1 risk is locking out valid users;
    # one block + rate limiting is enough for first offenders).
    if block_layer == "behavioral":
        try:
            audit_log.ban_user(user_id, "cumulative risk exceeded")
        except Exception:
            pass
    return outcome
