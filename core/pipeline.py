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

    if SETTINGS.max_prompt_chars > 0 and len(prompt) > SETTINGS.max_prompt_chars:
        layers["sanitizer"] = _layer_meta(
            removed=["prompt_too_large"],
            length=len(prompt),
            limit=SETTINGS.max_prompt_chars,
        )
        outcome = PipelineOutcome(
            blocked=True,
            status_code=413,
            body={
                **BlockedResponse(
                    error="prompt too large",
                    reason=f"prompt too large ({len(prompt)} chars > {SETTINGS.max_prompt_chars} limit)",
                    risk_score=1.0,
                    layers=layers,
                    request_id=request_id,
                    latency_ms=round(1000 * (time.perf_counter() - t_start), 2),
                ).model_dump(),
                "limit": SETTINGS.max_prompt_chars,
                "length": len(prompt),
            },
        )
        return _finish(
            request_id, user_id, req, outcome, layers, client_ip,
            t_start, decision_label="block", block_layer="length_guard", risk=1.0,
        )

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

    # ---- Semantic attack memory (Qdrant): recall known-blocked near-dupes -- #
    memory_similarity, memory_payload = 0.0, {}
    if intent.embedding_vector:
        from services import qdrant_client as _qmem

        memory_similarity, memory_payload = _qmem.recall_similar(
            intent.embedding_vector)
    layers["memory"] = _layer_meta(
        similarity=round(memory_similarity, 4),
        matched=memory_similarity >= SETTINGS.memory_block_threshold,
        known_attack=(memory_payload.get("text") or "")[:80] if memory_similarity >= 0.65 else "",
    )

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
                                injection_weightage=sentiment["weightage"],
                                memory_similarity=memory_similarity)

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
        # Semantic memory: remember this attack (deduped) for future recall,
        # and register a long-term user strike (repeat offenders get banned).
        try:
            from services import qdrant_client as _qmem

            _qmem.remember_blocked(sanitized.sanitized_prompt,
                                   intent.embedding_vector,
                                   user_id=user_id, risk=dec.risk_score,
                                   layer=dec.layer)
        except Exception:
            pass
        try:
            behavioral.register_strike(user_id)
        except Exception:
            pass
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


def inspect_prompt_modules(req: ChatCompletionRequest) -> dict[str, Any]:
    """Evaluate all 6 security analysis modules (L1-L5) without calling the LLM.

    Always computes the deep embedding vector so AI Threat Detection,
    Semantic Attack Memory, Behavioral Analysis, and RAG Security all report
    complete numerical scores for the frontend transparency breakdown.
    """
    t_start = time.perf_counter()
    user_id = req.user_id or "anon"
    prompt = req.effective_prompt()

    if SETTINGS.max_prompt_chars > 0 and len(prompt) > SETTINGS.max_prompt_chars:
        lat = round(1000 * (time.perf_counter() - t_start), 2)
        reason = f"prompt too large ({len(prompt)} chars > {SETTINGS.max_prompt_chars} limit)"
        return {
            "blocked": True,
            "error": "prompt too large",
            "limit": SETTINGS.max_prompt_chars,
            "length": len(prompt),
            "risk_score": 1.0,
            "block_layer": "length_guard",
            "reason": reason,
            "latency_ms": lat,
            "modules": {
                "prompt_sanitization": {"score": 100.0, "raw_score": 1.0, "status": "REJECTED", "removed": ["prompt_too_large"], "word_weightage": 0.0, "negative_terms": [], "positive_terms": [], "latency_ms": lat},
                "ai_threat_detection": {"score": 0.0, "raw_score": 0.0, "status": "SKIPPED", "intent_score": 0.0, "tfidf_score": None, "cascade_tier": "fast-reject", "model": "length_guard", "threshold": input_filter.block_threshold(), "latency_ms": 0.0},
                "semantic_attack_memory": {"score": 0.0, "raw_score": 0.0, "status": "CLEAR", "similarity": 0.0, "threshold": SETTINGS.memory_block_threshold, "matched": False, "known_attack": "", "latency_ms": 0.0},
                "behavioral_analysis": {"score": 75.0, "raw_score": 0.75, "status": "HIGH", "cumulative_risk": 0.75, "drift": 0.0, "attack_proximity": 1.0, "turn_count": 1, "sentiment_avg": 0.0, "backend": redis_backend(), "latency_ms": 0.0},
                "rag_security": {"score": 0.0, "raw_score": 0.0, "status": "SAFE", "risk": 0.0, "safe_docs": 0, "dropped_docs": [], "imperative_flags": [], "latency_ms": 0.0},
                "final_decision_engine": {"score": 100.0, "raw_score": 1.0, "status": "BLOCK", "verdict": "BLOCK", "triggered_by": "length_guard", "reason": reason, "latency_ms": lat},
            },
        }

    # 1. Prompt Sanitization + Sentiment Lexicon
    t0 = time.perf_counter()
    sanitized = sanitizer.sanitize(prompt)
    from services.policy_engine import word_sentiment

    # Score word_sentiment on the RAW prompt so negative terms stripped by
    # sanitizer (e.g. "ignore previous instructions") still show their true
    # lexicon weightage in the UI.
    sentiment = word_sentiment(prompt)
    sanitize_ms = round(1000 * (time.perf_counter() - t0), 2)

    # 2. AI Threat Detection (Cascade TF-IDF + Deep MiniLM + XGBoost)
    t0 = time.perf_counter()
    sanitizer_clean = not sanitized.removed
    screen = (cascade_mod.fast_classify(
        sanitized.sanitized_prompt,
        weightage=sentiment["weightage"],
        sanitizer_clean=sanitizer_clean,
    ) if SETTINGS.cascade_enabled
    else {"tier": "deep", "tfidf_score": None, "reason": "cascade disabled",
          "latency_ms": 0.0})
    intent = input_filter.classify(sanitized.sanitized_prompt)
    intent_ms = round(1000 * (time.perf_counter() - t0), 2)

    # 3. Semantic Attack Memory (Qdrant cosine similarity)
    t0 = time.perf_counter()
    memory_similarity, memory_payload = 0.0, {}
    if intent.embedding_vector:
        from services import qdrant_client as _qmem

        memory_similarity, memory_payload = _qmem.recall_similar(
            intent.embedding_vector)
    memory_ms = round(1000 * (time.perf_counter() - t0), 2)

    # 4. Behavioral Analysis (Session EWMA risk, drift, attack proximity)
    t0 = time.perf_counter()
    session = behavioral.track(
        user_id, intent.embedding_vector, intent.intent_score,
        injection_weightage=sentiment["weightage"],
    )
    behavior_ms = round(1000 * (time.perf_counter() - t0), 2)

    # 5. RAG Security (Context-intent consistency, imperatives, credential leaks)
    t0 = time.perf_counter()
    rag = rag_validator.validate(intent.embedding_vector, sanitized.sanitized_prompt)
    rag_ms = round(1000 * (time.perf_counter() - t0), 2)

    # 6. Final Multi-Signal Decision Engine
    t0 = time.perf_counter()
    dec = decision_mod.evaluate(sanitized, intent, session, rag,
                                injection_weightage=sentiment["weightage"],
                                memory_similarity=memory_similarity)
    decision_ms = round(1000 * (time.perf_counter() - t0), 2)

    if dec.blocked:
        try:
            from services import qdrant_client as _qmem

            _qmem.remember_blocked(sanitized.sanitized_prompt,
                                   intent.embedding_vector,
                                   user_id=user_id, risk=dec.risk_score,
                                   layer=dec.layer)
        except Exception:
            pass

    sanitize_score = min(1.0, round(
        max(sentiment["weightage"], 0.85 if sanitized.removed else 0.0), 4))

    return {
        "blocked": dec.blocked,
        "risk_score": dec.risk_score,
        "block_layer": dec.layer or ("none" if not dec.blocked else "policy"),
        "reason": dec.reason,
        "latency_ms": round(1000 * (time.perf_counter() - t_start), 2),
        "modules": {
            "prompt_sanitization": {
                "score": round(sanitize_score * 100, 1),
                "raw_score": sanitize_score,
                "status": "SCRUBBED" if sanitized.removed else ("FLAGGED" if sentiment["weightage"] >= 0.5 else "CLEAN"),
                "removed": sanitized.removed,
                "word_weightage": round(sentiment["weightage"], 4),
                "negative_terms": sentiment["negative_terms"],
                "positive_terms": sentiment["positive_terms"],
                "latency_ms": sanitize_ms,
            },
            "ai_threat_detection": {
                "score": round(intent.intent_score * 100, 1),
                "raw_score": round(intent.intent_score, 4),
                "status": "THREAT" if intent.intent_score >= input_filter.block_threshold() else ("ELEVATED" if intent.intent_score >= 0.4 else "SAFE"),
                "intent_score": round(intent.intent_score, 4),
                "tfidf_score": round(screen["tfidf_score"], 4) if screen.get("tfidf_score") is not None else None,
                "cascade_tier": screen.get("tier", "deep"),
                "model": intent.model_used,
                "threshold": input_filter.block_threshold(),
                "latency_ms": intent_ms,
            },
            "semantic_attack_memory": {
                "score": round(memory_similarity * 100, 1),
                "raw_score": round(memory_similarity, 4),
                "status": "MATCHED" if memory_similarity >= SETTINGS.memory_block_threshold else ("NEAR" if memory_similarity >= 0.70 else "CLEAR"),
                "similarity": round(memory_similarity, 4),
                "threshold": SETTINGS.memory_block_threshold,
                "matched": memory_similarity >= SETTINGS.memory_block_threshold,
                "known_attack": (memory_payload.get("text") or "")[:80] if memory_similarity >= 0.65 else "",
                "latency_ms": memory_ms,
            },
            "behavioral_analysis": {
                "score": round(session.cumulative_risk * 100, 1),
                "raw_score": round(session.cumulative_risk, 4),
                "status": "BLOCKED" if session.blocked else ("HIGH" if session.cumulative_risk >= 0.7 else ("MEDIUM" if session.cumulative_risk >= 0.35 else "LOW")),
                "cumulative_risk": round(session.cumulative_risk, 4),
                "drift": round(session.drift, 4),
                "attack_proximity": round(session.attack_proximity, 4),
                "turn_count": session.turn_count,
                "sentiment_avg": round(session.sentiment_avg, 4),
                "backend": redis_backend(),
                "latency_ms": behavior_ms,
            },
            "rag_security": {
                "score": round(rag.risk * 100, 1),
                "raw_score": round(rag.risk, 4),
                "status": "POISONED" if rag.risk >= 0.7 else ("FILTERED" if rag.dropped_docs else "SAFE"),
                "risk": round(rag.risk, 4),
                "safe_docs": len(rag.safe_rag_docs),
                "dropped_docs": rag.dropped_docs,
                "imperative_flags": rag.imperative_flags,
                "latency_ms": rag_ms,
            },
            "final_decision_engine": {
                "score": round(dec.risk_score * 100, 1),
                "raw_score": round(dec.risk_score, 4),
                "status": "BLOCK" if dec.blocked else ("RESTRICT" if dec.risk_score >= 0.5 else "ALLOW"),
                "verdict": "BLOCK" if dec.blocked else "ALLOW",
                "triggered_by": dec.layer or "none",
                "reason": dec.reason or "all security modules passed",
                "latency_ms": decision_ms,
            },
        },
    }


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
