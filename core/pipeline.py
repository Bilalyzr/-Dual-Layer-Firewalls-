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
    try:
        if audit_log.is_banned(user_id):
            return _finish(request_id, user_id, req, PipelineOutcome(
                blocked=True, status_code=403,
                body=BlockedResponse(reason="user banned").model_dump(),
            ), layers, client_ip, t_start, decision_label="block", block_layer="ban")
    except Exception:
        pass

    prompt = req.effective_prompt()

    # ---- L1: Prompt Sanitization ----------------------------------------- #
    t0 = time.perf_counter()
    sanitized = sanitizer.sanitize(prompt)
    layers["sanitizer"] = _layer_meta(removed=sanitized.removed)
    metrics.observe_latency("sanitizer", time.perf_counter() - t0)

    # ---- L2: Semantic Intent Guardrail ----------------------------------- #
    t0 = time.perf_counter()
    intent = input_filter.classify(sanitized.sanitized_prompt)
    layers["intent"] = _layer_meta(
        intent_score=round(intent.intent_score, 4),
        model=intent.model_used,
        degraded=intent.degraded,
    )
    metrics.observe_latency("intent", time.perf_counter() - t0)

    # ---- L3: Behavioral Session Layer (stateful) -------------------------- #
    t0 = time.perf_counter()
    session = behavioral.track(user_id, intent.embedding_vector, intent.intent_score)
    layers["behavioral"] = _layer_meta(
        cumulative_risk=session.cumulative_risk,
        drift=session.drift,
        turn_count=session.turn_count,
        attack_proximity=session.attack_proximity,
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
    dec = decision_mod.evaluate(sanitized, intent, session, rag)
    if dec.blocked:
        behavioral.reset(user_id)          # PDF §3.3: terminate + reset session
        metrics.inc_layer_block(dec.layer)
        outcome = PipelineOutcome(
            blocked=True, status_code=403,
            body=BlockedResponse(reason=dec.reason, risk_score=dec.risk_score).model_dump(),
        )
        return _finish(request_id, user_id, req, outcome, layers, client_ip,
                       t_start, decision_label="block", block_layer=dec.layer,
                       risk=dec.risk_score)

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
        ),
    ).model_dump()

    outcome = PipelineOutcome(blocked=False, status_code=200, body=body)
    return _finish(request_id, user_id, req, outcome, layers, client_ip,
                   t_start, decision_label="filtered" if not out.safe else "allow",
                   risk=dec.risk_score)


# --------------------------------------------------------------------------- #
def _finish(request_id: str, user_id: str, req: ChatCompletionRequest,
            outcome: PipelineOutcome, layers: dict, client_ip: str,
            t_start: float, *, decision_label: str, risk: float = 0.0,
            block_layer: str = "") -> PipelineOutcome:
    outcome.request_id = request_id
    outcome.latency_ms = round(1000 * (time.perf_counter() - t_start), 2)
    metrics.inc_requests(decision_label)
    metrics.observe_risk(risk)
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
