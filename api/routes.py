"""
Routes (PDF §4.2 api/routes.py; diagram: POST /v1/chat/completions).

  POST /v1/chat/completions  — the 7-layer pipeline (200 OK | 403 | 429)
  GET  /health               — layer readiness for probes
  GET  /metrics              — Prometheus scrape endpoint
  GET  /admin/events         — recent audit events (forensics)
  GET  /session/risk/{uid}   — peek at the Redis session-risk state
  DELETE /session/risk/{uid} — terminate a session (PDF §3.3 reset)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.dependencies import firewall_pipeline
from core.config import SETTINGS
from core.pipeline import PipelineOutcome
from guardrails import behavioral
from models.schemas import ChatCompletionRequest
from services import audit_log, litellm_client, metrics, qdrant_client
from services.embedding_service import status as embed_status
from services.redis_client import backend_name as redis_backend
from guardrails.input_filter import status as intent_status

router = APIRouter()


@router.post("/v1/chat/completions")
def chat_completions(outcome: PipelineOutcome = Depends(firewall_pipeline)):
    if outcome.blocked:
        return JSONResponse(status_code=outcome.status_code, content=outcome.body)
    return JSONResponse(status_code=200, content=outcome.body)


@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": SETTINGS.api_title,
        "layers": {
            "sanitizer": SETTINGS.sanitizer_enabled,
            "intent": intent_status(),
            "embedding": embed_status(),
            "behavioral": {"backend": redis_backend(), "ttl_s": SETTINGS.session_risk_ttl_s},
            "rag": {"backend": qdrant_client.backend_name(), "ready": qdrant_client.ready()},
            "llm": litellm_client.status(),
            "output_filter": SETTINGS.output_filter_enabled,
        },
        "audit_backend": audit_log.backend_name(),
    }


@router.get("/metrics")
def prometheus_metrics():
    body, ctype = metrics.render()
    return Response(content=body, media_type=ctype)


@router.get("/admin/events")
def admin_events(limit: int = 50):
    return {"backend": audit_log.backend_name(),
            "events": audit_log.recent_events(limit)}


# --------------------------------------------------------------------------- #
# Real-time learning (trial-update: train on LIVE traffic, not a predefined set)
# --------------------------------------------------------------------------- #
class RealtimeSampleRequest(ChatCompletionRequest):
    label: int = 1          # 1 = threat, 0 = benign
    source: str = "external"
    risk: float = 0.0       # caller's own risk estimate (poisoning guard)


@router.post("/realtime/sample")
def realtime_sample(req: RealtimeSampleRequest):
    """Push a labeled REAL sample (used by the legacy proxy and manual runs).

    Poisoning guard: a BENIGN label carrying risk >= 0.5 is a near-miss
    attack the caller was lucky to allow — training on it as benign makes
    the model forget the attack. Those go to the vulnerability queue for
    review instead of the training store.
    """
    from services import audit_log, realtime_learner

    text = req.effective_prompt()
    if req.label == 0:
        # Two poisoning guards for benign-labeled pushes:
        # 1) caller-reported risk says near-miss, or
        # 2) LABEL CONFLICT — our own live classifier rates the text as a
        #    likely attack (observed live: a caller's blind spot re-taught
        #    the model that a blocked attack was benign). Queue for review.
        conflict = False
        try:
            from guardrails.input_filter import classify as _classify

            conflict = _classify(text).intent_score >= 0.7
        except Exception:
            pass
        if req.risk >= 0.5 or conflict:
            audit_log.record_vulnerability(
                prompt_text=text, layer="label-conflict" if conflict else "proxy-nearmiss",
                risk=max(req.risk, 0.7 if conflict else req.risk), source="sampling")
            return {"status": "queued_for_review", "label": req.label,
                    "reason": "label_conflict" if conflict else "near_miss"}
    stored = realtime_learner.record(text=text, label=req.label,
                                     source=req.source or "external")
    return {"status": "recorded" if stored else "duplicate_ignored",
            "label": req.label}


class RealtimeBatchRequest(BaseModel):
    samples: list[dict] = Field(default_factory=list)  # [{prompt|text, label, source}]


@router.post("/realtime/samples")
def realtime_samples_batch(req: RealtimeBatchRequest):
    """Bulk import (dataset feeds): one transaction, deduped server-side."""
    from services import audit_log

    rows = [{"text": s.get("prompt") or s.get("text") or "",
             "label": int(s.get("label", 1)),
             "source": s.get("source") or "dataset",
             "scores": {}} for s in (req.samples or [])]
    result = audit_log.record_training_samples_batch(rows)
    return {"status": "ok", **result, "submitted": len(rows)}


@router.get("/realtime/stats")
def realtime_stats():
    from services import realtime_learner

    ready, reason = realtime_learner.ready_to_retrain()
    return {**realtime_learner.stats(), "ready_to_retrain": ready, "reason": reason}


@router.post("/admin/retrain-realtime")
def admin_retrain_realtime(force: bool = True):
    """Force a retrain on captured REAL traffic (no predefined set)."""
    from services import realtime_learner

    return realtime_learner.retrain_now(force=force)


@router.post("/admin/rollback-model")
def admin_rollback_model():
    from services import realtime_learner

    return realtime_learner.rollback_model()


# --------------------------------------------------------------------------- #
# Session persistence (trial-update: every session saved to the database)
# --------------------------------------------------------------------------- #
@router.get("/admin/sessions")
def admin_sessions(limit: int = 50, user_id: str | None = None):
    sessions = audit_log.list_sessions(limit)
    if user_id:
        sessions = [s for s in sessions if s.get("user_id") == user_id]
    return {"backend": audit_log.backend_name(), "count": len(sessions),
            "sessions": sessions}


# --------------------------------------------------------------------------- #
# Vulnerability -> retrain loop (trial-update: new input vulnerabilities
# update and train the model)
# --------------------------------------------------------------------------- #
class VulnerabilityReport(ChatCompletionRequest):
    layer: str = "manual"
    risk: float = 0.0


@router.get("/admin/vulnerabilities")
def admin_vulnerabilities(status: str = "pending", limit: int = 100):
    vulns = audit_log.list_vulnerabilities(status=status, limit=limit)
    return {"backend": audit_log.backend_name(), "count": len(vulns),
            "vulnerabilities": vulns}


@router.post("/admin/vulnerabilities")
def report_vulnerability(req: VulnerabilityReport):
    text = req.effective_prompt()
    if not text:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="prompt required")
    audit_log.record_vulnerability(prompt_text=text, layer=req.layer or "manual",
                                   risk=req.risk, source="manual")
    return {"status": "recorded", "pending": len(
        audit_log.list_vulnerabilities(status="pending", limit=1000))}


@router.post("/admin/retrain")
def admin_retrain(min_samples: int = 1):
    """Fold pending input vulnerabilities into the threat model (fast path:
    only the new samples are embedded — base corpus embeddings are cached)."""
    from fastapi import HTTPException

    vulns = audit_log.list_vulnerabilities(status="pending", limit=1000)
    rows = [(v.get("prompt_text", ""), 0) for v in vulns if v.get("prompt_text")]
    if len(rows) < min_samples:
        raise HTTPException(status_code=409,
                            detail=f"only {len(rows)} pending samples "
                                   f"(min_samples={min_samples})")
    try:
        from train.train_threat_model import retrain_with

        result = retrain_with(rows)
    except SystemExit as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    ids = [int(v["id"]) for v in vulns if v.get("id") is not None]
    audit_log.mark_vulnerabilities_trained(ids)
    # Best-effort: mirror the new attack vectors into the vector store for
    # similarity-based recall of known-bad prompts.
    try:
        from qdrant_client import models  # type: ignore

        from services import qdrant_client
        from services.embedding_service import EMBED_DIM, embed_batch

        client = qdrant_client.get_client()
        if client is not None:
            if not client.collection_exists("blocked_prompts"):
                client.create_collection(
                    collection_name="blocked_prompts",
                    vectors_config=models.VectorParams(
                        size=EMBED_DIM, distance=models.Distance.COSINE),
                )
            vectors = embed_batch([t for t, _ in rows])
            client.upsert(
                collection_name="blocked_prompts",
                points=[models.PointStruct(
                    id=i, vector=v.tolist(),
                    payload={"text": t, "kind": "vulnerability"})
                    for i, (v, (t, _)) in enumerate(zip(vectors, rows))],
            )
    except Exception:
        pass
    return {"status": "retrained", "trained_samples": len(rows), **result}


@router.get("/session/risk/{user_id}")
def session_risk(user_id: str):
    return behavioral.peek(user_id).model_dump()


@router.delete("/session/risk/{user_id}")
def reset_session(user_id: str, session_key: str | None = None):
    behavioral.reset(user_id)
    try:
        # Align the durable record with the termination (block alignment).
        sessions = audit_log.list_sessions(limit=200)
        for s in sessions:
            if s.get("session_key") in {session_key, f"user:{user_id}"} or \
                    (s.get("user_id") == user_id and s.get("status") == "active"):
                audit_log.upsert_session(
                    session_key=s["session_key"], user_id=user_id,
                    turns=int(s.get("turns") or 0),
                    risk=float(s.get("last_risk") or 0.0),
                    sentiment_avg=float(s.get("sentiment_avg") or 0.0),
                    status="terminated",
                )
    except Exception:
        pass
    return {"status": "reset", "user_id": user_id}


# --------------------------------------------------------------------------- #
# Trial-update #1: live word-injection scoring for display DURING input.
# Pure-lexicon (no embedding/model) so the site can call it on every
# debounced keystroke and render term-level polarity + prompt weightage.
# --------------------------------------------------------------------------- #
class SentimentScoreRequest(ChatCompletionRequest):
    pass


@router.post("/sentiment/score")
def sentiment_score(req: SentimentScoreRequest):
    """Word + sentence weightage for any prompt. Pure lexicon — no model,
    no embedding, no network: sub-millisecond server-side; `latency_ms`
    is included so the UI can prove it."""
    import time as _time

    from services.policy_engine import word_sentiment

    t0 = _time.perf_counter()
    text = req.effective_prompt() or ""
    result = word_sentiment(text)
    result["latency_ms"] = round(1000 * (_time.perf_counter() - t0), 3)
    return result
