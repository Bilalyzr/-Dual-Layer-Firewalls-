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


@router.get("/session/risk/{user_id}")
def session_risk(user_id: str):
    return behavioral.peek(user_id).model_dump()


@router.delete("/session/risk/{user_id}")
def reset_session(user_id: str):
    behavioral.reset(user_id)
    return {"status": "reset", "user_id": user_id}
