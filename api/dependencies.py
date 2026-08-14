"""
Dependency injection surface (diagram: "Dependency Injection:
execute_firewall_pipeline()"; PDF §4.2 api/dependencies.py).

The route resolves this dependency, so the pipeline can be swapped/mocked in
tests without touching transport code.
"""
from __future__ import annotations

from fastapi import Depends, Header

from core.pipeline import PipelineOutcome, execute_firewall_pipeline
from core.rate_limiter import allow
from core.security import require_api_key
from models.schemas import ChatCompletionRequest


def firewall_pipeline(
    req: ChatCompletionRequest,
    _: None = Depends(require_api_key),
    x_user_id: str | None = Header(default=None),
    x_session_id: str | None = Header(default=None),
    x_client_ip: str | None = Header(default=None),
) -> PipelineOutcome:
    """Bind headers (diagram: X-User-Id / X-Session-Id) + rate limit, then run."""
    if x_user_id and req.user_id in ("", "anon"):
        req.user_id = x_user_id
    if x_session_id and not req.session_id:
        req.session_id = x_session_id
    if not allow(req.user_id):
        import os
        import time

        from models.schemas import BlockedResponse
        from services import audit_log, metrics

        request_id = f"fw-{os.urandom(6).hex()}"
        metrics.inc_requests("block")
        body = BlockedResponse(
            error="Rate limit exceeded", reason="rate limit",
            request_id=request_id, latency_ms=0.0,
        ).model_dump()
        try:
            audit_log.record(
                request_id=request_id, user_id=req.user_id, session_id=req.session_id,
                decision="block", risk_score=0.0, reason="rate limit",
                layers={}, client_ip=x_client_ip or "",
            )
        except Exception:
            pass
        return PipelineOutcome(blocked=True, status_code=429, body=body)
    return execute_firewall_pipeline(req, client_ip=x_client_ip or "")
