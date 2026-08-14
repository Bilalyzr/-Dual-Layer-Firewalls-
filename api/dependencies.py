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
        from models.schemas import BlockedResponse

        return PipelineOutcome(
            blocked=True, status_code=429,
            body=BlockedResponse(error="Rate limit exceeded",
                                 reason="rate limit").model_dump(),
        )
    return execute_firewall_pipeline(req, client_ip=x_client_ip or "")
