"""
Pydantic schemas — the exact wire contracts from the architecture diagram.

Request (diagram "INPUT / Request Body"):
    {"model": "gpt-4o", "prompt": "...", "user_id": "user_123",
     "session_id": "sess_abc", "context": {}}
OpenAI-style `messages` is also accepted; the last user turn becomes `prompt`.

Success 200 (diagram "OUTPUT / Success"):
    {"response": "...", "model": "gpt-4o",
     "guardrails": {"status": "passed", "risk_score": 0.12}}

Blocked 403 (diagram "OUTPUT / Blocked"):
    {"error": "Request blocked by firewall", "reason": "cumulative risk exceeded"}
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Inbound
# --------------------------------------------------------------------------- #
class ChatCompletionRequest(BaseModel):
    model: str | None = None
    prompt: str | None = None
    messages: list[dict[str, Any]] | None = None
    user_id: str = "anon"
    session_id: str = ""
    context: dict[str, Any] = Field(default_factory=dict)

    def effective_prompt(self) -> str:
        """`prompt` wins; else last user message from OpenAI-style messages."""
        if self.prompt and self.prompt.strip():
            return self.prompt.strip()
        for m in reversed(self.messages or []):
            role = str(m.get("role", "")).lower()
            content = m.get("content", "")
            if role == "user" and isinstance(content, str) and content.strip():
                return content.strip()
        return ""


# --------------------------------------------------------------------------- #
# Outbound
# --------------------------------------------------------------------------- #
class GuardrailStatus(BaseModel):
    status: str = "passed"          # passed | filtered
    risk_score: float = 0.0
    layers: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0


class ChatCompletionResponse(BaseModel):
    response: str
    model: str
    guardrails: GuardrailStatus = Field(default_factory=GuardrailStatus)


class BlockedResponse(BaseModel):
    error: str = "Request blocked by firewall"
    reason: str = "cumulative risk exceeded"
    risk_score: float = 0.0


# --------------------------------------------------------------------------- #
# Internal per-layer results (pipeline bus)
# --------------------------------------------------------------------------- #
class SanitizeResult(BaseModel):
    sanitized_prompt: str
    removed: list[str] = Field(default_factory=list)  # PII/jailbreak patterns scrubbed


class IntentResult(BaseModel):
    intent_score: float = 0.0        # P(threat) from the XGBoost head
    embedding_vector: list[float] = Field(default_factory=list)
    model_used: str = "none"         # semantic | fallback-hash | none
    degraded: bool = False


class SessionRiskResult(BaseModel):
    cumulative_risk: float = 0.0
    drift: float = 0.0               # cosine distance from session baseline
    turn_count: int = 0
    attack_proximity: float = 0.0    # cosine sim to the known-attack centroid
    blocked: bool = False


class RagValidationResult(BaseModel):
    safe_rag_docs: list[str] = Field(default_factory=list)
    dropped_docs: list[str] = Field(default_factory=list)
    imperative_flags: list[str] = Field(default_factory=list)
    risk: float = 0.0


class OutputFilterResult(BaseModel):
    filtered_response: str = ""
    safe: bool = True
    toxicity_score: float = 0.0
    pii_leak: bool = False
    policy_violations: list[str] = Field(default_factory=list)
