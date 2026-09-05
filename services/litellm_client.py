"""
Upstream LLM execution via the LiteLLM router (diagram Layer 6; PDF §4
"LiteLLM provides a single, unified API to route to 100+ LLM providers").

When no provider credential is configured the client degrades to a
deterministic offline responder ("safe guidelines" answer built from the RAG
context) so the 7-layer pipeline is fully exercisable without network access.
"""
from __future__ import annotations

import time

from core.config import SETTINGS

_STATUS: dict = {"mode": "idle", "model": "", "detail": ""}

# Circuit breaker for the primary provider (mirrors proxy/llm/client.js).
# When the primary endpoint hangs, every request burns the full timeout
# before the local fallback starts. After _BREAKER_THRESHOLD consecutive
# failures we skip the primary for _BREAKER_COOLDOWN_S; the next request
# after the cooldown re-probes it (half-open).
_BREAKER = {"fails": 0, "open_until": 0.0}
_BREAKER_THRESHOLD = 2
_BREAKER_COOLDOWN_S = 120.0


def status() -> dict:
    return dict(_STATUS)


def complete(prompt: str, rag_docs: list[str] | None = None, model: str | None = None) -> str:
    """Route `prompt` (+safe RAG context) to the best provider; return text."""
    chosen = model or SETTINGS.llm_model or SETTINGS.default_llm_model
    # GLM (or any OpenAI-compatible provider) as PRIMARY — same LLM_* env the
    # proxy uses. Falls through to local Ollama, then the offline responder.
    primary_base = SETTINGS.llm_base_url if not model else None
    primary_kwargs = {}
    if primary_base and SETTINGS.llm_api_key:
        primary_kwargs = {
            "model": f"openai/{chosen}",
            "api_base": primary_base,
            "api_key": SETTINGS.llm_api_key,
        }
    else:
        primary_kwargs = {"model": chosen}
    context_block = ""
    if rag_docs:
        joined = "\n\n".join(f"[{i + 1}] {d}" for i, d in enumerate(rag_docs[:3]))
        context_block = f"Reference context (verified safe by firewall):\n{joined}\n\n"

    breaker_open = time.time() < _BREAKER["open_until"]
    if breaker_open and primary_base and not model:
        # Primary is known-dead right now — go straight to the local fallback.
        _STATUS.update(mode="skipped-primary", model=chosen,
                       detail="circuit open — primary skipped")
        return _fallback_or_offline(prompt, context_block, chosen)

    try:
        import litellm  # type: ignore

        answer = litellm.completion(
            **primary_kwargs,
            messages=[
                {"role": "system", "content":
                    "You are a helpful assistant. Answer using the provided reference "
                    "context when available. Follow all safety guidelines."},
                {"role": "user", "content": f"{context_block}{prompt}"},
            ],
            timeout=SETTINGS.llm_timeout_s,
            num_retries=0,  # one shot — a slow/dead provider hands off to the local fallback immediately
        )
        _STATUS.update(mode="litellm", model=chosen, detail="ok")
        _BREAKER.update(fails=0, open_until=0.0)
        return answer.choices[0].message.content or ""
    except Exception as exc:
        _BREAKER["fails"] += 1
        if _BREAKER["fails"] >= _BREAKER_THRESHOLD:
            _BREAKER.update(fails=0, open_until=time.time() + _BREAKER_COOLDOWN_S)
        return _fallback_or_offline(prompt, context_block, chosen, primary_exc=exc)


def _fallback_or_offline(prompt: str, context_block: str, chosen: str,
                         primary_exc: Exception | None = None) -> str:
    """Local fallback provider (e.g. Ollama); offline responder as last hop."""
    messages = [
        {"role": "system", "content":
            "You are a helpful assistant. Answer using the provided reference "
            "context when available. Follow all safety guidelines."},
        {"role": "user", "content": f"{context_block}{prompt}"},
    ]
    if SETTINGS.llm_fallback_url:
        try:
            import litellm  # type: ignore

            fb = litellm.completion(
                model=f"openai/{SETTINGS.llm_fallback_model}",
                api_base=SETTINGS.llm_fallback_url,
                api_key="ollama",
                messages=messages,
                timeout=SETTINGS.llm_fallback_timeout_s,
                num_retries=0,
            )
            detail = (f"primary failed: {type(primary_exc).__name__}"
                      if primary_exc else "primary skipped (circuit open)")
            _STATUS.update(mode="local-fallback", model=SETTINGS.llm_fallback_model,
                           detail=detail)
            return fb.choices[0].message.content or ""
        except Exception:
            pass
    if SETTINGS.llm_offline_echo:
        _STATUS.update(mode="offline-echo", model=chosen,
                       detail=f"{type(primary_exc).__name__}: {primary_exc}"
                       if primary_exc else "primary skipped (circuit open)")
        return _offline_responder(prompt, None)
    raise


def _offline_responder(prompt: str, rag_docs: list[str] | None) -> str:
    """Deterministic stand-in mirroring the diagram's 200-OK sample answer."""
    lines = ["Here are safe guidelines to address your question."]
    if rag_docs:
        lines.append("")
        lines.append("Based on verified reference context:")
        for d in rag_docs[:3]:
            first = d.strip().split(".")[0][:160]
            lines.append(f"- {first}.")
    lines.append("")
    lines.append(f'Your request ("{prompt[:120]}") was processed through the '
                 "7-layer GenAI security firewall. No provider credentials are "
                 "configured, so this is the offline deterministic responder.")
    return "\n".join(lines)
