"""
Upstream LLM execution via the LiteLLM router (diagram Layer 6; PDF §4
"LiteLLM provides a single, unified API to route to 100+ LLM providers").

When no provider credential is configured the client degrades to a
deterministic offline responder ("safe guidelines" answer built from the RAG
context) so the 7-layer pipeline is fully exercisable without network access.
"""
from __future__ import annotations

from core.config import SETTINGS

_STATUS: dict = {"mode": "idle", "model": "", "detail": ""}


def status() -> dict:
    return dict(_STATUS)


def complete(prompt: str, rag_docs: list[str] | None = None, model: str | None = None) -> str:
    """Route `prompt` (+safe RAG context) to the best provider; return text."""
    chosen = model or SETTINGS.default_llm_model
    context_block = ""
    if rag_docs:
        joined = "\n\n".join(f"[{i+1}] {d}" for i, d in enumerate(rag_docs[:3]))
        context_block = f"Reference context (verified safe by firewall):\n{joined}\n\n"
    try:
        import litellm  # type: ignore

        answer = litellm.completion(
            model=chosen,
            messages=[
                {"role": "system", "content":
                    "You are a helpful assistant. Answer using the provided reference "
                    "context when available. Follow all safety guidelines."},
                {"role": "user", "content": f"{context_block}{prompt}"},
            ],
            timeout=SETTINGS.llm_timeout_s,
        )
        _STATUS.update(mode="litellm", model=chosen, detail="ok")
        return answer.choices[0].message.content or ""
    except Exception as exc:
        # Local fallback provider (e.g. Ollama) — rides through primary-provider
        # outages/rate-limits before the offline responder is used.
        if SETTINGS.llm_fallback_url:
            try:
                import litellm  # type: ignore

                fb = litellm.completion(
                    model=f"openai/{SETTINGS.llm_fallback_model}",
                    api_base=SETTINGS.llm_fallback_url,
                    api_key="ollama",
                    messages=[
                        {"role": "system", "content":
                            "You are a helpful assistant. Answer using the provided reference "
                            "context when available. Follow all safety guidelines."},
                        {"role": "user", "content": f"{context_block}{prompt}"},
                    ],
                    timeout=SETTINGS.llm_fallback_timeout_s,
                )
                _STATUS.update(mode="local-fallback", model=SETTINGS.llm_fallback_model,
                               detail=f"primary failed: {type(exc).__name__}")
                return fb.choices[0].message.content or ""
            except Exception:
                pass
        if SETTINGS.llm_offline_echo:
            _STATUS.update(mode="offline-echo", model=chosen,
                           detail=f"{type(exc).__name__}: {exc}")
            return _offline_responder(prompt, rag_docs)
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
