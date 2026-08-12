"""
Component 5 — AI/LLM Context Enrichment (PRD §18-20).

The LLM does NOT decide access. It analyzes contextual signals and extracts
additional security features that feed into the threat determination model.

Example: "Export all customer records" → { operation=BULK_EXPORT, exfiltration_risk=0.9 }

Uses our existing GLM connection. Disabled by default (BEHAVIORAL_LLM_CONTEXT=false)
to avoid adding latency. When disabled, returns empty enrichment.
"""
from __future__ import annotations
import os
import json
import urllib.request


def enabled() -> bool:
    return os.getenv("BEHAVIORAL_LLM_CONTEXT", "false").lower() == "true"


def enrich(telemetry_dict: dict) -> dict:
    """Analyze the request context via LLM and extract security signals.

    Returns { context_score: float (0..1), signals: dict, reason: str }.
    Never throws — on failure returns empty enrichment.
    """
    if not enabled():
        return {"context_score": 0.0, "signals": {}, "enabled": False}

    api_key = os.getenv("LLM_API_KEY", "")
    base_url = os.getenv("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
    model = os.getenv("LLM_MODEL", "glm-4.5-flash")

    if not api_key:
        return {"context_score": 0.0, "signals": {}, "enabled": True, "error": "no API key"}

    prompt = _build_prompt(telemetry_dict)
    try:
        data = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 200,
        }).encode()

        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=data,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        return _parse_response(content)
    except Exception as exc:
        return {"context_score": 0.0, "signals": {}, "enabled": True, "error": str(exc)[:80]}


_SYSTEM_PROMPT = (
    "You are a security context analyzer. Analyze the user activity context and return "
    "ONLY a JSON object with these fields:\n"
    '{"context_score": <0..1 risk multiplier>, "operation_type": "<classify the action>", '
    '"potential_exfiltration": <true/false>, "unusual_pattern": <true/false>, "reason": "<brief>"}\n'
    "Higher context_score = more suspicious. Respond with ONLY the JSON."
)


def _build_prompt(d: dict) -> str:
    return (
        f"User: {d.get('user_id','?')} (role={d.get('role','?')})\n"
        f"Device: {'registered' if d.get('registered_device') else 'NEW'}, trust={d.get('device_trust',0)}\n"
        f"Location: {d.get('country','?')}/{d.get('region','?')} (change={d.get('location_change',False)})\n"
        f"Time: hour={d.get('hour',0)} working_hours={d.get('working_hours',True)}\n"
        f"Resource: {d.get('resource_type','?')} sensitivity={d.get('resource_sensitivity','low')}\n"
        f"Activity: {d.get('request_frequency',0)} req/hr, {d.get('failed_auth_count',0)} failed auths\n"
        f"Prompt: {d.get('prompt_text','(none)')}"
    )


def _parse_response(content: str) -> dict:
    try:
        obj = json.loads(content)
        return {
            "context_score": float(obj.get("context_score", 0.0)),
            "signals": obj,
            "enabled": True,
        }
    except Exception:
        return {"context_score": 0.0, "signals": {}, "enabled": True, "error": "parse failed"}
