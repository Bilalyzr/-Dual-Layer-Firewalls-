"""
LAYER 7 — EGRESS OUTPUT GUARDRAIL (diagram: "Output Filter — check response
for toxicity, PII leakage, policy violations"; PDF §2.1 Output Guardrails).

  llm_response -> filtered_response (str), safe (bool)

Additive to the proxy-side regex checks (`proxy/firewall/outputCheck.js`):
this one is semantic-aware (toxicity lexicon over the deobfuscated form) and
applies the shared Policy Engine to the model's own words. Fails open — a
broken filter must never void a valid answer; it flags instead.
"""
from __future__ import annotations

from core.config import SETTINGS
from models.schemas import OutputFilterResult
from services import policy_engine


def filter_response(llm_response: str) -> OutputFilterResult:
    if not SETTINGS.output_filter_enabled or not llm_response:
        return OutputFilterResult(filtered_response=llm_response)

    text = llm_response
    violations: list[str] = []

    # 1) Toxicity (Policy Engine lexicon, deobfuscated match).
    tox = policy_engine.toxicity_score(text)
    if tox > 0:
        violations.append(f"toxicity={tox:.2f}")

    # 2) PII leakage — mask anything the model should not echo.
    clean, pii_kinds = policy_engine.scrub_pii(text)
    pii_leak = bool(pii_kinds)
    if pii_leak:
        violations.append(f"pii:{','.join(pii_kinds)}")
    text = clean

    # 3) Credential / secret leakage (sk-…, AKIA…, BEGIN PRIVATE KEY, JWTs…).
    leaks = policy_engine.leak_hits(text)
    if leaks:
        violations.append(f"leak:{','.join(leaks.keys())}")
        for pat in policy_engine.LEAK_PATTERNS.values():
            text = pat.sub("[REDACTED-SECRET]", text)

    # 4) Denied-topic violations in the generated text.
    denied = policy_engine.denied_topic_hits(text)
    if denied:
        violations.append(f"denied-topic:{','.join(denied)}")

    unsafe = tox >= SETTINGS.output_block_threshold or bool(denied)
    if unsafe:
        text = ("[Response filtered by firewall egress guardrail: "
                f"{'; '.join(violations)}]")

    return OutputFilterResult(
        filtered_response=text,
        safe=not unsafe,
        toxicity_score=round(tox, 4),
        pii_leak=pii_leak,
        policy_violations=violations,
    )
