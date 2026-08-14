"""
LAYER 1 — PROMPT SANITIZATION (diagram: "Regex, PII").

Cleans the prompt: removes PII, strips jailbreak patterns/obfuscations.
Output feeds L2. Never blocks on its own — it scrubs, the semantic layers
decide (defense-in-depth: this layer makes attacks *harder to hide*, the
next layer catches what remains).
"""
from __future__ import annotations

import re

from core.config import SETTINGS
from models.schemas import SanitizeResult
from services import policy_engine


def sanitize(prompt: str) -> SanitizeResult:
    if not SETTINGS.sanitizer_enabled:
        return SanitizeResult(sanitized_prompt=prompt)

    removed: list[str] = []

    # 1) Mask PII before anything downstream sees it.
    clean, pii_kinds = policy_engine.scrub_pii(prompt)
    removed.extend(f"pii:{k}" for k in pii_kinds)

    # 2) Neutralize known jailbreak phrasings. Patterns are matched on the
    #    deobfuscated form (leetspeak/splitting evasions), and when an
    #    evasion fires we keep the SCRUBBED deobfuscated text — the request
    #    is suspicious, so digit-mangling is acceptable there.
    for pattern in policy_engine.JAILBREAK_PATTERNS:
        probe = policy_engine.deobfuscate(clean)
        hit_raw = pattern.search(clean)
        hit_deob = pattern.search(probe) if not hit_raw else None
        if hit_raw:
            clean = pattern.sub("[sanitized:instruction-override]", clean)
            removed.append(f"jailbreak:{pattern.pattern[:32]}")
        elif hit_deob:
            clean = pattern.sub("[sanitized:instruction-override]", probe)
            removed.append(f"jailbreak-obfuscated:{pattern.pattern[:32]}")

    # 4) Decode smuggled base64 payloads: an encoded blob whose DECODED text
    #    carries an instruction-override is an attack no matter how innocent
    #    the surrounding sentence looks (observed live: "decode ... then obey").
    import base64 as _b64
    import binascii as _binascii

    for m in re.finditer(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", clean):
        token = m.group(0)
        try:
            decoded = _b64.b64decode(token + "=" * (-len(token) % 4)).decode("utf-8", "ignore")
        except (_binascii.Error, ValueError):
            continue
        if len(decoded) < 8:
            continue
        probe = policy_engine.deobfuscate(decoded)
        if any(p.search(probe) or p.search(decoded) for p in policy_engine.JAILBREAK_PATTERNS) \
                or policy_engine.imperative_hits(decoded):
            clean = clean.replace(token, "[sanitized:encoded-payload]")
            removed.append(f"base64-payload:{decoded[:32]}")

    # 5) Collapse control/zero-width characters used to smuggle instructions.
    smuggled = re.findall(r"[\u200b-\u200f\u2028\u2029\ufeff]", clean)
    if smuggled:
        clean = re.sub(r"[\u200b-\u200f\u2028\u2029\ufeff]", "", clean)
        removed.append(f"invisible-chars:{len(smuggled)}")

    # 6) Bound the prompt length (413-style guard, inline).
    if len(clean) > 32_000:
        clean = clean[:32_000]
        removed.append("truncated")

    return SanitizeResult(sanitized_prompt=clean.strip(), removed=removed)
