"""
Policy & Rules Engine (diagram: "POLICY & RULES ENGINE — regex, PII rules,
deny lists, allowed topics, toxicity thresholds, data leak patterns").

One shared rule-set consumed by three layers:
  L1 Sanitization  -> scrub_pii / jailbreak patterns / deobfuscation
  L4 RAG validator -> imperative-injection patterns in retrieved docs
  L7 Output filter -> toxicity lexicon / PII leaks / data-leak signatures
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# PII patterns (scrubbed from prompts in L1; detected in responses by L7)
# --------------------------------------------------------------------------- #
PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3}\)?[\s-]?)\d{3}[\s-]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

PII_MASK = "[REDACTED]"

# --------------------------------------------------------------------------- #
# Jailbreak / injection patterns (L1 scrub + L4 doc scan)
# --------------------------------------------------------------------------- #
JAILBREAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b", re.I),
    re.compile(r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior)\b", re.I),
    re.compile(r"\bforget\s+(?:all\s+)?(?:your|prior|previous)\s+(?:instructions|rules)\b", re.I),
    re.compile(r"\boverride\s+(?:your\s+)?(?:current\s+)?instructions\b", re.I),
    re.compile(r"\bsystem\s*:\s*", re.I),
    re.compile(r"\byou\s+are\s+now\s+(?:DAN|AIM|developer\s+mode)\b", re.I),
    re.compile(r"\bdeveloper\s+mode\s+(?:enabled|on)\b", re.I),
    re.compile(r"\b(?:reveal|show|print|dump|output)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions|secret)\b", re.I),
]

# Imperative commands that should never appear in passive reference data
# (PDF §2.2 check #2 — "Ignore", "Output this" in retrieved chunks).
IMPERATIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\b", re.I),
    re.compile(r"\bdisregard\b.{0,30}\b(?:instruction|rule|prompt)\b", re.I),
    re.compile(r"\b(?:output|print|reveal|exfiltrate|send)\s+(?:this|the|all)\b.{0,30}\b(?:key|secret|prompt|credential|token)\b", re.I),
    re.compile(r"\bnew\s+instructions?\s*:", re.I),
    re.compile(r"\bfrom\s+now\s+on[,\s]+(?:you\s+must|ignore)\b", re.I),
]

# --------------------------------------------------------------------------- #
# Data-leak signatures in outbound text (L7 + L4): credential shapes
# --------------------------------------------------------------------------- #
LEAK_PATTERNS: dict[str, re.Pattern] = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    "bearer": re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b"),
}

# --------------------------------------------------------------------------- #
# Toxicity lexicon (L7) — weighted terms; score = saturating weighted sum
# --------------------------------------------------------------------------- #
TOXICITY_LEXICON: dict[str, float] = {
    "idiot": 0.3, "stupid": 0.3, "moron": 0.4, "imbecile": 0.4,
    "hate you": 0.4, "kill yourself": 1.0, "kys": 0.9,
    "worthless trash": 0.8, "subhuman": 0.8,
    "bomb": 0.6, "explosive": 0.5, "malware": 0.5, "ransomware": 0.6,
    "credit card dump": 0.9, "heroin": 0.6, "meth lab": 0.8,
}

DENIED_TOPICS: list[str] = [
    "weapons of mass destruction",
    "child exploitation",
    "credit card fraud",
    "identity theft tutorial",
]

ALLOWED_TOPICS: list[str] = []  # empty = allow-all (deny list governs)


def scrub_pii(text: str) -> tuple[str, list[str]]:
    """Mask every PII hit; returns (clean_text, kinds_found)."""
    found: list[str] = []
    clean = text
    for kind, pat in PII_PATTERNS.items():
        if pat.search(clean):
            found.append(kind)
            clean = pat.sub(PII_MASK, clean)
    return clean, found


def deobfuscate(text: str) -> str:
    """Normalize common evasions (leetspeak digits, zero-width, spacing)."""
    table = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                           "7": "t", "@": "a", "$": "s"})
    squashed = re.sub(r"([a-z])\1{2,}", r"\1", text)          # 1gn0ooooore -> 1gnore
    lowered = squashed.lower()
    translated = lowered.translate(table)
    # Rejoin split words: "i g n o r e" / "ig nore"
    if re.search(r"\b(?:[a-z] ){3,}[a-z]\b", translated):
        translated = re.sub(r"(?<=[a-z]) (?=[a-z](?: |$))", "", translated)
    return translated


def jailbreak_hits(text: str) -> list[str]:
    """Which jailbreak patterns fire on `text` (checked on deobfuscated form)."""
    probe = f"{deobfuscate(text)}\n{text}"
    return [p.pattern for p in JAILBREAK_PATTERNS if p.search(probe)]


def imperative_hits(text: str) -> list[str]:
    return [p.pattern for p in IMPERATIVE_PATTERNS if p.search(text)]


def leak_hits(text: str) -> dict[str, str]:
    """credential-shape matches: {kind: first matched snippet}."""
    out: dict[str, str] = {}
    for kind, pat in LEAK_PATTERNS.items():
        m = pat.search(text)
        if m:
            out[kind] = m.group(0)[:24] + "…"
    return out


def toxicity_score(text: str) -> float:
    """Saturating weighted lexicon score in [0,1]."""
    low = deobfuscate(text)
    total = 0.0
    for term, weight in TOXICITY_LEXICON.items():
        occurrences = low.count(term)
        if occurrences:
            total += weight * min(occurrences, 3)
    return min(total, 1.0)


def denied_topic_hits(text: str) -> list[str]:
    low = text.lower()
    return [t for t in DENIED_TOPICS if t in low]


def allowed_topic_check(text: str) -> bool:
    """True when the allow-list is empty (default) or text matches it."""
    if not ALLOWED_TOPICS:
        return True
    low = text.lower()
    return any(t in low for t in ALLOWED_TOPICS)
