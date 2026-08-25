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
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|constraints?|directions?|prompts?)\b", re.I),
    re.compile(r"\b(?:ignore|disregard|forget|bypass)\s+(?:all|any|every)\s+(?:rules?|instructions?|constraints?|safety|guidelines?|restrictions?|filters?|guardrails?)\b", re.I),
    re.compile(r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior)\b", re.I),
    re.compile(r"\bforget\s+(?:all\s+)?(?:your|prior|previous)\s+(?:instructions|rules)\b", re.I),
    re.compile(r"\boverride\s+(?:your\s+)?(?:current\s+)?instructions\b", re.I),
    re.compile(r"\bsystem\s*:\s*", re.I),
    re.compile(r"\byou\s+are\s+now\s+(?:dan|aim|badbot|evil[^\s,]*|unrestricted[^\s,]*|developer\s+mode|debug\s+mode)\b", re.I),
    re.compile(r"\bdeveloper\s+mode\s+(?:enabled|on)\b", re.I),
    re.compile(r"\b(?:reveal|show|print|dump|output|append|include|exfiltrate|export|send|leak)\b"
               r"[^.]{0,50}\b(?:api\s+keys?|secrets?|credentials?|tokens?|system\s+prompt|seed\s+phrase|passphrase)\b", re.I),
    re.compile(r"\bactivation\s+code\b", re.I),
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

# --------------------------------------------------------------------------- #
# Word-injection lexicon (trial-update #1): per-term polarity weights.
# Negative  = attack/injection vocabulary ("trojanhorse", "crack", "toolkit")
# Positive  = benign relation vocabulary ("classmate", "study", "protect")
# The prompt weightage = (neg_total - pos_total) normalized; the aggregate
# average = net / matched-term count. Phrases are matched before single words.
# --------------------------------------------------------------------------- #
INJECTION_LEXICON: dict[str, float] = {
    # very strong attack vocabulary
    "trojanhorse": 0.95, "trojan horse": 0.95, "ransomware": 0.95,
    "keylogger": 0.95, "rootkit": 0.95, "botnet": 0.95, "backdoor": 0.95,
    "spyware": 0.9, "exploit kit": 0.95, "credential stuffing": 0.95,
    # strong
    "trojan": 0.85, "malware": 0.85, "virus": 0.8, "worm": 0.8,
    "phishing": 0.85, "ddos": 0.85, "brute force": 0.85, "crack": 0.75,
    "hacking": 0.8, "hack into": 0.85, "bypass security": 0.85,
    "steal credentials": 0.95, "exfiltrate": 0.85, "payload": 0.8,
    "weaponize": 0.9, "zero-day": 0.8, "sql injection": 0.85,
    "privilege escalation": 0.8, "keylog": 0.9, "sniffing": 0.65,
    # medium
    "attack": 0.7, "toolkit": 0.55, "exploit": 0.65, "inject": 0.6,
    "malicious": 0.7, "breach": 0.6, "spoof": 0.6, "decrypt": 0.5,
    "dark web": 0.6, "unauthorized": 0.55, "vulnerable": 0.45,
    "unrestricted": 0.5, "debug mode": 0.5, "spy": 0.55,
    "seed phrase": 0.85, "passphrase": 0.7, "recovery phrase": 0.85,
    # mild (context words that lean hostile in intent statements)
    "plan": 0.2, "target": 0.35, "victim": 0.45, "illegal": 0.5,
}

BENIGN_LEXICON: dict[str, float] = {
    # strong benign/relation vocabulary
    "classmate": 0.7, "classmates": 0.7, "friend": 0.7, "friends": 0.7,
    "colleague": 0.7, "teammate": 0.7, "protect": 0.7, "defend": 0.7,
    "safeguard": 0.7, "ethical": 0.65, "authorized": 0.65,
    # medium
    "learn": 0.5, "study": 0.5, "understand": 0.5, "homework": 0.5,
    "assignment": 0.5, "project": 0.45, "research": 0.5, "teacher": 0.5,
    "school": 0.5, "university": 0.5, "prevent": 0.5, "security awareness": 0.55,
    "defend against": 0.6, "protect against": 0.6, "mitigation": 0.5,
    # mild
    "help": 0.3, "share": 0.3, "discuss": 0.3, "review": 0.3,
    "practice": 0.3, "safe": 0.35, "guide": 0.3, "legal": 0.35,
}

# Saturation point: a net attack weight at/above this -> weightage 1.0.
INJECTION_SATURATION = 2.5

# ---- precompiled matchers (built once at import; the scorer is pure-CPU) --- #
import re as _re  # noqa: E402  (module-level precompile below)

_PHRASES_FIRST: list[str] = sorted(
    [k for k in list(INJECTION_LEXICON) + list(BENIGN_LEXICON) if " " in k],
    key=len, reverse=True,
)
_PHRASE_RES = [(t, _re.compile(_re.escape(t))) for t in _PHRASES_FIRST]
_WORD_RE = _re.compile(r"[a-z]{3,}")
_SENT_SPLIT = _re.compile(r"[.!?;\n]+")
_ALL_LEX = {**INJECTION_LEXICON, **BENIGN_LEXICON}

# Safety caps so pathological inputs can never stall the scorer.
_MAX_TEXT_CHARS = 16_000
_MAX_SENTENCES = 40


def _match_terms(low: str) -> tuple[list[dict], list[dict]]:
    """Match lexicon phrases (longest first) then single words, no double count.

    Claimed character positions live in a bytearray mask — overlap checks and
    marking run at C speed, so even a 16KB prompt full of hits stays O(n).
    """
    claimed = bytearray(len(low))
    negative: list[dict] = []
    positive: list[dict] = []

    def _claim(start: int, end: int) -> bool:
        if any(claimed[start:end]):
            return False
        claimed[start:end] = b"\x01" * (end - start)
        return True

    for term, rx in _PHRASE_RES:
        for m in rx.finditer(low):
            if _claim(m.start(), m.end()):
                if term in INJECTION_LEXICON:
                    negative.append({"term": term, "weight": INJECTION_LEXICON[term]})
                else:
                    positive.append({"term": term, "weight": BENIGN_LEXICON[term]})
    for m in _WORD_RE.finditer(low):
        w = m.group(0)
        weight = _ALL_LEX.get(w)
        if weight is not None and _claim(m.start(), m.end()):
            bucket = negative if w in INJECTION_LEXICON else positive
            bucket.append({"term": w, "weight": weight})
    return negative, positive


def _score_terms(negative: list[dict], positive: list[dict]) -> dict:
    neg_total = sum(t["weight"] for t in negative)
    pos_total = sum(t["weight"] for t in positive)
    net = neg_total - pos_total
    matched = len(negative) + len(positive)
    return {
        "negative_total": round(neg_total, 4),
        "positive_total": round(pos_total, 4),
        "weightage": round(min(1.0, max(0.0, net) / INJECTION_SATURATION), 4),
        "average_score": round(net / matched, 4) if matched else 0.0,
        "matched_terms": matched,
    }


def word_sentiment(text: str) -> dict:
    """Word + sentence weightage for ANY prompt (trial-update #1, speed-first).

    Pure lexicon — no model, no network, no embedding: sub-millisecond on
    typical prompts. Returns per-term matches, per-sentence breakdown,
    whole-prompt weightage and the aggregate average term score.
    """
    if not text or not text.strip():
        return {**_score_terms([], []),
                "negative_terms": [], "positive_terms": [],
                "sentence_count": 0, "sentence_weightage": 0.0, "sentences": []}
    if len(text) > _MAX_TEXT_CHARS:
        text = text[:_MAX_TEXT_CHARS]

    low = deobfuscate(text)
    negative, positive = _match_terms(low)
    overall = _score_terms(negative, positive)

    # ---- sentence-level weightage (worst sentence drives the risk) -------- #
    sentences: list[dict] = []
    for chunk in _SENT_SPLIT.split(text)[:_MAX_SENTENCES]:
        if not chunk.strip():
            continue
        c_low = deobfuscate(chunk)
        n, p = _match_terms(c_low)
        s = _score_terms(n, p)
        if s["matched_terms"]:
            sentences.append({
                "text": chunk.strip()[:120],
                "negative_total": s["negative_total"],
                "positive_total": s["positive_total"],
                "weightage": s["weightage"],
                "average_score": s["average_score"],
                "matched_terms": s["matched_terms"],
            })
    sentence_weightage = max((s["weightage"] for s in sentences), default=0.0)

    # The worst sentence sets the floor for the prompt: benign words damp
    # attack words IN RELATION (same sentence), but must never erase an
    # attack sentence from a different part of the prompt.
    overall["weightage"] = max(overall["weightage"], sentence_weightage)

    return {
        "negative_terms": negative,
        "positive_terms": positive,
        **overall,
        "sentence_count": len(sentences),
        "sentence_weightage": sentence_weightage,
        "sentences": sentences,
    }


# --------------------------------------------------------------------------- #
# SEMANTIC LEXICON EXPANSION (trial-update T4). Words outside the static
# lexicon inherit polarity from their nearest embedded lexicon term via
# Qdrant — so novel vocabulary ("infostealer", "passcodes") still scores.
# Never called from the sub-ms hot path; used by the /sentiment/score API
# (display + block evidence) and any caller that can afford a few ms.
# --------------------------------------------------------------------------- #
_SEMANTIC_MIN_SIM = 0.70          # cosine floor to inherit a polarity
_SEMANTIC_MAX_WORDS = 6           # cap per prompt (latency guard)
_SEMANTIC_STOPWORDS = frozenset(
    "the a an and or of to in for on with is are was were be been this that "
    "these those it its as at by from you your our their his her they them "
    "we i me my please can could would should will shall may might must not "
    "no yes do does did done have has had about into over under then than "
    "there here what which who whom when where why how all any some more most".split())


def semantic_expand(text: str) -> dict:
    """Enrich a word_sentiment() result with Qdrant-inferred polarities.

    Returns {'negative': [...], 'positive': [...], 'weightage': float} where
    each term carries {term, weight, nearest, similarity}. Empty when the
    vector store or embedding model is unavailable (fail-soft).
    """
    try:
        from services import qdrant_client as _q
        from services.embedding_service import embed_batch

        if not _q.ensure_lexicon_collection():
            return {"negative": [], "positive": [], "weightage": 0.0}

        low = deobfuscate(text or "")
        matched = {t["term"] for side in (_match_terms(low)) for t in side}
        candidates: list[str] = []
        for m in _WORD_RE.finditer(low):
            w = m.group(0)
            if (len(w) >= 4 and w not in matched and w not in _SEMANTIC_STOPWORDS
                    and w not in _ALL_LEX and w not in candidates):
                candidates.append(w)
        if not candidates:
            return {"negative": [], "positive": [], "weightage": 0.0}
        candidates = candidates[:_SEMANTIC_MAX_WORDS]

        neg: list[dict] = []
        pos: list[dict] = []
        neg_total = 0.0
        pos_total = 0.0
        vecs = embed_batch(candidates)
        for w, vec in zip(candidates, vecs):
            sim, payload = _q.lookup_lexicon(vec.tolist())
            if sim < _SEMANTIC_MIN_SIM:
                continue
            polarity = float(payload.get("polarity", 0.0))
            if not polarity:
                continue
            inferred = round(abs(polarity) * sim, 4)
            entry = {"term": w, "weight": inferred,
                     "nearest": payload.get("term", ""), "similarity": round(sim, 4)}
            if polarity < 0:
                neg.append(entry)
                neg_total += inferred
            else:
                pos.append(entry)
                pos_total += inferred
        # Same convention as _score_terms: net = attack magnitude − benign.
        weightage = round(min(1.0, max(0.0, neg_total - pos_total) / INJECTION_SATURATION), 4)
        return {"negative": neg, "positive": pos, "weightage": weightage}
    except Exception:
        return {"negative": [], "positive": [], "weightage": 0.0}


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
