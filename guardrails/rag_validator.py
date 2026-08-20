"""
LAYER 4 — RAG CONTEXT VALIDATION (diagram: "Policy, Content Filter";
PDF §2.2 — defense against Indirect Prompt Injection).

  embedding_vector -> fetch RAG docs -> validate each:
    1. Context-intent consistency : cosine(q, d) >= RAG_MIN_SIMILARITY
    2. Imperative detection        : commands in passive reference data => drop
    3. Data-leak check             : credential shapes inside documents
  Output: safe_rag_docs (list) — poisoned context is dropped, never passed on.
"""
from __future__ import annotations

from core.config import SETTINGS
from models.schemas import RagValidationResult
from services import policy_engine, qdrant_client
from services.embedding_service import cosine


def validate(embedding_vector: list[float], query_text: str = "") -> RagValidationResult:
    result = RagValidationResult()

    if not embedding_vector:
        return result  # cascade FAST tiers carry no embedding -> no retrieval
    if not qdrant_client.ready():
        return result

    hits = qdrant_client.search(embedding_vector, top_k=SETTINGS.rag_top_k)
    if not hits:
        return result

    risk = 0.0
    for hit in hits:
        doc = hit["text"]
        reasons: list[str] = []

        # 1) Context-intent consistency (PDF §2.2 check #1)
        if query_text:
            sim = cosine(embedding_vector, _embed_cache(query_text))
            if sim < SETTINGS.rag_min_similarity:
                reasons.append(f"intent-mismatch(sim={sim:.2f})")

        # 2) Imperatives in passive data (PDF §2.2 check #2)
        imperatives = policy_engine.imperative_hits(doc)
        if imperatives:
            result.imperative_flags.append(hit.get("source", "unknown"))
            reasons.append("imperative-injection")
            risk = max(risk, 0.9)

        # 3) Credential shapes inside the document (PDF §2.2 leak angle)
        if policy_engine.leak_hits(doc):
            reasons.append("credential-leak")
            risk = max(risk, 0.7)

        # 4) Explicitly untrusted sources never reach the LLM.
        if hit.get("access") == "untrusted":
            reasons.append("untrusted-source")
            risk = max(risk, 0.8)

        if reasons:
            result.dropped_docs.append(f'{hit.get("source", "doc")} [{", ".join(reasons)}]')
        else:
            result.safe_rag_docs.append(doc)

    result.risk = round(risk, 4)
    return result


# --------------------------------------------------------------------------- #
# Tiny embedding memo: L2 already embedded the sanitized prompt; re-embedding
# the same text for consistency scoring would double the latency budget.
# --------------------------------------------------------------------------- #
_CACHE: dict[str, list[float]] = {}


def _embed_cache(text: str) -> list[float]:
    if text not in _CACHE:
        from services.embedding_service import embed

        _CACHE[text] = embed(text).tolist()
        if len(_CACHE) > 64:
            _CACHE.pop(next(iter(_CACHE)))
    return _CACHE[text]
