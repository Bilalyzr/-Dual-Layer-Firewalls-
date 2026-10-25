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
        sim = float(hit.get("score", 0.0))
        reasons: list[str] = []

        # 1) Context-intent consistency (PDF §2.2 check #1):
        #    Use the document's actual cosine similarity to the query vector.
        #    Unrelated KB entries below rag_min_similarity are ignored rather
        #    than raising false-positive poisoning risk on everyday chat prompts.
        if sim < SETTINGS.rag_min_similarity:
            reasons.append(f"intent-mismatch(sim={sim:.2f})")

        # 2) Imperatives in passive data (PDF §2.2 check #2)
        imperatives = policy_engine.imperative_hits(doc)
        if imperatives:
            if sim >= SETTINGS.rag_min_similarity:
                result.imperative_flags.append(hit.get("source", "unknown"))
                risk = max(risk, 0.9)
            reasons.append("imperative-injection")

        # 3) Credential shapes inside the document (PDF §2.2 leak angle)
        if policy_engine.leak_hits(doc):
            if sim >= SETTINGS.rag_min_similarity:
                risk = max(risk, 0.7)
            reasons.append("credential-leak")

        # 4) Explicitly untrusted sources never reach the LLM.
        if hit.get("access") == "untrusted":
            if sim >= SETTINGS.rag_min_similarity:
                risk = max(risk, 0.8)
            reasons.append("untrusted-source")

        if reasons:
            if sim >= SETTINGS.rag_min_similarity:
                result.dropped_docs.append(f'{hit.get("source", "doc")} [{", ".join(reasons)}]')
        else:
            result.safe_rag_docs.append(doc)

    result.risk = round(risk, 4)
    return result
