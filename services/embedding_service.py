"""
Embedding service (diagram: "ML MODELS (Local) / all-MiniLM-L6-v2").

Singleton wrapper around the sentence-transformer, loaded once at startup and
kept in memory (PDF §5 step 3: "<10ms per embed"). When the model cannot load
(no network, first-run download failed) we degrade to a deterministic hashing
embedding so the whole pipeline keeps working — flagged as degraded upstream.
"""
from __future__ import annotations

import hashlib

import numpy as np

from core.config import SETTINGS

EMBED_DIM = 384  # all-MiniLM-L6-v2 output dimension

_MODEL = None
_STATUS: dict = {"ready": False, "degraded": False, "reason": "not loaded", "model": ""}


def status() -> dict:
    return dict(_STATUS)


def _load():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    try:
        from sentence_transformers import SentenceTransformer

        _MODEL = SentenceTransformer(SETTINGS.embedding_model)
        # Warm-up pass so the first real request doesn't pay lazy-init cost.
        _MODEL.encode(["warmup"], convert_to_numpy=True, normalize_embeddings=True)
        _STATUS.update(ready=True, degraded=False, reason="ok", model=SETTINGS.embedding_model)
    except Exception as exc:  # offline / OOM / corrupt cache — hash fallback
        _MODEL = False  # sentinel: attempted and failed
        _STATUS.update(ready=False, degraded=True, reason=f"{type(exc).__name__}: {exc}",
                       model=SETTINGS.embedding_model)
    return _MODEL


def _hash_embed(text: str) -> np.ndarray:
    """Deterministic 384-dim fallback embedding (untrained, but stable)."""
    vec = np.zeros(EMBED_DIM, dtype=np.float32)
    for tok in text.lower().split():
        h = int.from_bytes(hashlib.md5(tok.encode()).digest()[:4], "little")
        vec[h % EMBED_DIM] += 1.0
    n = float(np.linalg.norm(vec))
    return vec / n if n > 0 else vec


def embed(text: str) -> np.ndarray:
    """Embed one string -> normalized float32 vector (384-dim)."""
    if not text or not text.strip():
        return np.zeros(EMBED_DIM, dtype=np.float32)
    m = _load()
    if m:
        emb = m.encode([text], convert_to_numpy=True, normalize_embeddings=True)
        return np.asarray(emb[0], dtype=np.float32)
    return _hash_embed(text)


def embed_batch(texts: list[str]) -> np.ndarray:
    if not texts:
        return np.zeros((0, EMBED_DIM), dtype=np.float32)
    m = _load()
    if m:
        emb = m.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        return np.asarray(emb, dtype=np.float32)
    return np.vstack([_hash_embed(t) for t in texts])


def cosine(a, b) -> float:
    """Cosine similarity of two vectors (lists or arrays)."""
    va, vb = np.asarray(a, dtype=np.float32), np.asarray(b, dtype=np.float32)
    na, nb = float(np.linalg.norm(va)), float(np.linalg.norm(vb))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(va, vb) / (na * nb))
