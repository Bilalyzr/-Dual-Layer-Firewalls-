"""
EPIC F — DistilBERT embedding firewall (semantic outlier detection).

Catches novel/obfuscated prompt injections that lexical models (TF-IDF, regex)
miss — the OWASP LLM08 gap. Approach:

  1. Embed a corpus of KNOWN-BENIGN prompts with DistilBERT → compute their
     centroid + spread (covariance diagonal).
  2. At inference, embed the incoming prompt and measure Mahalanobis distance
     from the benign centroid. A large distance ⇒ semantic outlier ⇒ likely an
     injection even if it shares no keywords with the training attacks.

Heavy: requires `sentence-transformers` + downloads `distilbert-base-nli-mean-tokens`
(~250MB) on first use. Disabled by default (EMBEDDING_FIREWALL_ENABLED);
falls back gracefully (returns 0.0) when the model isn't available.
"""
from __future__ import annotations
import os
from pathlib import Path

import joblib
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
CENTROID_PATH = MODEL_DIR / "embed_centroid.joblib"  # {centroid, inv_cov, threshold}
_MODEL = None  # lazy-loaded sentence-transformer
_FIT = None    # cached fit params

# EPIC F: last-run health. Previously every failure (missing model, load error,
# runtime exception) was silently swallowed to 0.0 — indistinguishable from a
# genuine "no outlier". This tracks *why* the path produced 0.0 so /classify can
# surface a `degraded` flag (mirrors the biometric path's degraded reporting).
_STATUS: dict = {"degraded": False, "reason": "not run"}


def _mark(degraded: bool, reason: str) -> None:
    _STATUS["degraded"] = degraded
    _STATUS["reason"] = reason


def status() -> dict:
    """Health of the embedding path from its last invocation."""
    return dict(_STATUS)


def enabled() -> bool:
    return os.getenv("EMBEDDING_FIREWALL_ENABLED", "false").lower() == "true"


def _load_model():
    """Lazy-load the DistilBERT sentence-transformer (heavy)."""
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer  # heavy import

        name = os.getenv("EMBEDDING_MODEL", "sentence-transformers/distilbert-base-nli-mean-tokens")
        _MODEL = SentenceTransformer(name)
    return _MODEL


def _load_fit():
    global _FIT
    if _FIT is None:
        if not CENTROID_PATH.exists():
            return None
        _FIT = joblib.load(CENTROID_PATH)
    return _FIT


def _embed(texts):
    m = _load_model()
    emb = m.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
    return np.asarray(emb, dtype=np.float32)


def fit_from_benign(benign_texts: list[str], threshold_quantile: float = 0.99) -> dict:
    """Compute the benign centroid + inverse-covariance from a set of benign prompts.

    Persist to CENTROID_PATH. Call once (from train script) on a large benign corpus.
    """
    if not benign_texts:
        return {}
    emb = _embed(benign_texts)
    centroid = emb.mean(axis=0)
    # diagonal inverse-covariance (robust, no matrix inversion headaches)
    var = emb.var(axis=0)
    var[var < 1e-6] = 1e-6
    inv_cov = 1.0 / var
    # distance of each benign point from the centroid
    diff = emb - centroid
    dist = np.sqrt(np.einsum("ij,j,ij->i", diff, inv_cov, diff))
    threshold = float(np.quantile(dist, threshold_quantile))
    fit = {"centroid": centroid, "inv_cov": inv_cov, "threshold": threshold}
    joblib.dump(fit, CENTROID_PATH)
    return {"n_benign": len(benign_texts), "threshold": threshold, "dim": int(emb.shape[1])}


def outlier_score(text: str) -> float:
    """Return Mahalanobis distance of `text` from the benign centroid.

    0.0 when disabled or unfitted (fail-open). Higher ⇒ more anomalous.
    """
    if not enabled():
        _mark(False, "disabled")  # intentionally off — not a degradation
        return 0.0
    fit = _load_fit()
    if fit is None:
        _mark(True, "no fitted centroid (run the embedding-fit train step)")
        return 0.0
    try:
        emb = _embed([text])[0]
        diff = emb - fit["centroid"]
        dist = float(np.sqrt(np.einsum("j,j,j->", diff, fit["inv_cov"], diff)))
        _mark(False, "ok")
        return dist
    except Exception as exc:
        # never let the embedding path break scoring — but record that it broke,
        # so 0.0 here is distinguishable from a genuine "no outlier".
        _mark(True, f"{type(exc).__name__}: {exc}")
        return 0.0


def is_outlier(text: str) -> tuple[bool, float]:
    """(is_outlier, distance). Uses the fitted threshold."""
    d = outlier_score(text)
    fit = _load_fit()
    thr = fit["threshold"] if fit else float("inf")
    return (d > thr, d)
