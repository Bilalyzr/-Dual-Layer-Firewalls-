"""
Two-tier cascade classifier (trial-update): TF-IDF screening + semantic depth.

  FAST-BLOCK : TF-IDF >= CASCADE_FAST_BLOCK                    (~0.4ms)
               obvious lexical threat — block without MiniLM
  FAST-ALLOW : TF-IDF <  CASCADE_FAST_LOW
               AND word-injection weightage < CASCADE_CLEAN_WEIGHTAGE
               AND sanitizer found nothing                     (~0.5ms)
               every cheap signal agrees it's safe — skip MiniLM
  DEEP       : everything else -> MiniLM + XGBoost             (~33ms)

Why FAST-ALLOW needs the extra clearances: novel attacks often score ~0.00 on
TF-IDF (measured: the "grandma" jailbreak), so lexical-lowness alone is NOT
proof of safety. Weightage + sanitizer clearance close that hole: the grandma
prompt carries attack vocabulary, so it falls through to the DEEP tier.
"""
from __future__ import annotations

import time

from core.config import SETTINGS

_legacy = None
_STATUS: dict = {"ready": False, "reason": "not loaded"}


def _load():
    global _legacy
    if _legacy is not None:
        return _legacy
    try:
        # Prefer the 3-model soft-voting ensemble (same as engine /classify):
        # it runs rings around the base LogReg on dataset-lookalike attacks
        # (measured 1.00 vs 0.31) at a fraction of MiniLM's cost.
        from engine.classifier.ensemble import ensemble_ready, get_ensemble

        if ensemble_ready():
            _legacy = get_ensemble()
            _STATUS.update(ready=True, reason="ensemble")
            return _legacy
        from engine.classifier.model import get_classifier

        _legacy = get_classifier()          # TF-IDF + LogisticRegression
        _STATUS.update(ready=True, reason="logreg")
    except Exception as exc:
        _legacy = False
        _STATUS.update(ready=False, reason=f"{type(exc).__name__}: {exc}")
    return _legacy


def status() -> dict:
    return dict(_STATUS)


def fast_classify(text: str, *, weightage: float = 0.0,
                  sanitizer_clean: bool = True) -> dict:
    """Cheap screening. Returns {tier, tfidf_score, reason, latency_ms}.

    tier: 'fast-block' | 'fast-allow' | 'deep'
    Callers run the MiniLM deep tier on 'deep' only.
    """
    t0 = time.perf_counter()
    clf = _load()
    if clf is False or not text or not text.strip():
        return {"tier": "deep", "tfidf_score": None, "reason": "screening unavailable",
                "latency_ms": 0.0}   # fail toward depth, never toward allow
    tfidf = float(clf.predict_proba(text))
    if tfidf >= SETTINGS.cascade_fast_block:
        tier, reason = "fast-block", f"tfidf {tfidf:.2f} >= {SETTINGS.cascade_fast_block}"
    elif (tfidf < SETTINGS.cascade_fast_low
          and weightage < SETTINGS.cascade_clean_weightage
          and sanitizer_clean):
        tier = "fast-allow"
        reason = (f"tfidf {tfidf:.2f} < {SETTINGS.cascade_fast_low}, "
                  f"weightage {weightage:.2f} clean, sanitizer clean")
    else:
        tier = "deep"
        reason = f"ambiguous band (tfidf {tfidf:.2f})"
    return {"tier": tier, "tfidf_score": round(tfidf, 4), "reason": reason,
            "latency_ms": round(1000 * (time.perf_counter() - t0), 3)}
