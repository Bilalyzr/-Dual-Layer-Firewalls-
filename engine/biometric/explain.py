"""
Async SHAP explainability for the biometric ensemble (Req 3.4).

The PRD is explicit: SHAP runs *asynchronously, post-decision*, off the
real-time authentication path. So `explain()` is a plain (fast-ish) sync call
that the engine schedules in a background task — never awaited inside the
scoring hot path.

We use TreeExplainer on the RandomForest member of the voting ensemble (SHAP's
exact tree method — fast and dependency-light). For the voting ensemble we
attribute to the RF member, which is the dominant contributor and gives stable,
interpretable results.
"""
from __future__ import annotations
import asyncio
from typing import Any

import numpy as np

from .ensemble import FEATURE_ORDER

_shap_explainer = None  # lazy


def _get_explainer():
    """Lazy-build a TreeExplainer on the ensemble's RandomForest member."""
    global _shap_explainer
    if _shap_explainer is None:
        import shap  # imported lazily — heavy

        from .ensemble import get_ensemble

        clf = get_ensemble()
        # VotingClassifier wraps named estimators; rf is the tree-based one.
        rf = clf.named_estimators_["rf"]
        _shap_explainer = shap.TreeExplainer(rf)
    return _shap_explainer


def explain(features: np.ndarray, top_k: int = 6) -> dict[str, Any]:
    """
    Synchronous SHAP explanation for a single feature vector.

    Returns {base_value, features: [{name, value, shap, direction}], sum}.
    Call this from a background task — never inline in the scoring path.
    """
    explainer = _get_explainer()
    X = np.atleast_2d(features.astype(np.float32))
    sv = explainer.shap_values(X, check_additivity=False)

    # Binary RF: shap_values may be a list [class0, class1] or a 3D array.
    if isinstance(sv, list):
        # attribute to class 1 (genuine) — positive SHAP = pushes toward genuine
        contrib = np.array(sv[1])[0]
        base = float(np.array(explainer.expected_value[1]))
    else:
        sv_arr = np.array(sv)
        if sv_arr.ndim == 3:  # (1, F, 2)
            contrib = sv_arr[0, :, 1]
            base = float(np.array(explainer.expected_value)[1])
        else:  # (1, F)
            contrib = sv_arr[0]
            base = float(np.array(explainer.expected_value).ravel()[-1])

    rows = []
    for name, val, s in zip(FEATURE_ORDER, X[0], contrib):
        rows.append(
            {
                "name": str(name),
                "value": round(float(val), 4),
                "shap": round(float(s), 5),
                "direction": "genuine" if s >= 0 else "impostor",
            }
        )
    rows.sort(key=lambda r: abs(r["shap"]), reverse=True)
    return {
        "base_value": round(base, 4),
        "features": rows[:top_k],
        "sum": round(float(contrib.sum()), 5),
    }


async def explain_async(features: np.ndarray, top_k: int = 6) -> dict[str, Any]:
    """
    Run SHAP in a worker thread so it never blocks the event loop / scoring path.
    """
    return await asyncio.to_thread(explain, features, top_k)
