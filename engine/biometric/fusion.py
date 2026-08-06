"""
EPIC G — Multi-modal behavioral fusion.

Combines the per-modality signals (keystroke P(genuine), mouse score, session
heuristics) into a single trust score. Approach: weighted late fusion (the
weights reflect each modality's reliability and availability). When a modality
is missing (e.g. no mouse data yet), its weight is redistributed.

This runs AFTER each modality has been scored independently, so it's cheap and
doesn't change the existing keystroke ensemble's contract.
"""
from __future__ import annotations
from dataclasses import dataclass

# Default fusion weights (must sum to ~1.0 when all modalities present).
# Keystroke is the strongest signal; mouse adds cross-modal corroboration; the
# session prior is a mild nudge (long stable sessions ⇒ more trusted).
DEFAULT_WEIGHTS = {
    "keystroke": 0.60,
    "mouse": 0.30,
    "session": 0.10,
}


@dataclass
class FusionInput:
    keystroke_p_genuine: float | None = None  # from the LSTM/ensemble (0..1)
    mouse_score: float | None = None          # 0..1 (1 = matches baseline)
    session_trust: float | None = None        # 0..1 (recent stability)
    weights: dict | None = None


def fuse(inp: FusionInput) -> dict:
    """Weighted late fusion → {trust_score (0..100), risk_score (0..1), modalities, weights_used}."""
    weights = (inp.weights or DEFAULT_WEIGHTS).copy()
    signals = {
        "keystroke": inp.keystroke_p_genuine,
        "mouse": inp.mouse_score,
        "session": inp.session_trust,
    }
    # drop missing modalities and redistribute their weight
    present = {k: v for k, v in signals.items() if v is not None}
    if not present:
        return {"trust_score": 100.0, "risk_score": 0.0, "modalities": [], "reason": "no signals"}
    total_w = sum(weights[k] for k in present)
    if total_w <= 0:
        total_w = 1.0
    fused = sum(present[k] * (weights[k] / total_w) for k in present)
    fused = max(0.0, min(1.0, fused))
    return {
        "trust_score": round(fused * 100, 1),
        "risk_score": round(1.0 - fused, 3),
        "modalities": list(present.keys()),
        "weights_used": {k: round(weights[k] / total_w, 3) for k in present},
        "reason": "fused " + "+".join(present.keys()),
    }
