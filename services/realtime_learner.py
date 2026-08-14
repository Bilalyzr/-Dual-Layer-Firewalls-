"""
Real-time learner (trial-update: "train on real-time data, not a predefined set").

Capture -> auto-label -> auto-retrain loop:

  every request's final verdict becomes a training sample
      blocked => label 1 (threat)   allowed => label 0 (benign)
  a background trainer (REALTIME_INTERVAL_S) retrains the semantic head on
  the accumulated REAL samples only (REALTIME_BOOTSTRAP_SEED=false by
  default — the predefined jailbreak_dataset.csv is NOT used), hot-swaps
  the live model, and records a version for rollback.

Class-safety: a retrain only happens when BOTH classes have at least
REALTIME_MIN_CLASS samples — a one-sided corpus would destroy the model.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from core.config import SETTINGS
from services import audit_log

_STATE: dict[str, Any] = {
    "auto_running": False,
    "last_check": 0.0,
    "last_retrain": None,      # result dict of the last retrain
    "last_error": "",
    "trained_marker": 0,       # sample count at last successful retrain
    "thread": None,
}
_LOCK = threading.Lock()


def record(text: str, label: int, source: str = "realtime",
           scores: dict | None = None) -> bool:
    """Capture one labeled real-traffic prompt (deduped)."""
    return audit_log.record_training_sample(
        text=text, label=label, source=source, scores=scores
    )


def stats() -> dict[str, Any]:
    counts = audit_log.training_sample_counts()
    return {
        "samples": counts,
        "auto_train": {
            "enabled": SETTINGS.realtime_auto_train,
            "interval_s": SETTINGS.realtime_interval_s,
            "min_new": SETTINGS.realtime_min_new,
            "min_class": SETTINGS.realtime_min_class,
            "bootstrap_seed": SETTINGS.realtime_bootstrap_seed,
            "running": _STATE["auto_running"],
            "last_retrain": _STATE["last_retrain"],
            "last_error": _STATE["last_error"],
        },
        "model_version": audit_log.latest_model_version(),
    }


def ready_to_retrain() -> tuple[bool, str]:
    """(ready, reason) — both classes present + enough NEW samples."""
    counts = audit_log.training_sample_counts()
    threat, benign = counts["threat"], counts["benign"]
    if threat < SETTINGS.realtime_min_class:
        return False, f"only {threat} threat samples (need {SETTINGS.realtime_min_class}) — send more attacks"
    if benign < SETTINGS.realtime_min_class:
        return False, f"only {benign} benign samples (need {SETTINGS.realtime_min_class}) — send more normal prompts"
    new = counts["total"] - _STATE["trained_marker"]
    if new < SETTINGS.realtime_min_new:
        return False, f"only {new} new samples since last train (need {SETTINGS.realtime_min_new})"
    return True, "ok"


def retrain_now(force: bool = False) -> dict[str, Any]:
    """Retrain the semantic head from REAL captured traffic. Synchronous."""
    if not force:
        ok, reason = ready_to_retrain()
        if not ok:
            return {"status": "skipped", "reason": reason}
    rows = audit_log.list_training_samples(limit=10000)
    if not rows:
        return {"status": "skipped", "reason": "no training samples"}
    threat = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    if not threat or not benign:
        return {"status": "skipped",
                "reason": f"one-sided corpus (threat={len(threat)}, benign={len(benign)})"}

    try:
        from train.train_threat_model import retrain_from_realtime

        result = retrain_from_realtime(
            [(r["text"], int(r["label"])) for r in rows],
            bootstrap_seed=SETTINGS.realtime_bootstrap_seed,
        )
    except Exception as exc:
        _STATE["last_error"] = f"{type(exc).__name__}: {exc}"
        return {"status": "error", "reason": _STATE["last_error"]}

    _STATE["trained_marker"] = len(rows)
    _STATE["last_retrain"] = {"at": time.time(), "samples": len(rows),
                              "threat": len(threat), "benign": len(benign)}
    _STATE["last_error"] = ""
    try:
        audit_log.mark_training_samples_trained(
            [int(r["id"]) for r in rows if r.get("id") is not None])
    except Exception:
        pass
    return result


def rollback_model() -> dict[str, Any]:
    """Swap the live model back to the previous artifact (one click)."""
    prev = SETTINGS.threat_model_path.with_suffix(".prev.json")
    if not prev.exists():
        return {"status": "error", "reason": "no previous model artifact"}
    import shutil

    shutil.copy2(prev, SETTINGS.threat_model_path)
    from guardrails.input_filter import reload as reload_model

    ok = reload_model()
    return {"status": "rolled_back", "model_ready": ok,
            "version": audit_log.latest_model_version().get("version")}


# --------------------------------------------------------------------------- #
# Background auto-trainer
# --------------------------------------------------------------------------- #
def _loop() -> None:
    while _STATE["auto_running"]:
        time.sleep(min(SETTINGS.realtime_interval_s, 15))
        if not _STATE["auto_running"]:
            break
        if time.time() - _STATE["last_check"] < SETTINGS.realtime_interval_s:
            continue
        _STATE["last_check"] = time.time()
        try:
            ok, _ = ready_to_retrain()
            if ok:
                retrain_now(force=True)
        except Exception as exc:  # never kill the trainer thread
            _STATE["last_error"] = f"{type(exc).__name__}: {exc}"


def start_auto_trainer() -> bool:
    """Start the background trainer (idempotent). Called from app lifespan."""
    with _LOCK:
        if _STATE["auto_running"] or not SETTINGS.realtime_auto_train:
            return _STATE["auto_running"]
        _STATE["auto_running"] = True
        t = threading.Thread(target=_loop, name="realtime-auto-trainer", daemon=True)
        t.start()
        _STATE["thread"] = t
        return True


def stop_auto_trainer() -> None:
    _STATE["auto_running"] = False
