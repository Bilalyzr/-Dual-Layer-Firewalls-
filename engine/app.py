"""
FastAPI Processing Layer (PRD §4 "Processing Layer").

Two endpoints used by the Node proxy:
  POST /classify      — semantic jailbreak classification (Req 1.3)
  POST /score-batch   — keystroke-dynamics anomaly score (Req 3.1/3.6)

Health: GET /
"""
from __future__ import annotations
import asyncio
import os
import time
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .classifier.model import get_classifier

app = FastAPI(title="Orthrus — Processing Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# MTIME of the v2 threat model this process last loaded — drives hot-reload
# when the v2 auto-trainer swaps the artifact (see /classify semantic fusion).
_V2_MODEL_MTIME = 0.0

# Ensures the trained artifact is loaded at boot (fail fast if missing).
try:
    _CLF = get_classifier()
    _CLF_READY = True
except Exception as exc:  # pragma: no cover — startup guard
    _CLF = None
    _CLF_READY = False
    print(f"[engine] classifier not loaded: {exc}")


def _warm_models() -> None:
    """Warm the heavy optional paths at boot instead of on the first /classify.

    Previously the ensemble + DistilBERT embedding firewall were imported and
    loaded lazily *inside* the request, so the first classify absorbed the full
    model-load latency (and each call re-imported). Loading the cached singletons
    here moves that cost to startup. Fail-open: any failure just leaves the lazy
    fallback in place — never blocks boot.
    """
    try:
        from .classifier.ensemble import ensemble_ready, get_ensemble

        if ensemble_ready():
            get_ensemble()  # caches the soft-voting singleton
            print("[engine] ensemble warmed")
    except Exception as exc:  # pragma: no cover — warm is best-effort
        print(f"[engine] ensemble warm skipped: {exc}")

    try:
        from .classifier.embedding_firewall import enabled as _emb_enabled, _load_model, _load_fit

        if _emb_enabled():
            _load_fit()
            _load_model()  # caches the DistilBERT sentence-transformer
            print("[engine] embedding firewall warmed")
    except Exception as exc:  # pragma: no cover — warm is best-effort
        print(f"[engine] embedding warm skipped: {exc}")

    try:
        from .behavioral.anomaly_svm import model_ready as _svm_ready, _load as _svm_load
        from .behavioral.threat_engine import model_ready as _rf_ready, _load as _rf_load

        if _svm_ready():
            _svm_load()
        if _rf_ready():
            _rf_load()
        print("[engine] behavioral models warmed")
    except Exception as exc:  # pragma: no cover — warm is best-effort
        print(f"[engine] behavioral warm skipped: {exc}")


if os.getenv("ENGINE_WARM_MODELS", "true").lower() == "true":
    _warm_models()


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class ClassifyRequest(BaseModel):
    text: str = Field(..., description="Prompt / payload to inspect")


class ClassifyResponse(BaseModel):
    threat_probability: float
    latency_ms: float
    ready: bool
    model_used: str = "logreg"          # EPIC F: logreg | ensemble | none
    outlier_distance: float = 0.0       # EPIC F: embedding-outlier distance
    outlier_flag: bool = False          # EPIC F: novel-injection flag
    degraded: bool = False              # EPIC F: embedding path failed (≠ "no outlier")
    degraded_reason: str = ""           # why the embedding path is degraded
    llmguard_risk: float = 0.0          # LLM Guard (Protect AI) risk score
    llmguard_detected: bool = False     # LLM Guard flagged injection
    semantic_used: bool = False         # v2 MiniLM+XGBoost contributed to the score


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def root() -> dict[str, Any]:
    return {"service": "orthrus-engine", "classifier_ready": _CLF_READY}


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest) -> ClassifyResponse:
    t0 = time.perf_counter()
    # EPIC F: prefer the soft-voting ensemble when trained; fall back to single LogReg.
    proba = 0.0
    model_used = "none"
    if _CLF_READY:
        try:
            from .classifier.ensemble import ensemble_ready, get_ensemble

            if ensemble_ready():
                proba = get_ensemble().predict_proba(req.text)
                model_used = "ensemble"
            else:
                proba = _CLF.predict_proba(req.text)
                model_used = "logreg"
        except Exception:
            proba = _CLF.predict_proba(req.text)
            model_used = "logreg"
    latency_ms = (time.perf_counter() - t0) * 1000.0

    # EPIC F: optional DistilBERT embedding-outlier score (catches novel injections).
    outlier_distance = 0.0
    is_outlier = False
    degraded = False
    degraded_reason = ""
    try:
        from .classifier.embedding_firewall import is_outlier as _is_out, status as _emb_status

        is_outlier, outlier_distance = _is_out(req.text)
        st = _emb_status()
        degraded = bool(st.get("degraded"))
        degraded_reason = st.get("reason", "")
    except Exception as exc:
        # The import/call itself failed — that's a degradation, not "no outlier".
        degraded = True
        degraded_reason = f"{type(exc).__name__}: {exc}"

    # LLM Guard (Protect AI): DeBERTa-based production prompt-injection scanner.
    llmguard_risk = 0.0
    llmguard_detected = False
    try:
        from .classifier.llmguard_scanner import scan as _lg_scan

        lg = _lg_scan(req.text)
        llmguard_risk = lg["risk_score"]
        llmguard_detected = lg["detected"]
        # Combine: take the MAX of the ensemble + LLM Guard so either detector
        # flagging a threat is enough to block it (defense-in-depth).
        proba = max(proba, llmguard_risk)
    except Exception:
        pass

    # Architecture-v2 semantic model (MiniLM + XGBoost, trained on real
    # traffic + datasets). The site gate (0.65) is much lower than the v2
    # gate (0.90), so the semantic score only contributes as a HIGH-CONFIDENCE
    # kill-shot (>= 0.85) — mid-range semantic scores stay out to avoid
    # importing the semantic model's borderline FPs into the site path.
    # Fail-open when unavailable. The artifact is MTIME-WATCHED: the v2
    # auto-trainer hot-swaps models/threat_model.json in ITS process; without
    # this check the engine would keep scoring with a stale copy forever.
    semantic_used = False
    try:
        global _V2_MODEL_MTIME
        from core.config import SETTINGS as _V2_SETTINGS

        mtime = _V2_SETTINGS.threat_model_path.stat().st_mtime
        if mtime != _V2_MODEL_MTIME:
            from guardrails.input_filter import reload as _v2_reload

            _v2_reload()
            _V2_MODEL_MTIME = mtime
        from guardrails.input_filter import classify as _v2_classify

        v2 = _v2_classify(req.text)
        if v2.intent_score >= 0.85 and v2.intent_score > proba:
            proba = v2.intent_score
        semantic_used = v2.model_used == "semantic"
    except Exception:
        pass

    return ClassifyResponse(
        threat_probability=round(proba, 4),
        latency_ms=round(latency_ms, 3),
        ready=_CLF_READY,
        model_used=model_used,
        outlier_distance=round(float(outlier_distance), 4),
        outlier_flag=bool(is_outlier),
        degraded=degraded,
        degraded_reason=degraded_reason,
        llmguard_risk=round(llmguard_risk, 4),
        llmguard_detected=bool(llmguard_detected),
        semantic_used=semantic_used,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
# Behavioral Risk Analysis API (PRD §42 — Layer 2 replacement)
# --------------------------------------------------------------------------- #
class BehaviorRequest(BaseModel):
    user_id: str = "anon"
    role: str = "user"
    device_id: str = ""
    device_type: str = "laptop"
    device_trust: float = 0.5
    registered_device: bool = True
    device_change: bool = False
    country: str = "IN"
    region: str = "TN"
    location_change: bool = False
    location_frequency: float = 0.8
    hour: int | None = None
    working_hours: bool | None = None
    working_day: bool | None = None
    session_id: str = ""
    session_duration: float = 600.0
    request_count: int = 5
    failed_auth_count: int = 0
    resource_id: str = ""
    resource_type: str = "web_page"
    resource_sensitivity: str = "low"
    request_frequency: float = 10.0
    resource_access_frequency: float = 5.0
    prompt_text: str = ""
    prompt_injection: bool = False  # Layer-1 flagged this prompt as an injection
    # v2 firewall word-injection breakdown — powers the prompt-specific
    # §35 EXPLAINABILITY reasons (attack vocabulary with weights).
    word_scores: dict = {}
    failed_auth_attempt: bool = False  # signal a failed authentication for escalation


@app.post("/behavior/analyze")
def behavior_analyze(req: BehaviorRequest) -> dict[str, Any]:
    """Run the full behavioral risk pipeline — returns the Decision Object (PRD §29)."""
    from .behavioral.telemetry import Telemetry, from_dict
    from .behavioral.pipeline import analyze

    # Handle failed-auth escalation
    if req.failed_auth_attempt:
        from .behavioral.response import escalate_failures
        escalate_failures(req.user_id)

    telemetry = from_dict(req.model_dump())
    result = analyze(telemetry)
    return result


@app.post("/behavior/event")
def behavior_event(req: BehaviorRequest) -> dict[str, Any]:
    """Submit a behavioral/security event (PRD §27 POST /event).

    Analyzes the event through the full pipeline and persists it (FR-12).
    Same engine as /analyze; the decision is recorded to the event store.
    """
    from .behavioral.telemetry import from_dict
    from .behavioral.pipeline import analyze

    if req.failed_auth_attempt:
        from .behavioral.response import escalate_failures
        escalate_failures(req.user_id)

    telemetry = from_dict(req.model_dump())
    result = analyze(telemetry)  # analyze() records to the store
    return {"status": "recorded", "decision": result}


@app.get("/behavior/events")
def behavior_events(user_id: str | None = None, risk_level: str | None = None, limit: int = 100) -> dict[str, Any]:
    """Retrieve behavioral security events (PRD §27 GET /events)."""
    from .behavioral.store import query
    events = query(user_id=user_id, risk_level=risk_level, limit=limit)
    return {"count": len(events), "events": events}


@app.get("/behavior/stats")
def behavior_stats() -> dict[str, Any]:
    """Behavioral Risk Command Center aggregates (PRD §25)."""
    from .behavioral.store import stats
    return stats()


@app.get("/behavior/profile/{user_id}")
def behavior_profile(user_id: str) -> dict[str, Any]:
    from .behavioral.baseline import get_baseline
    b = get_baseline(user_id)
    return b.to_dict()


@app.get("/behavior/risk/{user_id}")
def behavior_risk(user_id: str) -> dict[str, Any]:
    """Current + historical risk state for a user (PRD §27 GET /risk)."""
    from .behavioral.response import get_failure_count
    from .behavioral.store import query
    history = query(user_id=user_id, limit=50)
    current = history[0] if history else None
    return {
        "user_id": user_id,
        "failed_auth_count": get_failure_count(user_id),
        "current_risk_level": current["risk_level"] if current else "LOW",
        "current_risk_score": current["risk_score"] if current else 0.0,
        "history": history,
    }


@app.post("/behavior/recalculate")
def behavior_recalculate(req: BehaviorRequest) -> dict[str, Any]:
    """Recalculate the behavioral baseline from a confirmed-genuine event."""
    from .behavioral.telemetry import from_dict
    from .behavioral.baseline import update_baseline
    from .behavioral.response import reset_failures

    reset_failures(req.user_id)  # successful genuine event resets failures
    t = from_dict(req.model_dump())
    profile = update_baseline(req.user_id, t)
    return {"status": "updated", "profile": profile}
