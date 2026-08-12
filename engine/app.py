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

# Async SHAP result store (Req 3.4). request_id -> {status, result|error}.
_SHAP_STORE: dict[str, dict[str, Any]] = {}
# Per-user SHAP throttle: userId -> last-run timestamp (avoids re-running the
# ~1.2s SHAP computation on every keystroke batch).
_SHAP_LAST: dict[str, float] = {}

from .biometric.anomaly import (
    DEFAULT_MIN_SAMPLES,
    DEFAULT_Z_THRESHOLD,
    build_baseline,
    score_batch,
)
from .classifier.model import get_classifier

app = FastAPI(title="Dual-Layer Firewall — Processing Engine", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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


class ScoreRequest(BaseModel):
    dwell_history: list[float] = Field(default_factory=list)
    flight_history: list[float] = Field(default_factory=list)
    prior_n: int = 0
    dwell_times: list[float] = Field(default_factory=list)
    flight_times: list[float] = Field(default_factory=list)
    min_samples: int | None = None
    z_threshold: float | None = None


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/")
def root() -> dict[str, Any]:
    return {"service": "dual-layer-engine", "classifier_ready": _CLF_READY}


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
    )


@app.post("/score-batch")
async def score_batch_route(req: ScoreRequest) -> dict[str, Any]:
    min_samples = req.min_samples or int(
        os.getenv("BIOMETRIC_MIN_SAMPLES", DEFAULT_MIN_SAMPLES)
    )
    z_threshold = req.z_threshold or float(
        os.getenv("BIOMETRIC_Z_THRESHOLD", DEFAULT_Z_THRESHOLD)
    )
    baseline = build_baseline(
        dwell_history=req.dwell_history,
        flight_history=req.flight_history,
        prior_n=req.prior_n,
    )
    result = score_batch(
        baseline=baseline,
        dwell_times=req.dwell_times,
        flight_times=req.flight_times,
        min_samples=min_samples,
        z_threshold=z_threshold,
        dwell_history=req.dwell_history,
        flight_history=req.flight_history,
    )
    response = {
        "trust_score": result.trust_score,
        "risk_score": result.risk_score,
        "z": result.z,
        "cold_start": result.cold_start,
        "reason": result.reason,
        "dwell_mean": result.dwell_mean,
        "flight_mean": result.flight_mean,
        "model_used": result.model_used,
    }
    if result.p_genuine is not None:
        response["p_genuine"] = result.p_genuine

    # Async SHAP (Req 3.4) — fire-and-forget off the scoring path. The result is
    # stored and retrievable via /shap/{request_id}; never awaited here.
    # Throttled per-user: SHAP is for audit/compliance, not real-time display, so
    # we recompute at most every few seconds (avoids burning ~1.2s of CPU on every
    # 6-key batch).
    SHAP_THROTTLE_S = float(os.getenv("SHAP_THROTTLE_S", "8"))
    # Throttle key: a signature of this user's baseline so repeated batches from
    # the same user share a throttle bucket (the engine scores anonymously, so
    # we derive a proxy identity from the baseline length + first sample).
    throttle_key = f"u{req.prior_n}:{req.dwell_history[0]:.1f}" if req.dwell_history else "anon"
    def _should_run_shap() -> bool:
        now = time.time()
        last = _SHAP_LAST.get(throttle_key, 0.0)
        if now - last < SHAP_THROTTLE_S:
            return False
        _SHAP_LAST[throttle_key] = now
        return True

    if (
        result.model_used == "ensemble"
        and not result.cold_start
        and _should_run_shap()
    ):
        import numpy as np
        from .biometric.features import (
            load_seq_normalizer, load_stats_scaler, sequence_stats,
        )
        from .biometric.lstm_model import embed_batch
        from .biometric.anomaly import _build_sequence, SEQ_LEN

        try:
            pairs = _build_sequence(
                req.dwell_history, req.flight_history,
                req.dwell_times, req.flight_times,
            )
            seq = np.array(pairs, dtype=np.float32).reshape(1, SEQ_LEN, 2)
            seq_norm = load_seq_normalizer()
            seq_n = seq_norm.transform(seq) if seq_norm else seq
            bl_dwell_mean = float(np.mean(req.dwell_history)) if req.dwell_history else 0.0
            bl_flight_mean = float(np.mean(req.flight_history)) if req.flight_history else 0.0
            stats_v = sequence_stats(seq[0], bl_dwell_mean, bl_flight_mean).reshape(1, -1)
            stats_scaler = load_stats_scaler()
            stats_n = (stats_scaler.transform(stats_v).astype(np.float32)
                       if stats_scaler else stats_v.astype(np.float32))
            emb = embed_batch(seq_n)
            feats = np.concatenate([emb, stats_n], axis=1).astype(np.float32)

            request_id = f"shp-{os.urandom(6).hex()}"
            response["shap_request_id"] = request_id
            asyncio.create_task(_run_shap(request_id, feats))
        except Exception as exc:  # SHAP must never break scoring
            response["shap_error"] = f"{type(exc).__name__}: {exc}"

    return response


# Keep the in-memory SHAP result store bounded (results are short-lived, fetched
# once by the dashboard) so a long-running engine can't leak memory.
_SHAP_STORE_MAX = 200


def _store_shap(request_id: str, entry: dict[str, Any]) -> None:
    _SHAP_STORE[request_id] = entry
    if len(_SHAP_STORE) > _SHAP_STORE_MAX:
        # Drop the oldest insertions (dicts preserve insertion order in 3.7+).
        for stale in list(_SHAP_STORE.keys())[: len(_SHAP_STORE) - _SHAP_STORE_MAX]:
            _SHAP_STORE.pop(stale, None)


async def _run_shap(request_id: str, feats) -> None:
    """Background SHAP task — stores result for /shap/{request_id} retrieval."""
    try:
        from .biometric.explain import explain_async
        result = await explain_async(feats, top_k=6)
        _store_shap(request_id, {"status": "done", "result": result})
    except Exception as exc:
        _store_shap(request_id, {"status": "error", "error": f"{type(exc).__name__}: {exc}"})


@app.get("/shap/{request_id}")
def get_shap(request_id: str) -> dict[str, Any]:
    entry = _SHAP_STORE.get(request_id)
    if entry is None:
        return {"status": "pending", "request_id": request_id}
    return {"request_id": request_id, **entry}


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
