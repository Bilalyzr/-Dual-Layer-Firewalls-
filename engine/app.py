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


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class ClassifyRequest(BaseModel):
    text: str = Field(..., description="Prompt / payload to inspect")


class ClassifyResponse(BaseModel):
    threat_probability: float
    latency_ms: float
    ready: bool


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
    proba = _CLF.predict_proba(req.text) if _CLF_READY else 0.0
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return ClassifyResponse(
        threat_probability=round(proba, 4),
        latency_ms=round(latency_ms, 3),
        ready=_CLF_READY,
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
    if result.model_used == "ensemble" and not result.cold_start:
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


async def _run_shap(request_id: str, feats) -> None:
    """Background SHAP task — stores result for /shap/{request_id} retrieval."""
    try:
        from .biometric.explain import explain_async
        result = await explain_async(feats, top_k=6)
        _SHAP_STORE[request_id] = {"status": "done", "result": result}
    except Exception as exc:
        _SHAP_STORE[request_id] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


@app.get("/shap/{request_id}")
def get_shap(request_id: str) -> dict[str, Any]:
    entry = _SHAP_STORE.get(request_id)
    if entry is None:
        return {"status": "pending", "request_id": request_id}
    return {"request_id": request_id, **entry}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
