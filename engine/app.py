"""
FastAPI Processing Layer (PRD §4 "Processing Layer").

Two endpoints used by the Node proxy:
  POST /classify      — semantic jailbreak classification (Req 1.3)
  POST /score-batch   — keystroke-dynamics anomaly score (Req 3.1/3.6)

Health: GET /
"""
from __future__ import annotations
import os
import time
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
def score_batch_route(req: ScoreRequest) -> dict[str, Any]:
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
    )
    return {
        "trust_score": result.trust_score,
        "risk_score": result.risk_score,
        "z": result.z,
        "cold_start": result.cold_start,
        "reason": result.reason,
        "dwell_mean": result.dwell_mean,
        "flight_mean": result.flight_mean,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
