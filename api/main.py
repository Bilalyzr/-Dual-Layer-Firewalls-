"""
API ENTRY POINT — GenAI Security Firewall Proxy (diagram: "API ENTRY POINT
(api/main.py), Endpoint: POST /v1/chat/completions"; PDF §4.2).

Run (repo root):
    uvicorn api.main:app --host 0.0.0.0 --port 8020

Boot sequence (lifespan): audit store -> vector store (collection + demo
docs) -> embedding model warm-up -> XGBoost head warm-up. Heavy work happens
at startup so the request path stays inside the 10-50ms budget.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from core.config import SETTINGS
from guardrails import input_filter
from services import audit_log, qdrant_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[firewall] booting {SETTINGS.api_title}")
    try:
        audit_log.init()
        print(f"[firewall] audit backend: {audit_log.backend_name()}")
    except Exception as exc:
        print(f"[firewall] audit init skipped: {exc}")
    try:
        if qdrant_client.ensure_collection():
            print(f"[firewall] rag store ready ({qdrant_client.backend_name()})")
        else:
            print("[firewall] rag store unavailable — L4 degrades to no-context")
    except Exception as exc:
        print(f"[firewall] rag init skipped: {exc}")
    try:
        if qdrant_client.ensure_lexicon_collection():
            print("[firewall] semantic lexicon trained (Qdrant)")
    except Exception as exc:
        print(f"[firewall] semantic lexicon skipped: {exc}")
    try:
        from services.embedding_service import _load

        _load()
        print("[firewall] embedding model warm")
    except Exception as exc:
        print(f"[firewall] embedding warm skipped: {exc}")
    try:
        input_filter._load()
        print(f"[firewall] intent head: {input_filter.status()}")
    except Exception as exc:
        print(f"[firewall] intent head warm skipped: {exc}")
    try:
        from services import realtime_learner

        if realtime_learner.start_auto_trainer():
            print(f"[firewall] realtime auto-trainer ON "
                  f"(every {SETTINGS.realtime_interval_s}s, min {SETTINGS.realtime_min_new} new)")
    except Exception as exc:
        print(f"[firewall] realtime trainer skipped: {exc}")
    yield
    try:
        from services import realtime_learner

        realtime_learner.stop_auto_trainer()
    except Exception:
        pass
    print("[firewall] shutdown")


app = FastAPI(title=SETTINGS.api_title, version="2.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
app.include_router(router)
