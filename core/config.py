"""
Central configuration for the GenAI Security Firewall Proxy (Architecture v2).

Every knob is an environment variable with a safe default so the service boots
with zero configuration (fail-open philosophy, mirroring the engine's
`embedding_firewall` / `llmguard` conventions).

Architecture mapping (diagram "SUPPORTING SERVICES & DATA STORES"):
  - ML MODELS (local)        -> MODELS_DIR, EMBEDDING_MODEL
  - REDIS (state store)      -> REDIS_URL, SESSION_RISK_TTL_S
  - VECTOR DB (RAG store)    -> QDRANT_URL / QDRANT_COLLECTION
  - POLICY & RULES ENGINE    -> thresholds below
  - OBSERVABILITY            -> AUDIT_DSN, METRICS_ENABLED
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Load .env (base) then .env.local (overrides) so local runs match the docs.
for _envfile in (Path(__file__).resolve().parent.parent / ".env",
                 Path(__file__).resolve().parent.parent / ".env.local"):
    if _envfile.exists():
        for _line in _envfile.read_text().splitlines():
            if _line.strip() and not _line.lstrip().startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
MODEL_DIR_LEGACY = ROOT / "engine" / "models"  # artifacts from the Tier-1 classifier


def _env(key: str, default: str) -> str:
    return os.getenv(key, default)


def _envf(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


def _envi(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def _envb(key: str, default: bool) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # ---- API ----------------------------------------------------------- #
    api_title: str = "GenAI Security Firewall Proxy"
    api_key: str = field(default_factory=lambda: _env("FIREWALL_API_KEY", ""))
    # When set, callers must send `Authorization: Bearer <key>`.

    # ---- L1 Prompt Sanitization ---------------------------------------- #
    sanitizer_enabled: bool = field(default_factory=lambda: _envb("SANITIZER_ENABLED", True))

    # ---- L2 Semantic Intent Guardrail ----------------------------------- #
    embedding_model: str = field(
        default_factory=lambda: _env("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    )
    threat_model_path: Path = field(
        default_factory=lambda: Path(_env("THREAT_MODEL_PATH", str(MODELS_DIR / "threat_model.json")))
    )
    embed_stats_path: Path = field(
        default_factory=lambda: Path(_env("EMBED_STATS_PATH", str(MODELS_DIR / "embed_stats.joblib")))
    )
    # Single-turn block threshold for the XGBoost intent score (PDF: the FP
    # rate is the biggest risk — keep this high so benign users pass).
    intent_block_threshold: float = field(
        default_factory=lambda: _envf("INTENT_BLOCK_THRESHOLD", 0.90)
    )

    # ---- L3 Behavioral Session Layer (Redis risk engine) ---------------- #
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))
    # Diagram: "Key: session_risk:{user_id}, TTL: 30 mins".
    session_risk_ttl_s: int = field(default_factory=lambda: _envi("SESSION_RISK_TTL_S", 30 * 60))
    session_window: int = field(default_factory=lambda: _envi("SESSION_WINDOW", 10))
    # Composite cumulative-risk threshold — exceeded => 403 "cumulative risk exceeded".
    cumulative_risk_threshold: float = field(
        default_factory=lambda: _envf("CUMULATIVE_RISK_THRESHOLD", 0.80)
    )
    # Per-turn risk EWMA decay (how much past turns weigh on the current score).
    risk_decay: float = field(default_factory=lambda: _envf("RISK_DECAY", 0.80))
    # Semantic-drift contribution: max drift (cosine distance from session
    # baseline) that still adds zero risk.
    drift_free_tolerance: float = field(default_factory=lambda: _envf("DRIFT_FREE_TOLERANCE", 0.45))

    # ---- L4 RAG Context Validation -------------------------------------- #
    qdrant_url: str = field(default_factory=lambda: _env("QDRANT_URL", ""))  # "" => in-memory
    qdrant_collection: str = field(default_factory=lambda: _env("QDRANT_COLLECTION", "rag_documents"))
    rag_top_k: int = field(default_factory=lambda: _envi("RAG_TOP_K", 3))
    # Context-intent consistency floor: docs below this cosine sim to the
    # query are dropped (PDF §2.2 check #1).
    rag_min_similarity: float = field(default_factory=lambda: _envf("RAG_MIN_SIMILARITY", 0.25))
    rag_seed_demo_docs: bool = field(default_factory=lambda: _envb("RAG_SEED_DEMO_DOCS", True))

    # ---- L6 Upstream LLM Execution (LiteLLM router) --------------------- #
    default_llm_model: str = field(default_factory=lambda: _env("DEFAULT_LLM_MODEL", "gpt-4o-mini"))
    llm_timeout_s: float = field(default_factory=lambda: _envf("LLM_TIMEOUT_S", 30.0))
    # When no provider key is configured the router degrades to a
    # deterministic offline responder so the pipeline stays testable.
    llm_offline_echo: bool = field(default_factory=lambda: _envb("LLM_OFFLINE_ECHO", True))

    # ---- L6 local fallback provider (Ollama on localhost) ----------------- #
    # Used when the primary provider is unreachable or rate-limited, before
    # the offline responder. Empty string disables the hop.
    llm_fallback_url: str = field(default_factory=lambda: _env("LLM_FALLBACK_URL", ""))
    llm_fallback_model: str = field(
        default_factory=lambda: _env("LLM_FALLBACK_MODEL", "qwen2.5:7b-instruct-q4_K_M")
    )
    # CPU inference of a 7B model is slow — give it room.
    llm_fallback_timeout_s: float = field(
        default_factory=lambda: _envf("LLM_FALLBACK_TIMEOUT_S", 120.0)
    )

    # ---- L7 Egress Output Guardrail ------------------------------------- #
    output_filter_enabled: bool = field(default_factory=lambda: _envb("OUTPUT_FILTER_ENABLED", True))
    output_block_threshold: float = field(
        default_factory=lambda: _envf("OUTPUT_BLOCK_THRESHOLD", 0.85)
    )

    # ---- Policy & Rules Engine ------------------------------------------ #
    policy_enforce_denied_topics: bool = field(
        default_factory=lambda: _envb("POLICY_ENFORCE_DENIED_TOPICS", False)
    )

    # ---- Observability & Operations ------------------------------------- #
    # PostgreSQL first (diagram: POSTGRESQL log store); falls back to a local
    # SQLite file so the audit trail works with zero infra.
    audit_dsn: str = field(default_factory=lambda: _env("AUDIT_DSN", ""))
    audit_sqlite_path: Path = field(
        default_factory=lambda: Path(_env("AUDIT_SQLITE_PATH", str(ROOT / "data" / "security_audit.db")))
    )
    metrics_enabled: bool = field(default_factory=lambda: _envb("METRICS_ENABLED", True))

    # ---- Rate limiting (PDF core/rate_limiter.py) ----------------------- #
    rate_limit_per_min: int = field(default_factory=lambda: _envi("RATE_LIMIT_PER_MIN", 120))

    # ---- Real-time learning loop (model trains on LIVE traffic) --------- #
    # Off by default? No — the trial requirement is real-time data, so the
    # auto-trainer runs unless explicitly disabled.
    realtime_auto_train: bool = field(default_factory=lambda: _envb("REALTIME_AUTO_TRAIN", True))
    realtime_interval_s: int = field(default_factory=lambda: _envi("REALTIME_INTERVAL_S", 300))
    realtime_min_new: int = field(default_factory=lambda: _envi("REALTIME_MIN_NEW", 20))
    # Minimum samples PER CLASS before a real-data-only retrain is allowed.
    realtime_min_class: int = field(default_factory=lambda: _envi("REALTIME_MIN_CLASS", 8))
    # Bootstrap with the predefined seed dataset? Default FALSE — real data only
    # (the explicit trial requirement).
    realtime_bootstrap_seed: bool = field(
        default_factory=lambda: _envb("REALTIME_BOOTSTRAP_SEED", False)
    )

    # ---- Two-tier cascade (TF-IDF screening -> MiniLM depth) ------------- #
    cascade_enabled: bool = field(default_factory=lambda: _envb("CASCADE_ENABLED", True))
    # TF-IDF at/above this blocks instantly (obvious lexical threat).
    cascade_fast_block: float = field(
        default_factory=lambda: _envf("CASCADE_FAST_BLOCK", 0.90)
    )
    # TF-IDF below this AND clean weightage AND clean sanitizer allows
    # instantly. Lexical-lowness alone is NEVER enough (novel attacks score
    # ~0.00 on TF-IDF) — all cheap signals must agree.
    cascade_fast_low: float = field(
        default_factory=lambda: _envf("CASCADE_FAST_LOW", 0.20)
    )
    cascade_clean_weightage: float = field(
        default_factory=lambda: _envf("CASCADE_CLEAN_WEIGHTAGE", 0.20)
    )

    # ---- Semantic attack memory (Qdrant) ----------------------------------- #
    # Local on-disk storage for the embedded Qdrant (survives restarts).
    qdrant_path: Path = field(
        default_factory=lambda: Path(_env("QDRANT_PATH", str(ROOT / "data" / "qdrant")))
    )
    # Cosine similarity to a remembered-blocked prompt at/above this = the
    # prompt is a near-duplicate of a known attack -> memory block.
    memory_block_threshold: float = field(
        default_factory=lambda: _envf("MEMORY_BLOCK_THRESHOLD", 0.92)
    )

    # ---- Long-term user risk memory (Redis) -------------------------------- #
    # N blocks within the strike window -> the repeat offender is banned.
    user_strike_limit: int = field(default_factory=lambda: _envi("USER_STRIKE_LIMIT", 3))
    user_strike_window_s: int = field(
        default_factory=lambda: _envi("USER_STRIKE_WINDOW_S", 24 * 3600)
    )


SETTINGS = Settings()
