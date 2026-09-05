# 🛡️ Dual-Layer AI Firewall — GenAI Security Proxy

A security proxy that sits in front of any LLM application and inspects every
prompt and every response in real time:

- **Layer 1 — Semantic AI Firewall** — a 7-layer inspection pipeline (regex
  heuristics → sentiment/weightage → two-tier ML cascade → memory of known
  attacks → behavioral risk → RAG poisoning checks → policy decision), then
  the LLM, then output filtering (exfiltration / PII / toxicity). Mapped to
  the OWASP LLM Top 10 (LLM01 injection, LLMO2/06/08 …).
- **Layer 2 — Behavioral Zero-Trust Engine** — per-session risk scoring over
  a Redis-backed event timeline (drift, attack proximity, cumulative risk,
  injection weightage) that can escalate a gray-zone prompt to RESTRICT or
  BLOCK even when the classifiers are unsure.

Every verdict is explainable: the dashboard shows *why* a prompt was blocked
(matched attack vocabulary with weights, word-level sentiment chips, risk
trend, device/location context from the real public IP).

## Request lifecycle

```
                    ┌──────────────────────── site door ───────────────────────┐
 browser dashboard ─▶ proxy :4001  POST /api/chat   (block = 200 + blocked:true) │
                    │   sanitize → sentiment → cascade → memory → behavioral     │
                    │   → RAG validate → decision ──┐                            │
                    └───────────────────────────────┼────────────────────────────┘
                                                    ▼
   GLM-4.5-Flash (primary) ──6s hedge──▶ Ollama Qwen2.5 (local fallback) ──▶ offline responder
                                                    │
                                                    ▼
                              output filter (exfil / PII / toxicity) → answer
                    ┌──────────────────────── API door ────────────────────────┐
 API consumers ─────▶ firewall :8020  POST /v1/chat/completions (block = 403)   │
                    │   same pipeline, engine-side, full guardrails JSON        │
                    └───────────────────────────────────────────────────────────┘
```

## The inspection pipeline

| # | Layer | What it does |
|---|---|---|
| 1 | Sanitizer | strips obfuscation, leetspeak, base64 payloads |
| 2 | Sentiment / word weightage | lexicon + Qdrant-semantic expansion; gray-zone weightage rule |
| 3 | Cascade classifier | **fast tier** TF-IDF ensemble (~ms, blocks ≥0.85) → **deep tier** MiniLM + XGBoost |
| 4 | Attack memory | Qdrant similarity against previously blocked prompts |
| 5 | Behavioral engine | session risk, drift, attack proximity → escalate gray zone |
| 6 | RAG validator | drops poisoned retrieved docs (imperative-injection, untrusted source) |
| 7 | Decision | policy fusion → ALLOW / RESTRICT / BLOCK, with explainability payload |

Post-LLM: regex + semantic output filtering before anything reaches the user.

## LLM routing (built for flaky networks)

Primary (GLM) → **hedged** local fallback: if the primary hasn't answered in
6 s, Ollama Qwen2.5-3B starts generating *in parallel* and the first to
finish wins (the loser is aborted). A **circuit breaker** skips a dead
primary for 2 min after 2 consecutive failures. Worst-case reply ≈ 7 s,
breaker-open ≈ 1 s. The local model is kept warm (keep_alive + periodic ping).

## Stack

| Tier | Tech |
|---|---|
| Client | React + Vite — SecOps dashboard, SSE live threat feed, pipeline-scan loading |
| Proxy | Node.js + Express — Layer-1 pipeline, sessions/WebAuthn step-up, SSE, SSE edge defenses |
| Engine + v2 API | Python + FastAPI — cascade classifier, behavioral engine, RAG, output filter |
| Audit store | **PostgreSQL** (audit log, training samples, model versions) |
| Sessions / behavioral | **Redis** (sliding windows, strikes, timelines) |
| Vector store | **Qdrant** (attack memory, semantic lexicon, RAG docs) |
| Read models | MongoDB (alerts, metrics, intel) |
| LLMs | GLM-4.5-Flash (primary) · Qwen2.5 via Ollama (local fallback) |

## Run it

**One command (dev):**

```bash
npm install && npm run install:all   # first time only
npm run dev                          # engine :8011 + proxy :4001 + dashboard :5174
```

(Ctrl-C stops all three.) Start **Docker Desktop** first — it provides
PostgreSQL `:5436`, Redis `:6379` and Qdrant `:6333`.

**Full stack (Docker):**

```bash
docker compose up --build     # dashboard on :8080, API on :4000
```

**Zero-downtime blue-green deploy** (what CI/CD ships):

```bash
deploy/bluegreen/scripts/deploy-bluegreen.sh   # nginx edge :8090, health-gated switch
```

**v2 API door (reports + API testing):**

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8020   # run inside the project .venv
```

## Testing & the test report

```bash
python -m pytest tests/ -q            # firewall v2 API suite (51 tests)
cd engine && python -m pytest tests/  # engine suite (15 tests)
cd proxy && npm test                  # proxy suite (272 tests)
python scripts/redteam_custom.py      # novel-attack battery (16 attacks + 6 benign, both doors)
```

Every run is auto-recorded (`data/reports/history.jsonl`) and visualized:

- `GET /reports` — live metrics dashboard (suite runs, battery history, model trend)
- `GET /reports/testcase` — formal **Test Case Report** (TC ID · Test Case · Input · Expected · Actual · Status)
- `python scripts/export_report.py` — both as standalone double-clickable HTML (`data/reports/*.html`)

## Model lifecycle

Live traffic is stored as training samples (PostgreSQL). Retraining runs on
the hybrid corpus with **champion–challenger promotion gates** on both heads —
a challenger deploys only if it beats (or matches within tolerance) the
incumbent on a shared holdout; rejected challengers are logged, never served.
Fast-tier artifacts hot-reload on mtime.

## Project layout

```
dual-layer-firewall/
├── client/    React + Vite SecOps dashboard
├── proxy/     Node/Express Layer-1 firewall (routes, heuristics, LLM client)
├── engine/    FastAPI classifier engine (cascade, embeddings, training)
├── api/       v2 firewall API (:8020) — 7-layer pipeline + reports
├── services/  audit log (PG), policy engine, behavioral, LLM routing, report store
├── guardrails/ decision fusion, memory, behavioral guardrails
├── train/     retraining + promotion gates
├── scripts/   runner, red-team battery, report export, benchmarks
├── deploy/    blue-green compose + nginx edge + health-gated switch
└── docs/      PRD, implementation plan, deployment readiness, trial manual
```

## Configuration

Copy `.env.example` → `.env` (and/or `.env.local`, which wins). Key vars:
`LLM_BASE_URL / LLM_API_KEY / LLM_MODEL`, `LLM_FALLBACK_URL / _MODEL`,
`LLM_TIMEOUT_MS`, `LLM_HEDGE_DELAY_MS`, `AUDIT_DSN`, `FIREWALL_MODE`
(`shadow`/`enforce`), `STRICT_REAL`. See `core/config.py` for precedence.
