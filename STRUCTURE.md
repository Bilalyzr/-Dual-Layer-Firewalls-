# 📁 Codebase Structure

One-page map of the repository — what's active, where it lives, and what was removed.

## Active source code (the v2 firewall — `localhost:8020`)

```
api/            FastAPI surface — main.py (POST /v1/chat/completions), routes, DI
core/           pipeline.py (L1→L7 orchestrator), config, security, rate limiter
guardrails/     the 7 layers: sanitizer, cascade, input_filter (L2), behavioral (L3),
                rag_validator (L4), decision (L5), output_filter (L7)
services/       embedding (MiniLM), redis, qdrant (attack memory), policy engine,
                audit_log (PG/SQLite), realtime_learner, metrics, litellm, langfuse
models/         trained artifacts: threat_model.json (XGBoost), embed_stats.joblib
train/          train_threat_model.py — seed, realtime, and vulnerability retraining
tests/          v2 test suite (51 tests): layers, cascade, memory, strikes, timeline
```

## Active source code (the legacy stack — the dashboard site)

```
engine/         Python engine (:8011) — TF-IDF/ensemble classifier, behavioral
                pipeline, biometrics. Imports the v2 semantic model (fusion).
proxy/          Node firewall proxy (:4001) — chat interception, heuristics,
                auth/login, Llama Guard, agent tools, SSE event bus
client/         React SecOps dashboard (:5174, Vite)
reader-svc/     sandboxed reader agent (:8012, Epic E)
edge/           optional TLS-terminating nginx (compose `tls` profile)
```

## Infrastructure & operations

```
deploy/         helm chart, prometheus (+alerts), alertmanager configs
docker-compose.yml          core stack + `security` profile (firewall, redis,
                            qdrant, postgres, prometheus, grafana, alertmanager)
docker-compose.micro.yml    split microservices variant (validated in CI)
Dockerfile.firewall         v2 firewall image (trains model at build time)
render.yaml                 Render.com deploy config
.github/workflows/ci.yml    CI: 5 jobs (engine, proxy, client, micro, reader)
```

## Scripts (`scripts/`)

| Script | Purpose |
|---|---|
| `runner.js` | **one-command stack boot** (`npm dev`) — engine + proxy + dashboard |
| `trial_demo.py` | staff-trial driver: 5 scenarios + progress report |
| `redteam_custom.py` | 16 novel attacks + 6 benign controls verification |
| `fetch_datasets.py` | import public datasets (deepset, AdvBench) |
| `seed_db.js` / `benchmark.js` / `redteam.js` | demo seeding / benchmarking / red-team (prompts/) |
| `draw_architecture.py` | regenerates `docs/architecture.jpg` |
| `gen-certs.sh` | self-signed TLS certs for the edge profile |
| `md_to_docx.py` | regenerates `docs/TRIAL_MANUAL.docx` from the .md |

## Documentation (`docs/`)

```
PRD.md             original product requirements
TRIAL_MANUAL.md    staff trial delivery manual (+ .docx for printing)
architecture.jpg   architecture diagram (source: scripts/draw_architecture.py)
archive/           historical planning docs (Tier-2/3 TODOs, FINAL_PRD,
                   implementation plans, enhancement trackers)
```

Root: `README.md` (legacy stack) · `README_SECURITY.md` (v2 firewall) · `DEPLOY.md` · `STRUCTURE.md` (this file)

## Runtime state (gitignored — never commit)

```
data/             SQLite audit store, Qdrant attack memory (disk mode)
.env / .env.local secrets & local config (LLM keys, STRICT_REAL, ports)
models/*.prev.json  auto-kept rollback artifact
```

## Removed in this cleanup (dead code)

| Removed | Reason |
|---|---|
| `gpu-engine/Dockerfile` | CUDA inference image — no compose service, no CI job, referenced only by an archived doc |
| `proxy/firewall/gpuRouter.js` | exported but never imported anywhere (Epic J leftover) |
| `client/public/facetest.html` | unreferenced manual face-API test page |
| `docs/*` (6 files → `docs/archive/`) | completed planning docs, kept for history |
