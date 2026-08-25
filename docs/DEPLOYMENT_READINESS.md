# Deployment Feasibility Assessment (T8)

Verdict: **deployable today for a trial/demo on Render or any Docker host; production hardening items listed below.**

## What works out of the box

| Capability | Status | Evidence |
|---|---|---|
| Containerization | ✅ | `Dockerfile.firewall` builds + trains the model at build time; `docker-compose.yml` boots the full stack incl. `security` profile (Prometheus/Grafana/Alertmanager) |
| PaaS blueprint | ✅ | `render.yaml` defines the web service + env wiring |
| CI/CD | ✅ | 5 GitHub Actions jobs green (engine, proxy, client, reader-svc, micro smoke) |
| Config management | ✅ | every knob is an env var with a safe default (`core/config.py`); `.env` → `.env.local` precedence documented |
| Data stores | ✅ | PG (audit) + Redis (sessions) + Qdrant (vectors) via compose; graceful fallbacks (SQLite / in-memory / `:memory:`) when absent |
| Health & observability | ✅ | `/health` per-service readiness, `/metrics` Prometheus scrape, structured logs |
| Zero-downtime model updates | ✅ | retrained models hot-reload via MTIME watch; one-call rollback |

## Resource requirements (measured on this machine)

- **Firewall API**: 2 vCPU / 4 GB RAM (MiniLM ~500 MB RAM warm; CPU inference)
- **Proxy + Engine + Dashboard**: 1 vCPU / 1 GB each
- **LLM**: GLM API (no local cost) — local Qwen fallback is OPTIONAL and needs ~6 GB RAM
- Postgres/Redis/Qdrant: smallest container tiers suffice at trial scale

## Hardening required before production

1. **Secrets**: move `LLM_API_KEY`, `SESSION_SECRET`, `FIREWALL_API_KEY` to the platform's secret store (Render dashboard / Docker secrets). Never bake into images.
2. **HTTPS + auth on the dashboard**: the Vite dev server has no auth; put nginx (already in `edge/`) or the PaaS edge in front with TLS, and keep the proxy's session auth enforced.
3. **CORS**: `api/main.py` allows broad origins for the trial — pin to the dashboard origin in production.
4. **Managed datastores**: swap compose Postgres/Redis for managed instances (backups, TLS); set `AUDIT_DSN` + `REDIS_URL` + `QDRANT_URL`.
5. **Model artifact strategy**: either bake `models/` into the image (current, reproducible) or load from object storage; disable auto-retrain in prod until a promotion pipeline (canary + rollback gate) exists.
6. **Rate limits**: raise `RATE_LIMIT_PER_MIN` from the trial default only after load testing; the LLM provider quota is the real ceiling.
7. **Alert routing**: Alertmanager configs in `deploy/` currently log only — wire real receivers (email/Slack) for `block_rate` and `latency` alerts.

## Recommended target (trial day)

```
Render web service (Docker, Dockerfile.firewall)
  + managed Postgres + managed Redis (Render free/hobby tiers are sufficient)
  + GLM API key as secret
  + local Qwen fallback OPTIONAL (only if the plan includes a 6GB instance)
```

CI already gates every push; a manual smoke (`scripts/trial_demo.py` + `scripts/redteam_custom.py`) should run once against the deployed URL before the trial.
