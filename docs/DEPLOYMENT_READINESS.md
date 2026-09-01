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

---

## Zero-Downtime Deployment (blue-green) — how the site never crashes during updates

**The rule:** the running version keeps serving until the new version is built, booted, and health-checked. Traffic switches with a graceful nginx reload; only then does the old version stop.

```
scripts/deploy-bluegreen.sh          # deploy inactive color + switch
scripts/deploy-bluegreen.sh --status # show colors + health
```

Flow of every deploy:

1. Active color (say **blue**) keeps serving at the edge (`:8090`) the whole time.
2. **Green** is built and booted *beside* it (no shared ports — only the edge is public).
3. Health gate: engine `/health`, firewall `/health`, proxy `/api/alerts/status` must ALL pass. **A failed deploy aborts and blue keeps serving — the site never goes down.**
4. Edge nginx upstream flips to green + `nginx -s reload` (graceful — in-flight requests finish on blue).
5. Blue drains and stops. `.deploy-active` records green.

CI/CD (`.github/workflows/deploy.yml`): after the CI suite is green on `main`, the deploy job validates the compose configs and runs the same script on the server over SSH (configure `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, optional `DEPLOY_PATH` secrets). Without the secrets it skips with instructions instead of failing — CI stays green on any machine.

**First-time bootstrap on a server:**
```bash
git clone <repo> && cd dual-layer-firewall
docker compose --profile security up -d redis postgres qdrant   # shared data stores
echo green > .deploy-active && bash scripts/deploy-bluegreen.sh # bootstraps blue + edge
```
