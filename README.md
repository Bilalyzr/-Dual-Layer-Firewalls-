# 🛡️ Dual-Layer AI Firewall & Behavioral Zero-Trust Platform

A secure proxy that sits in front of an LLM application and defends it on two layers:

- **Layer 1 — Semantic AI Firewall** — scans every prompt with regex heuristics + an
  ML classifier, blocks jailbreaks / prompt injection, and checks responses for
  exfiltration (tagged to the OWASP LLM Top 10).
- **Layer 2 — Keystroke Dynamics** — scores each session's trust against a per-user
  typing baseline, with an MFA fallback during cold start.

## Stack

| Layer | Tech |
|---|---|
| Client | React + Vite (SecOps dashboard) |
| Proxy | Node.js + Express (firewall pipeline, SSE) |
| Engine | Python + FastAPI + scikit-learn (classifier, biometric scoring) |
| Database | MongoDB |

## Tier 2 — completion matrix

All Tier-2 epics are delivered and covered by the test suite (`docs/TIER2_TODO.md`
tracks the detail). Verified against source, not a summary line.

| Epic | Capability | Status | Key files |
|---|---|---|---|
| A | Signed sessions + `trustState` | ✅ | `proxy/auth/session.js` |
| B | FIDO2/WebAuthn step-up MFA | ✅ | `proxy/routes/auth.js`, `client/src/components/StepUpModal.jsx` |
| C | Llama Guard 4 safety layer (in + out) | ✅ | `proxy/firewall/llamaGuard.js` |
| D | TLS 1.3 in transit + AES-256-GCM at rest | ✅ | `edge/nginx.conf`, `proxy/db/encryption.js` |
| E | OS-level Reader-Agent sandbox | ✅ | `reader-svc/`, hardened in `docker-compose.yml` |
| F | Real Actor tools + RBAC + rate limit/audit | ✅ | `proxy/agents/tools/` |
| G | Distributed microservices + Redis bus | ✅ | `proxy/app.js`, `proxy/services/`, `docker-compose.micro.yml` |
| H | XGBoost ensemble parity + per-service CI | ✅ | `engine/biometric/ensemble.py`, `.github/workflows/ci.yml` |

**Firewall latency (PRD §6, <5ms):** heuristics run first and short-circuit a
confirmed block in enforce mode without the ML/Guard round-trip; classifier
verdicts are cached per-prompt (`proxy/firewall/clfCache.js`). Malicious and
repeated/benign paths return sub-millisecond; only a novel benign prompt pays the
single engine hop.

## Quick start

```bash
cp .env.example .env          # optional: set LLM_API_KEY / LLM_BASE_URL / LLM_MODEL
docker compose up --build
```

Open **http://localhost:8080** (dashboard); the API runs on http://localhost:4000.
Without an LLM key the firewall still inspects every request and returns a simulated answer.

## Testing

```bash
cd engine && python -m pytest tests/    # Python engine
cd proxy  && npm test                   # Node proxy
```

## Project layout

```
dual-layer-firewall/
├── engine/   Python FastAPI: classifier + biometric scoring
├── proxy/    Node.js Express firewall proxy
├── client/   React + Vite dashboard
├── scripts/  seed + benchmark
└── docs/     PRD + implementation notes
```
