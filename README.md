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
