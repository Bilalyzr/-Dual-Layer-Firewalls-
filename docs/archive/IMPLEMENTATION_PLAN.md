# Implementation Plan
> Extracted from `Implementation plan.docx`. This MVP executes **Phases 1–3** (Tier 1) plus the minimal Phase 6 dashboard needed for shadow-mode visibility.

## Two de-risking principles (from the plan)
1. The two things most likely to kill this project aren't technical — **legal/consent review of biometric data** and the **replace-vs-augment MFA decision**. In this MVP, biometric scoring is **shadow-only** (Req 3.x does not enforce), sidestepping the consent/liability question for demonstration.
2. **Tier 1's purpose is to produce real benchmark numbers** — Phase 3 is a hard go/no-go gate before Tier 2 spend.

## Phase coverage in this build

### Phase 1 — Semantic Firewall Proxy MVP (Reqs 1.1–1.5)
Node proxy intercepts inbound prompts → regex heuristics (OWASP LLM Top 10 tags) + scikit-learn classifier with tunable threshold → outbound integrity check → confidence logging + low-confidence sampling in MongoDB. **Runs shadow-first, then enforce.**

### Phase 2 — Keystroke Telemetry & Baseline (Reqs 3.1, 3.6)
React `performance.now()` capture hook for dwell/flight → batched to proxy → rolling-average per-user baseline in MongoDB with z-score anomaly scoring → **cold-start fallback** (users with < N samples get MFA flag, no scoring). Shadow-only.

### Phase 3 — Benchmark & Go/No-Go Gate
`scripts/benchmark.js` + `/api/metrics` measure proxy latency, throughput, classifier precision/recall/F1, and biometric false-positive estimate — producing the measured numbers Tier 2 investment depends on.

### Phase 6 (minimal) — SecOps Dashboard
Real-time threat feed (OWASP LLM Top 10), active-session trust scores, agent audit-trail placeholder. Tier-2 panels (SHAP explanations, Trifecta agents) shown as deferred.

## Deferred to Tier 2 (Phases 4–5)
LSTM + RF/XGBoost/MLP ensemble · async SHAP · LangGraph Reader/Actor Trifecta separation · FIDO2 step-up enforcement · Llama Guard 4.
