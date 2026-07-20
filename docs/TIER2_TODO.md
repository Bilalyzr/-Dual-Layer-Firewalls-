# Tier 2 — Implementation TODO

Status legend: ✅ done · 🟡 partial · ⬜ not started
Effort: S (≤1 day) · M (2–4 days) · L (1–2 weeks) · XL (multi-week)

## Already delivered (Phases 4–5, engine + agents)
- [x] ✅ LSTM + RF/GB/MLP biometric ensemble (`engine/biometric/`, macro F1 ≈ 0.962)
- [x] ✅ Async SHAP explainability (`engine/biometric/explain.py`, `GET /api/shap/:id`)
- [x] ✅ Trifecta Reader→Validator→Actor agents with JSON-schema validation + RBAC (`proxy/agents/`)

Everything below is the remaining Tier 2 surface, sequenced by dependency.

---

## EPIC A — Session & Identity foundation  (prereq for FIDO2)  · Effort M
The stack currently keys everything off a client-generated `userId` with **no real
session**. FIDO2 step-up needs an authenticated session to protect.

- [ ] ⬜ Add a `sessions` concept: issue a signed session token (JWT or opaque + Mongo `sessions` collection) on first load. Files: `proxy/auth/session.js`, middleware in `proxy/server.js`.
- [ ] ⬜ Add `sessions` + `credentials` Mongo collections to `proxy/db/mongo.js` (with in-memory fallback like the others).
- [ ] ⬜ Thread `sessionId` through `/api/chat` and `/api/biometric/batch` (replace bare `userId`).
- [ ] ⬜ Add a per-session `trustState` ({ stepUpRequired, lastVerifiedAt }).
- **Acceptance:** every request carries a verifiable session; server can mark a session `stepUpRequired` and read it back.

## EPIC B — FIDO2 / WebAuthn step-up MFA enforcement  · Effort L · depends on A
Turns Layer 2 from shadow into enforce: when keystroke trust collapses, require a
hardware/passkey re-auth before the session may continue.

- [ ] ⬜ Backend: `@simplewebauthn/server`. Endpoints in `proxy/routes/auth.js`:
      `POST /api/auth/webauthn/register/options` · `/register/verify` · `/authenticate/options` · `/authenticate/verify`.
- [ ] ⬜ Store credentials (credentialID, publicKey, counter) in the `credentials` collection.
- [ ] ⬜ Enforcement hook: in `proxy/routes/biometric.js`, when `BIOMETRIC_MODE=enforce` and `trust_score < BIOMETRIC_STEPUP_THRESHOLD` (new env) and not cold-start → set session `stepUpRequired=true`, emit `publish("stepup", …)`.
- [ ] ⬜ Gate `/api/chat`: if `stepUpRequired`, return `401 {reason:"step_up_required"}` until a fresh WebAuthn assertion clears it.
- [ ] ⬜ Frontend: `@simplewebauthn/browser`. A step-up modal component that triggers on `401 step_up_required`; a one-time registration flow. Files: `client/src/components/StepUpModal.jsx`, wire into `ChatPanel.jsx`.
- [ ] ⬜ Config: `BIOMETRIC_MODE=enforce`, `BIOMETRIC_STEPUP_THRESHOLD`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN` in `.env.example`.
- [ ] ⬜ Tests: unit test the enforcement decision; mock a verified/failed assertion.
- **Acceptance:** in enforce mode, forcing trust below threshold blocks chat until a WebAuthn assertion verifies; passes/fails logged as alerts.

## EPIC C — Llama Guard 4 safety layer  · Effort M · independent
A dedicated safety-model pass on **input and output**, complementing the regex +
scikit-learn classifier.

- [ ] ⬜ `proxy/firewall/llamaGuard.js`: call a Llama-Guard-hosting endpoint (Groq/Together/Ollama) via the existing OpenAI-compatible client; parse the safe/unsafe + category (S1–S13) verdict.
- [ ] ⬜ Wire into the pipeline in `proxy/routes/chat.js`: run alongside `runHeuristics`+`classifyPrompt` (input) and alongside `checkOutput` (output). Combine verdicts into the existing `verdict` object.
- [ ] ⬜ Map Llama Guard categories → OWASP LLM tags for the dashboard threat feed.
- [ ] ⬜ Config: `LLAMAGUARD_ENABLED`, `LLAMAGUARD_URL`, `LLAMAGUARD_MODEL`. Fail-open in shadow, fail-closed in enforce (match existing firewall semantics).
- [ ] ⬜ Tests: known-unsafe and known-safe prompts; degraded-endpoint fallback.
- **Acceptance:** an unsafe prompt Llama Guard flags is blocked in enforce mode with a category tag, even if the regex/classifier miss it.

## EPIC D — Security NFRs: TLS 1.3 in transit + AES-256 at rest  · Effort M
PRD §6 requirements currently unmet (plain HTTP, unencrypted storage).

- [ ] ⬜ TLS: terminate TLS at an nginx reverse proxy in `docker-compose.yml` (or Node `https`), TLS 1.3 only; redirect HTTP→HTTPS. Update client `PROXY_URL`/docs.
- [ ] ⬜ At rest: enable Mongo encryption-at-rest (Atlas/Enterprise) **or** application-level field encryption for sensitive fields (stored prompt snippets in `alerts`/`samples`, keystroke `baselines`). Node `crypto` AES-256-GCM helper in `proxy/db/encryption.js`, applied in `insertAlert`/`insertSample`/`upsertBaseline`.
- [ ] ⬜ Move the LLM key + secrets out of `.env.local` into a secret manager for any non-local deploy; document key rotation.
- **Acceptance:** all traffic over HTTPS/TLS 1.3; sensitive DB fields are ciphertext at rest.

## EPIC E — OS-level Reader-Agent sandboxing  · Effort L · Phase 5
Today the Reader is isolated only *logically* (RBAC → zero tools) but runs in the
main Node process. Make the isolation real.

- [ ] ⬜ Extract the Reader into its own service `reader-svc` (small Node/Express) that ONLY accepts untrusted text and returns validated JSON. Files: `reader-svc/` + `proxy/agents/readerAgent.js` becomes a thin HTTP client to it.
- [ ] ⬜ Container hardening in `docker-compose.yml`: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges]`, non-root user, tmpfs only.
- [ ] ⬜ Network egress policy: reader-svc may reach ONLY the LLM endpoint — not Mongo, not the engine, not the proxy internals (dedicated docker network + no shared network with data services). Optionally gVisor (`runsc`) runtime.
- [ ] ⬜ Tests: assert reader-svc cannot open a socket to Mongo/engine (integration test in CI).
- **Acceptance:** a compromised Reader prompt cannot exfiltrate to internal services — only the LLM call and the schema-checked JSON return are possible.

## EPIC F — Real Actor tool integrations  · Effort M · Phase 5 · depends on B/E
Replace the mock `lookup`/`summarize`/`notify` tools with real, still-RBAC-gated adapters.

- [ ] ⬜ Define a tool-adapter interface; move implementations to `proxy/agents/tools/` (one file per tool).
- [ ] ⬜ `notify` → real channel (SendGrid/SMTP email, or Slack webhook) behind env creds; test/sandbox mode when unset.
- [ ] ⬜ `lookup` → real KB/vector search or CRM read API.
- [ ] ⬜ Keep every call behind the existing schema validation + `canCall('actor', …)` RBAC; add per-tool rate limits + audit log entries.
- [ ] ⬜ Feature-flag each integration; default to mock when creds absent (keeps the demo working).
- **Acceptance:** with creds set, `notify` sends a real message; with creds absent, falls back to mock; RBAC/schema still enforced either way.

## EPIC G — Distributed microservices architecture  · Effort XL · Phase 5 (last)
PRD §7 Tier 2 target. Do this only after A–F stabilize.

- [ ] ⬜ Split the proxy into: `gateway`, `firewall-svc`, `agent-svc`, `biometric-svc` (engine already separate; reader-svc from Epic E).
- [ ] ⬜ Introduce a message bus (NATS/Redis) for the SSE event fan-out instead of the in-process `eventBus.js`.
- [ ] ⬜ k8s manifests or an expanded `docker-compose.yml`; per-service health checks; horizontal scale for `firewall-svc`.
- [ ] ⬜ Centralized structured logging + metrics (OpenTelemetry) across services.
- **Acceptance:** services deploy and scale independently; end-to-end flow unchanged for the client.

## EPIC H — Model parity & housekeeping  · Effort S · optional
- [ ] ⬜ Swap ensemble `GradientBoosting` → `XGBoost` to match the plan literally; retrain, re-emit `biometric_metrics.json`. (Functionally equivalent today — low priority.)
- [ ] ⬜ Add a Tier-2 completion matrix to `README.md` reflecting this file.
- [ ] ⬜ Extend CI (`.github/workflows/ci.yml`) with jobs for each new service.

---

## Suggested delivery order
1. **A → B** (session foundation, then FIDO2 step-up) — the biggest missing Tier-2 capability.
2. **C** (Llama Guard) — high security value, independent, parallelizable.
3. **D** (TLS + at-rest encryption) — required before any non-local deployment.
4. **E → F** (real sandboxing, then real tools) — hardens and completes the agent story.
5. **G** (microservices) — architectural finish, last.
6. **H** — parity + docs, fold in opportunistically.

## Definition of "Tier 2 complete"
All of A–F shipped with tests + CI green, docs updated, and `/api/alerts/status`
`deferred[]` empty (or only listing G if intentionally staged).
