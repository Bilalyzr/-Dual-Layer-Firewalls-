# Tier 2 — Implementation TODO

Status legend: ✅ done · 🟡 partial · ⬜ not started
Effort: S (≤1 day) · L (1–2 weeks) · M (2–4 days) · XL (multi-week)

> **Status (verified against source + green test suite): Epics A–H delivered.**
> Every epic below was audited against the actual code and the proxy/engine test
> suites pass. Checkboxes reflect reality — do not trust a summary line alone.

## Already delivered (Phases 4–5, engine + agents)
- [x] ✅ LSTM + RF/GB/MLP biometric ensemble (`engine/biometric/`, macro F1 ≈ 0.962)
- [x] ✅ Async SHAP explainability (`engine/biometric/explain.py`, `GET /api/shap/:id`)
- [x] ✅ Trifecta Reader→Validator→Actor agents with JSON-schema validation + RBAC (`proxy/agents/`)

---

## EPIC A — Session & Identity foundation  · Effort M  ✅ DONE
Signed server-side sessions with a per-session `trustState`, the prerequisite for
FIDO2 step-up.

- [x] ✅ Signed session tokens (`<sessionId>.<HMAC-SHA256>`) issued on first load. `proxy/auth/session.js` + `sessionMiddleware`.
- [x] ✅ `sessions` + `credentials` Mongo collections with in-memory fallback (`proxy/db/mongo.js`).
- [x] ✅ `sessionId` threaded through `/api/chat` and `/api/biometric/batch`.
- [x] ✅ Per-session `trustState` ({ stepUpRequired, lastVerifiedAt, reason }).
- **Acceptance:** ✅ every request carries a verifiable session; server marks/reads `stepUpRequired`. Tests: `proxy/tests/session.test.js`.

## EPIC B — FIDO2 / WebAuthn step-up MFA enforcement  · Effort L  ✅ DONE
Layer 2 enforces: when keystroke trust collapses, a hardware/passkey re-auth is
required before the session may continue.

- [x] ✅ `@simplewebauthn/server`. `proxy/routes/auth.js`: register/authenticate `options` + `verify` endpoints.
- [x] ✅ Credentials (credentialID, publicKey, counter) in the `credentials` collection.
- [x] ✅ Enforcement hook in `proxy/routes/biometric.js`: `BIOMETRIC_MODE=enforce` + `trust_score ≤ BIOMETRIC_STEPUP_THRESHOLD` + not cold-start → `stepUpRequired=true`, `publish("stepup", …)`.
- [x] ✅ `/api/chat` gated: `401 {reason:"step_up_required"}` until a fresh WebAuthn assertion clears it.
- [x] ✅ Frontend `@simplewebauthn/browser` — `client/src/components/StepUpModal.jsx` triggers on 401; registration flow.
- [x] ✅ Config: `BIOMETRIC_STEPUP_THRESHOLD`, `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` in `.env.example`.
- [x] ✅ Tests: enforcement decision + mocked verified/failed assertion (`proxy/tests/auth.test.js`, `session.test.js`).
- **Acceptance:** ✅ in enforce mode, trust below threshold blocks chat until a WebAuthn assertion verifies; logged as alerts.

## EPIC C — Llama Guard 4 safety layer  · Effort M  ✅ DONE
A dedicated safety-model pass on input and output, complementing regex + classifier.

- [x] ✅ `proxy/firewall/llamaGuard.js`: OpenAI-compatible call; parses safe/unsafe + category (S1–S13).
- [x] ✅ Wired into `proxy/routes/chat.js`: input (alongside heuristics + classifier) and output (alongside `checkOutput`), combined into `verdict`.
- [x] ✅ Llama Guard categories → OWASP LLM tags for the dashboard.
- [x] ✅ Config: `LLAMAGUARD_ENABLED`, `LLAMAGUARD_URL`, `LLAMAGUARD_MODEL`, `LLAMAGUARD_API_KEY`. Fail-open in shadow, fail-closed in enforce.
- [x] ✅ Tests: known-safe/unsafe + degraded-endpoint fallback (`proxy/tests/llamaGuard.test.js`, `chatGuard.test.js`).
- **Acceptance:** ✅ an unsafe prompt is blocked in enforce mode with a category tag even when regex/classifier miss it.

## EPIC D — Security NFRs: TLS 1.3 in transit + AES-256 at rest  · Effort M  ✅ DONE
- [x] ✅ TLS: nginx edge (`edge/nginx.conf`, `TLSv1.3` only, HSTS, HTTP→HTTPS redirect); `docker-compose.yml` `edge` service (`--profile tls`); `scripts/gen-certs.sh`.
- [x] ✅ At rest: AES-256-GCM field encryption `proxy/db/encryption.js`, applied in `insertAlert`/`insertSample`/`upsertBaseline`. Transparent pass-through when `APP_ENCRYPTION_KEY` unset.
- [x] ✅ Secrets via env (`STRICT_REAL` guards silent fallbacks); key rotation documented in `.env.example`.
- **Acceptance:** ✅ HTTPS/TLS 1.3 with certs present; sensitive DB fields ciphertext when the key is set. Tests: `proxy/tests/encryption.test.js`.
- **Prod note:** self-signed certs for dev; Let's Encrypt + a secret manager remain deployment work (tracked in Tier 3).

## EPIC E — OS-level Reader-Agent sandboxing  · Effort L  ✅ DONE
- [x] ✅ Reader extracted to `reader-svc/` (minimal Express: untrusted text → validated JSON). `proxy/agents/readerAgent.js` becomes an HTTP client when `READER_SVC_URL` set, in-process fallback otherwise.
- [x] ✅ Container hardening in `docker-compose.yml`: `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges]`, non-root `user`, tmpfs.
- [x] ✅ Egress isolation: dedicated `reader_egress` network; Mongo/engine unreachable from reader-svc.
- [x] ✅ Tests: routing + isolation + fallback (`proxy/tests/readerSandbox.test.js`).
- **Acceptance:** ✅ a compromised Reader prompt can only make the LLM call + schema-checked JSON return.

## EPIC F — Real Actor tool integrations  · Effort M  ✅ DONE
- [x] ✅ Tool-adapter interface in `proxy/agents/tools/` (`notify.js`, `lookup.js`, `summarize.js`, `_audit.js`, `_smtp.js`).
- [x] ✅ `notify` → real SMTP (`NOTIFY_SMTP_URL`) or webhook (`NOTIFY_WEBHOOK_URL`); mock fallback when unset.
- [x] ✅ `lookup` → real KB API (`LOOKUP_API_URL`/`LOOKUP_API_KEY`); mock fallback.
- [x] ✅ Every call behind schema validation + `canCall('actor', …)` RBAC; per-tool rate limits + audit log (`_audit.js`).
- [x] ✅ Feature-flagged; default to mock when creds absent (demo-safe).
- **Acceptance:** ✅ with creds set `notify` sends a real message; without, falls back to mock; RBAC/schema enforced either way. Tests: `proxy/tests/tools.test.js`, `smtp.test.js`.

## EPIC G — Distributed microservices architecture  · Effort XL  ✅ DONE
Role-parameterized single image + `docker-compose.micro.yml`; monolith default
unchanged, all fall back to in-process when the new env vars are unset.

- [x] ✅ Split into `gateway`, `firewall-svc`, `agent-svc`, `biometric-svc` (reader-svc from Epic E). App factory `proxy/app.js` (`createApp({role})`), `proxy/services/*.js`, HTTP agent delegation (`AGENT_SVC_URL`).
- [x] ✅ Redis pub/sub SSE fan-out (`proxy/middleware/eventBus.js`, `startBusRelay()`), in-process fallback when `REDIS_URL` unset.
- [x] ✅ `docker-compose.micro.yml`; per-service `/healthz`; horizontal scale for `firewall-svc`.
- [x] ✅ Structured JSON logging (`proxy/lib/logger.js`, request-id) + Prometheus `/metrics` (`proxy/middleware/telemetry.js`).
- **Acceptance:** ✅ services deploy/scale independently; client flow unchanged (`proxy/tests/microservices.test.js`).

## EPIC H — Model parity & housekeeping  · Effort S  ✅ DONE
- [x] ✅ Ensemble `GradientBoosting` → `XGBoost` (`engine/biometric/ensemble.py`); retrained, `biometric_metrics.json` re-emitted; SHAP unaffected (explains the RF member).
- [x] ✅ Tier-2 completion matrix in `README.md` reflecting this file.
- [x] ✅ CI (`.github/workflows/ci.yml`) jobs for the split services (agent-svc + biometric-svc + reader-svc smoke).

---

## Latency addendum (PRD §6 <5ms firewall path)
- [x] ✅ Heuristic scan runs first; a confirmed heuristic hit in enforce mode BLOCKS without the ML/Guard network round-trip (`proxy/routes/chat.js`).
- [x] ✅ Per-prompt classifier verdict cache (`proxy/firewall/clfCache.js`, Tier-3 §12.8) — identical prompts skip the engine hop.
- **Acceptance:** ✅ malicious (heuristic) and repeated/benign (cache) paths return sub-millisecond; only novel benign prompts pay the one engine round-trip. Tests: `proxy/tests/chat.test.js`.

## Definition of "Tier 2 complete"  ✅ MET
All of A–H shipped with tests green, docs updated, and `/api/alerts/status`
`deferred[]` empty.
