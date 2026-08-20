# Tier 3 — Implementation TODO

Advanced enhancements distilled from `project_documentation.md` §12
("Advanced Future Enhancement Recommendations"), fine-tuned into a
dependency-sequenced, buildable backlog.

Status legend: ✅ done · 🟡 partial · ⬜ not started
Effort: S (≤1 day) · M (2–4 days) · L (1–2 weeks) · XL (multi-week)
Priority: 🔴 high · 🟡 medium · 🟢 low

> **Baseline:** Tier 1 + Tier 2 + Tier 3 (Epics A–K) are delivered — 266 proxy +
> 59 engine tests green, `/api/alerts/status.deferred` empty. Tier 3 builds on the existing seams:
> Redis event bus, `telemetry.js` `/metrics`, `logger.js`, the `alerts`
> collection + `insertAlert`, and the per-tool rate limiter in
> `agents/tools/_audit.js`. Reuse these — do not rebuild them.

---

# WAVE 1 — IP Forensics & Automated Threat Response  🔴\



*The user-requested capability (§12.1). Everything network-level depends on Epic A.*

## EPIC A — IP context foundation  · Effort M · 🔴 · (prereq for B, C, D, E)
Capture the true client IP on every request and thread it into the alert record.
Nothing downstream (GeoIP, banning, SIEM) works without a trustworthy source IP.

- [x] ✅ `proxy/middleware/ipContext.js`: parse `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP`, walk the proxy chain, resolve the real client IP. Honor a `TRUSTED_PROXIES` CIDR allow-list so a spoofed `XFF` can't forge the IP (Express `trust proxy` set correctly behind the nginx edge).
- [x] ✅ Attach `req.ipContext = { clientIp, realIp, proxyChain }` and propagate it via the `x-request-id`-style header across microservices (`lib/forward.js`).
- [x] ✅ Extend the alert schema + `insertAlert` (`proxy/db/mongo.js`) with a `forensics` sub-document (start with IP fields only; enrichment fills the rest in Epic B). Add `forensics.*` to `SENSITIVE_ALERT_FIELDS` where PII (Epic D encryption already covers alerts).
- [x] ✅ Surface source IP in the threat feed (`ThreatFeed.jsx`) behind a redaction toggle.
- [x] ✅ Config: `TRUSTED_PROXIES`, `IP_FORENSICS_ENABLED`.
- [x] ✅ Tests: XFF chain parsing, spoof rejection when source ∉ trusted proxies, forensics field persisted + encrypted.
- **Acceptance:** every BLOCK/THREAT alert records a tamper-resistant client IP; a forged `X-Forwarded-For` from an untrusted hop is ignored.

## EPIC B — Threat enrichment pipeline  · Effort L · 🔴 · depends on A
Turn a bare IP into actionable intelligence. All lookups async + cached + fail-open.

- [x] ✅ `proxy/forensics/geoip.js`: MaxMind GeoLite2 (local `.mmdb`, no per-request network call) → country, city, ISP, org.
- [x] ✅ `proxy/forensics/asn.js`: ASN + `/24` CIDR + abuse contact (offline MaxMind ASN db primary; `bgpview.io` optional fallback).
- [x] ✅ `proxy/forensics/reputation.js`: AbuseIPDB score + previous-offense count; VPN/Tor/proxy flag via `proxycheck.io` or Tor exit-node list. **Cache in Redis** (TTL) — never block the request path on an external API.
- [x] ✅ Enrichment runs **out-of-band** (post-response, on the event bus) so it never adds request latency; result patched onto the stored alert.
- [x] ✅ Config: `MAXMIND_DB_PATH`, `ABUSEIPDB_KEY`, `PROXYCHECK_KEY`, `ENRICHMENT_CACHE_TTL`. Mock/skip cleanly when keys absent (demo-safe, matches Tier-2 fallback convention).
- [x] ✅ Tests: enrichment shape matches the §12.1 schema; degraded API → alert still stored without forensics; cache hit path.
- **Acceptance:** a flagged IP yields `{ geoip, asn, vpnDetected, abuseScore, previousOffenses }` matching the documented schema; enrichment adds **zero** request-path latency.

## EPIC C — Automated response engine  · Effort L · 🔴 · depends on A, B
Move from *observe* to *act*: block repeat offenders automatically.

- [x] ✅ `proxy/middleware/ipGuard.js` (edge middleware): reject requests from blacklisted IPs/CIDRs before the pipeline runs. Backed by a **Redis sorted set** (score = offense count, member = IP).
- [x] ✅ Auto-blacklist rule: N+ threats from one IP within a window → temp ban (TTL); repeat → escalate. Generalize the sliding-window logic already in `agents/tools/_audit.js`.
- [x] ✅ CIDR range ban: multiple offenders in one `/24` → ban the range (in-memory CIDR trie, hydrated from Redis).
- [x] ✅ Honeypot mode (`RESPONSE_MODE=honeypot`): serve delayed fake responses instead of a hard block, to waste attacker time and gather more signal.
- [x] ✅ Per-user/IP rate limiting at the gateway (§12.8 item — folded in here since it shares the store).
- [x] ✅ Config: `AUTO_BAN_THRESHOLD`, `AUTO_BAN_WINDOW`, `AUTO_BAN_TTL`, `RESPONSE_MODE` (block|honeypot|off). **Default off** in shadow, matching firewall semantics.
- [x] ✅ Ops: an unban endpoint + a "kill switch" flag; every auto-ban emits an alert.
- [x] ✅ Tests: N-strikes → ban, ban expiry, CIDR escalation, honeypot response shape, false-positive unban.
- **Acceptance:** an IP that trips the threshold is blocked on its next request without human action; bans expire; a whole `/24` can be banned; all actions are logged and reversible.

---

# WAVE 2 — Threat Intelligence & Network Defenses  🟡
*Enterprise SOC integration and edge hardening. Value scales with deployment size.*

## EPIC D — SIEM & threat-intelligence sharing  · Effort M · 🟡 · depends on A
- [x] ✅ `proxy/integrations/siem.js`: push every BLOCK event to a configurable webhook (Splunk HEC / Elastic / Sentinel / Sumo). Reuse the event bus — a SIEM relay is just another subscriber.
- [x] ✅ `proxy/integrations/stix.js`: export indicators as STIX 2.1; optional TAXII pull endpoint for community feeds.
- [x] ✅ Attack fingerprinting: hash (prompt structure + timing + evasion technique) → signature; auto-block known signatures **before** ML inference (cost saver).
- [x] ✅ Threat-correlation query: same IP / different users, same typing pattern / different IPs → coordinated-campaign flag.
- [x] ✅ Config: `SIEM_WEBHOOK_URL`, `SIEM_FORMAT`, `STIX_ENABLED`.
- [x] ✅ Tests: webhook fired on block, STIX document validates, signature cache hit short-circuits ML.
- **Acceptance:** every block reaches the configured SIEM; a repeat attack pattern is blocked by signature without an ML call.

## EPIC E — Advanced network-level defenses  · Effort L · 🟡 · depends on B · ⚠️ privacy-gated
- [x] ✅ Geo-fencing: allow/deny by country/ASN at the gateway (`GEOFENCE_MODE`, `GEOFENCE_LIST`).
- [x] ✅ DNSBL check (Spamhaus/Barracuda) at the edge for known-bad IPs.
- [x] ✅ TLS fingerprinting (JA3/JA4) to spot automated/bot clients — requires exposing handshake data from the nginx edge.
- [x] ✅ Request-cadence analysis: too-fast / too-regular timing → bot score feeding the auto-response engine (Epic C).
- [x] ✅ Client-side fingerprinting (canvas/WebGL/audio) — `client/src/lib/fingerprint.js` + `proxy/routes/fingerprint.js`, behind the Epic I consent gate (server-side + client-side).
- [x] ✅ Tests: geofence deny, DNSBL hit, cadence bot-score threshold.
- **Acceptance:** traffic from a denied geo/ASN is refused; a scripted client with robotic cadence is scored and throttled.

---

# WAVE 3 — ML, Biometrics, Ops & Compliance  🟢
*Depth and enterprise-readiness. Parallelizable; sequence by team interest.*

## EPIC F — Adversarial ML hardening  · Effort L · 🟡
- [x] ✅ Ensemble prompt classifier: LogReg + calibrated SVM + RandomForest soft-vote (`engine/classifier/ensemble.py`), wired into `/classify` (falls back to single LogReg).
- [x] ✅ Adversarial-training loop: `engine/classifier/adversarial_train.py` pulls reviewed samples from Mongo, augments the dataset, and retrains.
- [x] ✅ Semantic embedding firewall: DistilBERT outlier detection (`engine/classifier/embedding_firewall.py`, Mahalanobis distance from benign centroid). Enabled via `EMBEDDING_FIREWALL_ENABLED=true`.
- [x] ✅ Prompt canaries: `proxy/firewall/canary.js` — invisible watermark injected into the system prompt; canary-leak detection in the outbound check.
- [x] ✅ Cross-lingual detection: heuristics extended to ES/FR/DE/PT/HI/ZH/RU/AR instruction-override patterns.
- [x] ✅ Tests: canary leak/false-positive + 7-language cross-lingual detection (`proxy/tests/epicF.test.js`, 14 tests).
- **Acceptance:** ✅ an evasion that fools the current LogReg is caught by an ensemble peer or the embedding-outlier check; a leaked system prompt trips its canary.

## EPIC G — Biometric enhancements  · Effort L · 🟢 · ⚠️ consent-gated
- [x] ✅ Mouse-dynamics layer (speed, click, cadence, turn-rate): `client/src/hooks/useMouseCapture.js` + `proxy/routes/mouse.js` + `engine/biometric/fusion.py`.
- [x] ✅ Transformer-based sequence model: `engine/biometric/transformer_model.py` (2-layer Transformer encoder, mean-pooled → 16-d embed; drop-in via `USE_TRANSFORMER=true`).
- [x] ✅ Online/incremental baseline adaptation: `engine/biometric/online.py` (EWMA, α=0.05 — conservative).
- [x] ✅ Multi-modal fusion: `engine/biometric/fusion.py` — weighted late fusion of keystroke + mouse + session (8 tests).
- [x] ✅ Touch biometrics (pressure/area/swipe): `client/src/hooks/useTouchCapture.js` + `proxy/routes/touch.js`. Works on touchscreens/tablets; inert on desktop.
- **Acceptance:** ✅ trust score fuses ≥2 behavioral channels; baseline adapts to gradual drift without a false step-up storm.

## EPIC H — Observability & monitoring  · Effort M · 🟡
- [x] ✅ OTLP export: `proxy/observability/otel.js` wires to an OTLP collector (lazy-loads @opentelemetry/*; no-op when `OTEL_EXPORTER_OTLP_ENDPOINT` unset).
- [x] ✅ Distributed tracing: `withSpan()` helper + resource attributes; `x-request-id` propagation already in place.
- [x] ✅ Alerting pipeline: `proxy/observability/alerting.js` — PagerDuty/OpsGenie/generic webhook, severity-gated.
- [x] ✅ SLA dashboard: `proxy/observability/sla.js` + `proxy/routes/sla.js` — latency p50/p95/p99 + availability + error rate over a rolling window, exposed at `/api/sla`.
- [x] ✅ System-metric anomaly detection: `sla.js sampleSystemMetrics()` — CPU load, memory %, request-rate via Node `os`; flags anomalies (CPU/mem/request-rate thresholds) for DDoS early warning.
- **Acceptance:** ✅ traces span the full chain (when collector configured); a Sev-1 threat pages on-call (when webhook configured); per-service SLOs visible via OTLP.

## EPIC I — Compliance & governance  · Effort M · 🟡 · (unblocks E & G enforcement)
- [x] ✅ Consent management: `proxy/compliance/consent.js` — per-category opt-in/opt-out + `requireConsent` middleware gate.
- [x] ✅ GDPR right-to-erasure: `proxy/compliance/erasure.js` — purges keystroke baselines + adaptive state; returns a receipt.
- [x] ✅ Data-retention TTLs: `proxy/compliance/retention.js` — sweep on alerts/samples/baselines/biometric_events (env-tunable).
- [x] ✅ Append-only, hash-chained audit log: `proxy/compliance/auditChain.js` — SHA-256 chained, tamper-detection verified (15 tests).
- [x] ✅ SOC 2 Type II evidence-collection automation: `proxy/compliance/soc2.js` — gathers audit-chain integrity, consent, retention, encryption, RBAC, kill-switch into a structured report (`collectEvidence()` + `evidenceSummary()`).
- **Acceptance:** ✅ a user can withdraw consent and have biometric data erased on request; security logs are tamper-evident; retention is enforced automatically.

## EPIC J — Scalability & performance  · Effort L · 🟢
- [x] ✅ Kubernetes Helm charts: `deploy/helm/dual-layer-firewall/` (Chart.yaml + values.yaml — HPA, PDB, resources, ingress).
- [x] ✅ Edge caching of classifier decisions: `proxy/firewall/classifierCache.js` (LRU + TTL, never caches threats).
- [x] ✅ Optional GPU inference service: `gpu-engine/Dockerfile` (CUDA base for DistilBERT/Llama Guard) + `proxy/firewall/gpuRouter.js` (routes to GPU svc when `INFERENCE_SVC_URL` set; CPU fallback via circuit breaker). Needs GPU hardware to accelerate; CPU fallback works.
- [x] ✅ Circuit-breaker pattern: `proxy/firewall/circuitBreaker.js` (closed/open/half-open, reusable `withBreaker`).
- **Acceptance:** ✅ the stack deploys to k8s (chart ready); repeated benign prompts skip ML via cache; a downed backend degrades gracefully.

## EPIC K — Advanced agent security  · Effort L · 🟢
- [x] ✅ Kill switch: `proxy/agents/killSwitch.js` — engage/disengage, hash-chained into the audit log.
- [x] ✅ Tool-capability attestation: `proxy/agents/attestation.js` — HMAC-signed capabilities; injection can't forge an escalation.
- [x] ✅ Multi-agent consensus: `proxy/agents/consensus.js` — N-of-M agreement for high-risk tools.
- [x] ✅ Micro-VM sandbox: `reader-svc/docker-compose.gvisor.yml` (gVisor `runsc` runtime override) + `reader-svc/firecracker.json` (KVM-level Firecracker VM config). Defense-in-depth on top of the Tier 2 EPIC E Docker isolation. Requires gVisor/Firecracker installed on the host.
- [x] ✅ Automated red-teaming: `scripts/redteam.js` — fires the full attack battery, reports BLOCK/LEAK, CI-gateable (`EXIT_ON_LEAK=1`).
- **Acceptance:** ✅ high-risk actions need quorum; a compromised agent cannot escalate capabilities; nightly red-team run gates the pipeline.

---

## Suggested delivery order
1. **A → B → C** (Wave 1) — the requested IP forensics + auto-response. Highest priority; strictly sequential.
2. **D**, then **E** (Wave 2) — SIEM export is independent and quick; network defenses build on enrichment. **E and G need I's consent work before *enforcement*.**
3. **I** early-ish — it unblocks enforcement of E and G, so pull it forward if biometric/fingerprint enforcement is in scope.
4. **F / H / J / K** (Wave 3) — parallelizable; sequence by team interest and deployment stage. **H** and **J** are mostly "connect existing seams" and give fast enterprise wins.

## Quick wins (low effort, high signal — do first if you want momentum)
- OTLP wiring (Epic H) — seam already exists.
- SIEM webhook (Epic D) — one event-bus subscriber.
- Attack-fingerprint cache (Epic D) — cuts ML cost immediately.
- Redis auto-blacklist (Epic C) — Redis is already a dependency.

## Definition of "Tier 3 complete"
Wave 1 (A–C) shipped with tests + CI green and forensics visible in the dashboard;
Wave 2 (D–E) integrated with at least one SIEM and consent-gated where required;
Wave 3 epics delivered or explicitly deferred with rationale. Privacy-gated items
(E client-fingerprinting, G biometrics enforcement) must not ship before Epic I consent.

## ✅ Status: COMPLETE (2026-07-31)
All Epics A–K delivered. Privacy-gated items (E client-fingerprinting, G biometrics)
ship behind the Epic I consent gate (server-side + client-side). Suites green: **266
proxy tests**, **59 engine tests**, client build. Every epic header's 🔴/🟡/🟢 mark is a
**priority** tag (per the legend), not a status — all work items below them are `[x] ✅`.
