# Tier 3 — Implementation TODO

Advanced enhancements distilled from `project_documentation.md` §12
("Advanced Future Enhancement Recommendations"), fine-tuned into a
dependency-sequenced, buildable backlog.

Status legend: ✅ done · 🟡 partial · ⬜ not started
Effort: S (≤1 day) · M (2–4 days) · L (1–2 weeks) · XL (multi-week)
Priority: 🔴 high · 🟡 medium · 🟢 low

> **Baseline:** Tier 1 + Tier 2 (Epics A–H) are delivered — 164 tests green,
> `/api/alerts/status.deferred` empty. Tier 3 builds on the existing seams:
> Redis event bus, `telemetry.js` `/metrics`, `logger.js`, the `alerts`
> collection + `insertAlert`, and the per-tool rate limiter in
> `agents/tools/_audit.js`. Reuse these — do not rebuild them.

---

# WAVE 1 — IP Forensics & Automated Threat Response  🔴\

*The user-requested capability (§12.1). Everything network-level depends on Epic A.*

## EPIC A — IP context foundation  · Effort M · 🔴 · (prereq for B, C, D, E)
Capture the true client IP on every request and thread it into the alert record.
Nothing downstream (GeoIP, banning, SIEM) works without a trustworthy source IP.

- [ ] ⬜ `proxy/middleware/ipContext.js`: parse `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP`, walk the proxy chain, resolve the real client IP. Honor a `TRUSTED_PROXIES` CIDR allow-list so a spoofed `XFF` can't forge the IP (Express `trust proxy` set correctly behind the nginx edge).
- [ ] ⬜ Attach `req.ipContext = { clientIp, realIp, proxyChain }` and propagate it via the `x-request-id`-style header across microservices (`lib/forward.js`).
- [ ] ⬜ Extend the alert schema + `insertAlert` (`proxy/db/mongo.js`) with a `forensics` sub-document (start with IP fields only; enrichment fills the rest in Epic B). Add `forensics.*` to `SENSITIVE_ALERT_FIELDS` where PII (Epic D encryption already covers alerts).
- [ ] ⬜ Surface source IP in the threat feed (`ThreatFeed.jsx`) behind a redaction toggle.
- [ ] ⬜ Config: `TRUSTED_PROXIES`, `IP_FORENSICS_ENABLED`.
- [ ] ⬜ Tests: XFF chain parsing, spoof rejection when source ∉ trusted proxies, forensics field persisted + encrypted.
- **Acceptance:** every BLOCK/THREAT alert records a tamper-resistant client IP; a forged `X-Forwarded-For` from an untrusted hop is ignored.

## EPIC B — Threat enrichment pipeline  · Effort L · 🔴 · depends on A
Turn a bare IP into actionable intelligence. All lookups async + cached + fail-open.

- [ ] ⬜ `proxy/forensics/geoip.js`: MaxMind GeoLite2 (local `.mmdb`, no per-request network call) → country, city, ISP, org.
- [ ] ⬜ `proxy/forensics/asn.js`: ASN + `/24` CIDR + abuse contact (offline MaxMind ASN db primary; `bgpview.io` optional fallback).
- [ ] ⬜ `proxy/forensics/reputation.js`: AbuseIPDB score + previous-offense count; VPN/Tor/proxy flag via `proxycheck.io` or Tor exit-node list. **Cache in Redis** (TTL) — never block the request path on an external API.
- [ ] ⬜ Enrichment runs **out-of-band** (post-response, on the event bus) so it never adds request latency; result patched onto the stored alert.
- [ ] ⬜ Config: `MAXMIND_DB_PATH`, `ABUSEIPDB_KEY`, `PROXYCHECK_KEY`, `ENRICHMENT_CACHE_TTL`. Mock/skip cleanly when keys absent (demo-safe, matches Tier-2 fallback convention).
- [ ] ⬜ Tests: enrichment shape matches the §12.1 schema; degraded API → alert still stored without forensics; cache hit path.
- **Acceptance:** a flagged IP yields `{ geoip, asn, vpnDetected, abuseScore, previousOffenses }` matching the documented schema; enrichment adds **zero** request-path latency.

## EPIC C — Automated response engine  · Effort L · 🔴 · depends on A, B
Move from *observe* to *act*: block repeat offenders automatically.

- [ ] ⬜ `proxy/middleware/ipGuard.js` (edge middleware): reject requests from blacklisted IPs/CIDRs before the pipeline runs. Backed by a **Redis sorted set** (score = offense count, member = IP).
- [ ] ⬜ Auto-blacklist rule: N+ threats from one IP within a window → temp ban (TTL); repeat → escalate. Generalize the sliding-window logic already in `agents/tools/_audit.js`.
- [ ] ⬜ CIDR range ban: multiple offenders in one `/24` → ban the range (in-memory CIDR trie, hydrated from Redis).
- [ ] ⬜ Honeypot mode (`RESPONSE_MODE=honeypot`): serve delayed fake responses instead of a hard block, to waste attacker time and gather more signal.
- [ ] ⬜ Per-user/IP rate limiting at the gateway (§12.8 item — folded in here since it shares the store).
- [ ] ⬜ Config: `AUTO_BAN_THRESHOLD`, `AUTO_BAN_WINDOW`, `AUTO_BAN_TTL`, `RESPONSE_MODE` (block|honeypot|off). **Default off** in shadow, matching firewall semantics.
- [ ] ⬜ Ops: an unban endpoint + a "kill switch" flag; every auto-ban emits an alert.
- [ ] ⬜ Tests: N-strikes → ban, ban expiry, CIDR escalation, honeypot response shape, false-positive unban.
- **Acceptance:** an IP that trips the threshold is blocked on its next request without human action; bans expire; a whole `/24` can be banned; all actions are logged and reversible.

---

# WAVE 2 — Threat Intelligence & Network Defenses  🟡
*Enterprise SOC integration and edge hardening. Value scales with deployment size.*

## EPIC D — SIEM & threat-intelligence sharing  · Effort M · 🟡 · depends on A
- [ ] ⬜ `proxy/integrations/siem.js`: push every BLOCK event to a configurable webhook (Splunk HEC / Elastic / Sentinel / Sumo). Reuse the event bus — a SIEM relay is just another subscriber.
- [ ] ⬜ `proxy/integrations/stix.js`: export indicators as STIX 2.1; optional TAXII pull endpoint for community feeds.
- [ ] ⬜ Attack fingerprinting: hash (prompt structure + timing + evasion technique) → signature; auto-block known signatures **before** ML inference (cost saver).
- [ ] ⬜ Threat-correlation query: same IP / different users, same typing pattern / different IPs → coordinated-campaign flag.
- [ ] ⬜ Config: `SIEM_WEBHOOK_URL`, `SIEM_FORMAT`, `STIX_ENABLED`.
- [ ] ⬜ Tests: webhook fired on block, STIX document validates, signature cache hit short-circuits ML.
- **Acceptance:** every block reaches the configured SIEM; a repeat attack pattern is blocked by signature without an ML call.

## EPIC E — Advanced network-level defenses  · Effort L · 🟡 · depends on B · ⚠️ privacy-gated
- [ ] ⬜ Geo-fencing: allow/deny by country/ASN at the gateway (`GEOFENCE_MODE`, `GEOFENCE_LIST`).
- [ ] ⬜ DNSBL check (Spamhaus/Barracuda) at the edge for known-bad IPs.
- [ ] ⬜ TLS fingerprinting (JA3/JA4) to spot automated/bot clients — requires exposing handshake data from the nginx edge.
- [ ] ⬜ Request-cadence analysis: too-fast / too-regular timing → bot score feeding the auto-response engine (Epic C).
- [ ] ⬜ Client-side fingerprinting (canvas/WebGL/audio) — **behind explicit consent (Epic I)**; personal data under GDPR.
- [ ] ⬜ Tests: geofence deny, DNSBL hit, cadence bot-score threshold.
- **Acceptance:** traffic from a denied geo/ASN is refused; a scripted client with robotic cadence is scored and throttled.

---

# WAVE 3 — ML, Biometrics, Ops & Compliance  🟢
*Depth and enterprise-readiness. Parallelizable; sequence by team interest.*

## EPIC F — Adversarial ML hardening  · Effort L · 🟡
- [ ] ⬜ Ensemble prompt classifier: LogReg + SVM + RandomForest + fine-tuned DistilBERT soft-vote, replacing the single TF-IDF+LogReg (`engine/classifier/`).
- [ ] ⬜ Adversarial-training loop: feed the existing 5% low-confidence sample queue back into retraining — closes the feedback loop the sampler already opened.
- [ ] ⬜ Semantic embedding firewall: sentence-transformer embeddings, flag outliers in embedding space (catches novel injections regex misses → covers OWASP LLM08 gap noted in Appendix B).
- [ ] ⬜ Prompt canaries: invisible watermark in system prompts; detect exfiltration in outputs (`outputCheck.js`).
- [ ] ⬜ Cross-lingual detection: extend beyond English-only regex.
- **Acceptance:** an evasion that fools the current LogReg is caught by an ensemble peer or the embedding-outlier check; a leaked system prompt trips its canary.

## EPIC G — Biometric enhancements  · Effort L · 🟢 · ⚠️ consent-gated
- [ ] ⬜ Mouse-dynamics layer (speed, click, scroll) added to the trust model.
- [ ] ⬜ Transformer-based sequence model replacing the LSTM (`engine/biometric/lstm_model.py`).
- [ ] ⬜ Online/incremental baseline adaptation — handle natural typing drift without full re-enrollment.
- [ ] ⬜ Multi-modal fusion: keystroke + mouse + session → single trust score.
- [ ] ⬜ Touch biometrics (pressure/area/swipe) for mobile.
- **Acceptance:** trust score fuses ≥2 behavioral channels; baseline adapts to gradual drift without a false step-up storm.

## EPIC H — Observability & monitoring  · Effort M · 🟡
- [ ] ⬜ OTLP export: wire the existing `/metrics` seam (`telemetry.js`) to Grafana/Datadog — the seam already exists, this is connection work.
- [ ] ⬜ Distributed tracing (Jaeger/Zipkin) across gateway → firewall-svc → engine → LLM; the `x-request-id` propagation is already in place.
- [ ] ⬜ Alerting pipeline (PagerDuty/OpsGenie) on high-severity / coordinated-attack events.
- [ ] ⬜ SLA dashboard: availability + latency percentiles + error rate per service.
- [ ] ⬜ System-metric anomaly detection (CPU/mem/request-pattern) for DDoS early warning.
- **Acceptance:** traces span the full microservice chain; a Sev-1 threat pages on-call; per-service SLOs are visible.

## EPIC I — Compliance & governance  · Effort M · 🟡 · (unblocks E & G enforcement)
- [ ] ⬜ Consent management: explicit opt-in/opt-out for keystroke + fingerprint capture — **legal prerequisite** for enforcing biometrics or client fingerprinting.
- [ ] ⬜ GDPR right-to-erasure pipeline for biometric data (Category-3 special data).
- [ ] ⬜ Data-retention TTLs on `alerts` / `samples` / `baselines`.
- [ ] ⬜ Append-only, hash-chained audit log (tamper-evident).
- [ ] ⬜ SOC 2 Type II evidence-collection automation.
- **Acceptance:** a user can withdraw consent and have biometric data erased on request; security logs are tamper-evident; retention is enforced automatically.

## EPIC J — Scalability & performance  · Effort L · 🟢
- [ ] ⬜ Kubernetes Helm charts (auto-scale, rolling updates, PDB) — the microservice split (Epic G/Tier 2) is done; k8s is the next target.
- [ ] ⬜ Edge caching of classifier decisions for repeated benign prompts (LRU + TTL).
- [ ] ⬜ Optional GPU inference service for DistilBERT / Llama Guard (unlocks 10k+ rps).
- [ ] ⬜ Formalize the circuit-breaker pattern across all backends (partial today via Llama-Guard degrade).
- **Acceptance:** the stack deploys to k8s and auto-scales; repeated benign prompts skip ML via cache; a downed backend degrades gracefully everywhere.

## EPIC K — Advanced agent security  · Effort L · 🟢
- [ ] ⬜ Kill switch: system-wide emergency halt of ALL agent actions (also referenced by Epic C ops).
- [ ] ⬜ Tool-capability attestation: cryptographically signed capabilities so injection can't escalate an agent's permission set.
- [ ] ⬜ Multi-agent consensus: N-of-M agreement before high-risk actions (delete/payment).
- [ ] ⬜ Micro-VM sandbox (gVisor/Firecracker) for code-execution tools — stronger than today's Docker isolation on `reader-svc`.
- [ ] ⬜ Automated red-teaming: scheduled runs of `prompts/prompt_injection_attacks.json` in CI to catch regressions.
- **Acceptance:** high-risk actions need quorum; a compromised agent cannot escalate capabilities; nightly red-team run gates the pipeline.

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
