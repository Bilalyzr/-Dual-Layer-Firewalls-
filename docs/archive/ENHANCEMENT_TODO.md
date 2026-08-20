# Enhancement TODO — derived from `MODULE_ENHANCEMENTS.md`

Tracking the enhancement work. Rule: **additive only** — the existing green suites
(proxy 266/266, engine 59, client build) must stay green. New behavior ships behind
flags/consent, never by breaking a passing path.

Status: ⬜ todo · 🟦 in progress · ✅ done

## Wave 1 — Consent gate + wire the dead capture hooks (§1, §2 minor)
- ✅ Backend consent HTTP route (`proxy/routes/consent.js`) — GET/POST, mounted in all roles
- ✅ Server-side consent gate on mouse + touch routes (defense-in-depth, matches fingerprint)
- ✅ Client consent helper (`client/src/lib/consent.js`)
- ✅ Consent banner/settings UI (`client/src/components/ConsentBanner.jsx`)
- ✅ Wire `useMouseCapture` / `useTouchCapture` / `fingerprint` into `App.jsx` behind consent
- ✅ `SlaPanel.jsx` consuming `/api/sla` (p50/p95/p99, availability, anomalies)
- ✅ Touch-velocity fix — refresh `last.t` on each move (§1 minor)
- ✅ Route tests: cold-start, scoring, consent-403 (`proxy/tests/biometricRoutes.test.js`)
- ✅ Styles for consent banner + SLA panel

## Wave 2 — Persist + fuse behavioral channels (§2)
- ✅ Persist mouse/touch baselines to Mongo (`behavior_baselines`, in-mem fallback) via
  `getBehaviorBaseline`/`upsertBehaviorBaseline` — routes no longer use per-process Maps
- ✅ Feed mouse/touch scores into the trust signal driving `requireStepUp`
  (`firewall/trustFusion.js`; keystroke route fuses aux channels into the step-up decision).
  No-op when no usable aux channel → existing enforce/collapse behavior byte-identical.
- ✅ `engine/biometric/fusion.py` — already implemented AND covered by
  `engine/tests/test_epicG_biometric.py`. Deliberately NOT called on the Node hot path:
  it's identical late-fusion math and a network hop would break the sub-5ms goal. Node
  mirrors it in `trustFusion.js`; the Python module stays for offline/engine analysis.

Env flag: `BIOMETRIC_FUSION=off` reverts to keystroke-only fusion (escape hatch).

## Wave 3 — Engine hardening + CI (§3, §5)
- ✅ Resolve numpy/pyarrow ABI so `engine/tests` runs locally. Root cause was the
  conda *base* env carrying pyarrow/bottleneck/numexpr built for numpy 1.x (sklearn
  imports them). Fixed by rebuilding those accelerators against numpy 2 (no numpy
  downgrade) + installing missing project deps (xgboost, shap). Documented the gotcha
  in `engine/requirements.txt`. Local: **59 engine tests pass**. CI already runs the suite.
- ✅ Warm ensemble + embedding-firewall at startup (`_warm_models()` in app.py; gated by
  `ENGINE_WARM_MODELS`, fail-open). Removes the first-request model-load latency spike.
- ✅ Surface `degraded` flag in `ClassifyResponse` — embedding firewall now records why it
  returned 0.0 (`status()`), so a broken/unfitted model is distinguishable from "no outlier".

## Wave 4 — Targeted firewall + polish (§4)
- ✅ Per-request/per-agent canary (Trifecta custom system prompts) — `firewall/canary.js`
  now mints a FRESH token per LLM call and scans ALL live tokens. Reader + Actor inject
  their own canary into their custom system prompts (`injectCanaryMessages`), and the
  orchestrator BLOCKS with `blockReason:"canary_leak"` when either agent leaks it. Closes
  the gap where Trifecta agents' prompt leaks were invisible. Tests: `proxy/tests/canaryPerAgent.test.js`.
- ✅ Native-script cross-lingual rules + transliteration pass — `firewall/heuristics.js` adds
  native-script (non-Latin) instruction-override rules for RU (Cyrillic), HI (Devanagari),
  AR (Arabic), JA, KO on top of the existing romanized set, plus an NFKC+NFD normalization
  pass that folds full-width/compatibility forms and strips Latin/Greek/Cyrillic combining
  marks (defeats "ｉｇｎｏｒｅ" and "ígnóré" evasion) while leaving native vowel signs intact.
  Tests: `proxy/tests/epicF.test.js`.
- ✅ Reconcile `TIER3_TODO.md` status legend with reality — baseline test counts refreshed;
  Tier 3 marked complete (all Epics A–K delivered, 266 proxy + 59 engine tests green).

## Future work — known bugs / gaps
- ✅ **SLA panel now fed by live traffic** (Epic H wiring gap closed). `requestLogger`'s
  `res.on("finish")` handler now calls `recordRequest(latencyMs, res.statusCode)` (imported
  from `../observability/sla.js`) right after computing `latencyMs`, so p50/p95/p99,
  availability, error rate, and request rate all reflect real traffic instead of flatlining.
  Wired in the shared `requestLogger` (runs in every role) per the scope note; each service
  keeps its own in-process window, multi-instance aggregation still via the OTLP seam. Test:
  `epicRemaining.test.js` drives a request through an app mounting `requestLogger` and asserts
  `slaSnapshot().requestCount` increases (was 266 → 267 proxy tests green).

<details><summary>Original gap writeup (now resolved)</summary>

- ⬜ **SLA panel not fed by live traffic** (Epic H wiring gap). The SLA math in
  `proxy/observability/sla.js` is correct and unit-tested (`epicRemaining.test.js`
  calls `recordRequest()` directly), but **nothing on the live request path ever
  calls `recordRequest()`**. `requestLogger` (`proxy/lib/logger.js`, `res.on("finish")`)
  already computes `latencyMs` but only writes it to a log line; `metricsMiddleware`
  (`proxy/middleware/telemetry.js`) only bumps Prometheus counters. Result: `_requests[]`
  stays empty in production, so `GET /api/sla` → `SlaPanel.jsx` always shows
  **p50/p95/p99 = 0.0ms, availability 100%, error rate 0%** (flatlined); only the
  CPU/memory anomaly half is live (and `reqRate` reads the same empty array → always 0).
  - **Fix:** in `requestLogger`'s finish handler, after computing `latencyMs`, call
    `recordRequest(latencyMs, res.statusCode)` (import from `../observability/sla.js`).
    One line makes latency/availability/error-rate/request-rate reflect real traffic.
  - **Test:** add a case asserting that driving a request through the app populates
    `slaSnapshot()` (requestCount > 0, non-zero p50) — currently only the pure function
    is covered, which is why the wiring gap slipped through.
  - **Scope note:** in the distributed topology each service keeps its own in-process
    window, so wire `recordRequest` in the shared `requestLogger` (runs in every role)
    rather than per-route; multi-instance aggregation still goes through the OTLP seam.

</details>
