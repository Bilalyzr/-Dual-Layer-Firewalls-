# Which Modules Need Enhancement

**Project:** Unified Dual-Layer AI Firewall & Behavioral Zero-Trust Platform
**Assessed:** 2026-07-29 · against `main` @ `fb7059e` + uncommitted Wave-3 work
**Baseline health:** proxy suite **236/236 green**, client builds clean, monolith runs.

This document is an honest, prioritized map of where the codebase is thin and what
to enhance next. It is scoped to what actually exists in the tree today — not the
aspirational roadmap in `TIER3_TODO.md` (which marks everything ✅ even where the
front-end never calls it).

Legend — Priority: 🔴 high · 🟡 medium · 🟢 low · Effort: S (≤1d) · M (2–4d) · L (1–2w)

---

## 0. Bug fixed in this pass ✅

**`proxy/app.js` — microservice role mounting gap.** The new Epic E/G/H routes
(`/api/biometric/mouse`, `/touch`, `/fingerprint`, `/api/sla`) were mounted **only**
in the `all` (monolith) role. In distributed mode the `biometric` and `gateway`
roles never mounted them, so every one of those endpoints returned **404 in any
multi-service deployment** while working fine in the monolith. Fixed by mounting the
behavioral sub-routes in the `biometric` role and the SLA read-model in the `gateway`
role. Verified: `tests/microservices.test.js` 8/8 still green.

---

## 1. Client dashboard (`client/src`) — 🔴 highest-value gap

The most impactful enhancement is here: **three fully-built capture features are dead code.**

| Module | State | Enhancement | Pri · Effort |
|---|---|---|---|
| `hooks/useMouseCapture.js` | Built, **not imported anywhere** | Wire into `App.jsx`/`ChatPanel` behind a consent gate | 🔴 · S |
| `hooks/useTouchCapture.js` | Built, **not imported anywhere** | Same — activate on touch devices | 🔴 · S |
| `lib/fingerprint.js` | Built, **not imported anywhere**; server 403s without consent | Needs a consent flow before it can send anything | 🔴 · M |
| SLA view | `/api/sla` exists, **no component consumes it** | Add an `SlaPanel.jsx` (p50/p95/p99, availability, anomalies) | 🟡 · S |
| Consent UI | **Does not exist** (`grep consent client/src` → only comments) | Build a consent banner/settings panel driving `proxy/compliance/consent.js` | 🔴 · M |

**Why this matters:** `docs/TIER3_TODO.md` marks Epics E/G ✅ "done", but on the live
site none of mouse dynamics, touch biometrics, or device fingerprinting actually run —
`App.jsx` only mounts keystroke capture. The backend + hooks exist; the wiring and the
**consent gate that must precede them** do not. Fingerprint + mouse/touch are explicitly
privacy-gated (Epic I), so they must **not** auto-activate — a consent UI is the real
blocker, which is why it's the top enhancement rather than a one-line import.

Minor: `useTouchCapture` computes swipe velocity as `distance / (now - last.t)` where
`last.t` is the *pointerdown* time and is never refreshed on move, so velocity is
underestimated across a single touch. Refresh `last.t` on each move. 🟢 · S

---

## 2. New biometric routes (`proxy/routes/mouse.js`, `touch.js`, `fingerprint.js`) — 🟡

These work, but are **second-class citizens** compared to keystroke scoring:

- **No persistence.** Baselines live in a module-level `Map` (`const baselines = new Map()`).
  They are lost on restart and **not shared across biometric-svc replicas** — so in the
  distributed mode the platform advertises, a user's mouse/touch baseline is per-pod and
  effectively resets on every deploy. Keystroke baselines, by contrast, persist to Mongo
  via `getBaseline`/`upsertBaseline`. **Enhance:** move these to Mongo (or Redis) the same way. 🟡 · M
- **No tests.** `mouse.js`/`touch.js`/`fingerprint.js` have no dedicated coverage; the
  green suite doesn't exercise them. **Enhance:** add route tests (cold-start, scoring,
  consent-403 for fingerprint). 🟡 · S
- **No fusion wiring.** `engine/biometric/fusion.py` exists to fuse keystroke+mouse+touch,
  but the mouse/touch scores are computed in Node and never sent to the fusion model or
  folded into the session trust score used for step-up. **Enhance:** feed these channels
  into the same trust signal that drives `requireStepUp`. 🔴 · M

---

## 3. Python engine (`engine/`) — 🟡

- **Dependency/ABI breakage.** `python -m pytest` currently **fails to collect** —
  `pyarrow` (pulled in transitively by scikit-learn) is compiled against NumPy 1.x but
  the environment has NumPy 2.x (`AttributeError: _ARRAY_API not found`). This is an
  environment issue, not app code, but it means **the engine test suite can't run locally.**
  **Enhance:** pin `numpy<2` (or upgrade pyarrow) in `requirements.txt` and add a CI job
  that actually runs `engine/tests`. 🔴 · S
- **Heavy optional imports on the hot path.** `app.py /classify` now imports the ensemble
  and DistilBERT embedding-firewall lazily inside the request. First-request latency will
  spike (model load) and each call re-imports. **Enhance:** warm these at startup and cache
  the module handles; keep the `try/except` fail-open. 🟡 · S
- **Embedding firewall is best-effort-silent.** Any exception is swallowed to `pass`, so a
  broken model looks identical to "no outlier." **Enhance:** surface a `degraded` flag in
  `ClassifyResponse` like the biometric path already does. 🟢 · S

---

## 4. Firewall heuristics (`proxy/firewall/`) — 🟢 solid, targeted gaps

- **Cross-lingual rules are romanization-only.** The new Epic-F rules cover romanized
  Hindi/Chinese/Russian/Arabic plus one CJK line, but native-script ES/FR/DE accents and
  non-Latin scripts are largely uncovered. Reasonable for a demo; note it's not the
  "8-language" coverage the TODO implies. **Enhance:** add native-script rules + a
  transliteration pass, or lean on the embedding firewall for non-Latin. 🟢 · M
- **Canary is single, process-static.** `canary.js` uses one token per boot injected into
  the default system prompt only. Trifecta agents (`chatCompletionMessages` with custom
  system prompts) get **no canary**, so their prompt leaks are invisible to the canary
  check. **Enhance:** inject a per-request/per-agent canary. 🟡 · M

---

## 5. Cross-cutting / ops — 🟡

- **`TIER3_TODO.md` overstates completion.** It marks Epics A–K ✅ but several are
  backend-only with no UI or no persistence (see §1, §2). **Enhance:** reconcile the
  status legend with reality (a 🟡 "backend built, not wired" state).
- **In-memory stores won't scale horizontally.** Beyond biometrics (§2), audit the other
  `new Map()`/module-singleton stores before claiming the k8s/HPA story in Epic J — HPA
  with per-pod memory state silently corrupts behavioral baselines. 🟡 · M
- **Engine tests not in CI gate.** Only the proxy suite reliably runs. Wire engine +
  client build into CI so regressions in the ML/biometric layers are caught. 🔴 · S

---

## Recommended order

1. 🔴 **Pin `numpy<2`** so the engine suite runs, then gate engine+client in CI. (§3, §5) — S
2. 🔴 **Build the consent UI**, then wire mouse/touch/fingerprint hooks behind it. (§1) — M
3. 🔴 **Persist + fuse** the mouse/touch baselines into the trust score. (§2) — M
4. 🟡 Add `SlaPanel.jsx`, route tests, per-agent canary. (§1, §2, §4) — S–M
5. 🟢 Native-script heuristics, touch-velocity fix, embedding `degraded` flag. — S–M

**One-line summary:** the *backend* is broad and green; the real enhancement work is
**front-end wiring + a consent gate (Client)**, **persisting/fusing the new behavioral
channels (biometric routes + engine)**, and **making the Python suite runnable in CI**.
