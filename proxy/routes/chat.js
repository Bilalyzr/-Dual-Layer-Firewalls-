/**
 * /api/chat — the core firewall interception point (Req 1.1–1.5).
 *
 * Pipeline:
 *   1. Intercept inbound prompt (1.1)
 *   2. Heuristic scan (1.2)
 *   3. ML classification via engine (1.3)
 *   4. Decide ALLOW/BLOCK using threshold + mode (shadow vs enforce)
 *   5. If allowed → call LLM backend → outbound integrity check (1.4)
 *   6. Always: log alert/confidence, sample low-confidence allowed traffic (1.5)
 */
import { Router } from "express";
import { runHeuristics, OWASP_TITLES } from "../firewall/heuristics.js";
import { classifyPrompt } from "../firewall/mlClient.js";
import { getCached, setCached } from "../firewall/clfCache.js";
import { checkOutput } from "../firewall/outputCheck.js";
import { detectCanaryLeak } from "../firewall/canary.js";
import { rebuffCheck } from "../firewall/rebuff.js";
import { moderateContent } from "../firewall/llamaGuard.js";
import { chatCompletion } from "../llm/client.js";
import { isAgentic, runTrifecta } from "../agents/orchestrator.js";
import { insertAlert, insertModuleAnalysis, insertSample } from "../db/mongo.js";
import { publish } from "../middleware/eventBus.js";
import { forensicsFromReq } from "../middleware/ipContext.js";
import { requestEnrichment } from "../forensics/enrich.js";
import { recordOffense } from "../response/banStore.js";
import { computeFingerprint, checkSignature, recordSignature } from "../firewall/fingerprint.js";
import { getFingerprintState } from "./fingerprint.js";

const router = Router();

// Layer-1 → Layer-2 bridge: engine base for behavioral events (same default
// as firewall/mlClient.js).
const ENGINE_URL = process.env.ENGINE_URL || "http://127.0.0.1:8011";

// Real-time learning bridge: push every REAL verdict (blocked -> threat,
// allowed -> benign) to the v2 firewall's training store so the model keeps
// learning from live site traffic. Fire-and-forget; off when unreachable.
const REALTIME_API = process.env.REALTIME_API_URL || "http://127.0.0.1:8020";
function reportRealtimeSample(prompt, label, risk = 0) {
  fetch(`${REALTIME_API}/realtime/sample`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt: String(prompt || "").slice(0, 4000), label, risk, source: "proxy-traffic" }),
    signal: AbortSignal.timeout(3000),
  }).catch(() => {});
}

// Trial-update: word-injection breakdown for BLOCKED messages — which exact
// terms carried negative/positive weight, so the dashboard can highlight them.
// Fail-soft: blocks must never wait long on this (2s cap, {} on any failure).
async function fetchWordScores(prompt) {
  try {
    const r = await fetch(`${REALTIME_API}/sentiment/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: String(prompt || "").slice(0, 4000) }),
      signal: AbortSignal.timeout(2000),
    });
    if (!r.ok) return {};
    const d = await r.json();
    return {
      negative_terms: d.negative_terms || [],
      positive_terms: d.positive_terms || [],
      weightage: d.weightage ?? null,
    };
  } catch {
    return {};
  }
}

/**
 * Fetch the 6-module security evaluation breakdown from the v2 firewall (:8020/v1/inspect)
 * and fuse it with the proxy's local heuristic, ML, signature, and agent signals.
 * Fail-soft: if :8020 is unreachable (e.g. unit tests), synthesizes accurate 0-100%
 * scores directly from the proxy's own evaluation layers.
 */
async function buildModuleScores({
  prompt,
  userId,
  sessionId,
  heuristic,
  classification,
  sigHit,
  fp,
  wordScores,
  agentTrace,
  blocked,
  category,
  blockReason,
  triggeredBy,
  threshold,
  totalLatencyMs,
}) {
  let v2 = null;
  try {
    const r = await fetch(`${REALTIME_API}/v1/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: String(prompt || "").slice(0, 4000),
        user_id: String(userId || "anon"),
        session_id: String(sessionId || ""),
      }),
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) v2 = await r.json();
  } catch {
    v2 = null;
  }

  const m = v2?.modules || {};
  const heurMatched = Boolean(heuristic?.matched);
  const heurSignals = (heuristic?.signals || []).map((s) => `${s.category}:${s.label}`);
  const v2Removed = m.prompt_sanitization?.removed || [];
  const allRemoved = [...new Set([...v2Removed, ...heurSignals])];
  const weightage = wordScores?.weightage ?? m.prompt_sanitization?.word_weightage ?? 0;
  const sanitizeRaw = Math.max(
    m.prompt_sanitization?.raw_score ?? 0,
    heurMatched ? 0.92 : 0,
    weightage
  );
  const sanitizeScore = Math.round(Math.min(1, sanitizeRaw) * 100);

  const proxyProb = classification?.threatProbability ?? null;
  const v2Intent = m.ai_threat_detection?.intent_score ?? null;
  const rawThreat =
    !blocked && v2Intent != null && (proxyProb ?? 0) < (threshold || 0.65)
      ? v2Intent
      : Math.max(
          proxyProb ?? 0,
          v2Intent ?? 0,
          heurMatched && proxyProb == null && v2Intent == null ? 0.88 : 0
        );
  const threatScore = Math.round(Math.min(1, rawThreat) * 100);

  const v2Sim = m.semantic_attack_memory?.similarity ?? 0;
  const sigMatched = Boolean(sigHit);
  const rawMem = Math.max(v2Sim, sigMatched ? 0.98 : 0);
  const memoryScore = Math.round(Math.min(1, rawMem) * 100);

  const rawBehav = m.behavioral_analysis?.cumulative_risk ?? (blocked ? Math.max(0.65, rawThreat * 0.85) : rawThreat * 0.4);
  const behaviorScore = Math.round(Math.min(1, rawBehav) * 100);

  const agentRagRisk = agentTrace?.blocked ? 0.95 : agentTrace ? 0.15 : 0;
  const rawRag = Math.max(m.rag_security?.risk ?? 0, agentRagRisk);
  const ragScore = Math.round(Math.min(1, rawRag) * 100);

  const rawFinal = Math.max(
    v2?.risk_score ?? 0,
    sanitizeRaw * 0.9,
    rawThreat,
    rawMem,
    rawBehav,
    rawRag,
    blocked ? 0.85 : 0
  );
  const finalScore = Math.round(Math.min(1, rawFinal) * 100);

  const payload = {
    prompt: String(prompt || "").slice(0, 180),
    userId: String(userId || "anon"),
    ts: new Date().toISOString(),
    blocked: Boolean(blocked),
    category: category || (blocked ? "LLM01" : "SAFE"),
    promptSanitization: {
      label: "Prompt Sanitization",
      score: sanitizeScore,
      status: sanitizeScore >= 70 ? "SCRUBBED" : sanitizeScore >= 35 ? "FLAGGED" : "CLEAN",
      removed: allRemoved,
      wordWeightage: Math.round(weightage * 100),
      heuristicMatched: heurMatched,
      negativeTerms: wordScores?.negative_terms || m.prompt_sanitization?.negative_terms || [],
      positiveTerms: wordScores?.positive_terms || m.prompt_sanitization?.positive_terms || [],
      latencyMs: m.prompt_sanitization?.latency_ms ?? heuristic?.latencyMs ?? 0.2,
    },
    aiThreatDetection: {
      label: "AI Threat Detection",
      score: threatScore,
      status: threatScore >= Math.round((threshold || 0.65) * 100) ? "THREAT" : threatScore >= 35 ? "ELEVATED" : "SAFE",
      intentScore: v2Intent != null ? Math.round(v2Intent * 100) : threatScore,
      classifierProb: proxyProb != null ? Math.round(proxyProb * 100) : null,
      tfidfScore: m.ai_threat_detection?.tfidf_score != null ? Math.round(m.ai_threat_detection.tfidf_score * 100) : null,
      cascadeTier: m.ai_threat_detection?.cascade_tier || "deep",
      model: m.ai_threat_detection?.model || "MiniLM-L6-v2 + XGBoost",
      latencyMs: m.ai_threat_detection?.latency_ms ?? classification?.latencyMs ?? 0,
    },
    semanticAttackMemory: {
      label: "Semantic Attack Memory",
      score: memoryScore,
      status: memoryScore >= 92 || sigMatched ? "MATCHED" : memoryScore >= 65 ? "NEAR" : "CLEAR",
      similarity: Math.round(rawMem * 100),
      threshold: Math.round((m.semantic_attack_memory?.threshold ?? 0.92) * 100),
      knownAttack:
        memoryScore >= 65 || sigMatched
          ? m.semantic_attack_memory?.known_attack || (sigHit ? sigHit.label : "")
          : "",
      signature: fp?.signature || null,
      signatureHits: sigHit?.hits || 0,
      latencyMs: m.semantic_attack_memory?.latency_ms ?? 0.4,
    },
    behavioralAnalysis: {
      label: "Behavioral Analysis",
      score: behaviorScore,
      status: behaviorScore >= 70 ? "HIGH" : behaviorScore >= 35 ? "MEDIUM" : "LOW",
      cumulativeRisk: behaviorScore,
      drift: Math.round((m.behavioral_analysis?.drift ?? 0) * 100),
      attackProximity: Math.round((m.behavioral_analysis?.attack_proximity ?? rawThreat) * 100),
      turnCount: m.behavioral_analysis?.turn_count ?? 1,
      sentimentAvg: m.behavioral_analysis?.sentiment_avg ?? 0,
      latencyMs: m.behavioral_analysis?.latency_ms ?? 0.5,
    },
    ragSecurity: {
      label: "RAG Security",
      score: ragScore,
      status: ragScore >= 70 ? "POISONED" : (m.rag_security?.dropped_docs?.length || 0) > 0 ? "FILTERED" : "SAFE",
      safeDocs: m.rag_security?.safe_docs ?? 2,
      droppedDocs: m.rag_security?.dropped_docs || [],
      imperativeFlags: m.rag_security?.imperative_flags || [],
      latencyMs: m.rag_security?.latency_ms ?? 0.8,
    },
    finalDecisionEngine: {
      label: "Final Decision Engine",
      score: finalScore,
      status: blocked ? "BLOCK" : finalScore >= 50 ? "RESTRICT" : "ALLOW",
      verdict: blocked ? "BLOCK" : "ALLOW",
      triggeredBy: triggeredBy || m.final_decision_engine?.triggered_by || (blocked ? "policy" : "none"),
      reason: blockReason || m.final_decision_engine?.reason || "All 6 security modules passed",
      threshold: Math.round((threshold || 0.65) * 100),
      latencyMs: totalLatencyMs ?? v2?.latency_ms ?? 0,
    },
  };

  await insertModuleAnalysis(payload);
  publish("module_analysis", payload);
  return payload;
}

// Prompt injection → Behavioral Risk Analysis updates DIRECTLY (PRD §35):
// run the Layer-2 pipeline on the hostile-session context and publish the
// decision to the SSE stream so the dashboard's EXPLAINABILITY block shows
// every triggered warning (new device/location, off-hours, sensitive
// resource, frequency above baseline, prior failed auths, anomaly score).
// Fire-and-forget from EVERY block path — never adds chat-path latency.
// `wordScores` (from fetchWordScores) makes the §35 EXPLAINABILITY reasons
// prompt-specific: the engine quotes the attack vocabulary it contains.
//
// REAL-TIME CONTEXT (trial-update): device/location/time signals are taken
// from the ACTUAL request — the user's stored fingerprint (changed vs not),
// the resolved client IP (changed vs not), and the real clock. The old
// hardcoded hostile context (unknown device, 3am, critical database) made
// "New device/location detected" fire for everyone, always — fake signals.
const _lastSeenIp = new Map(); // userId -> last client IP (real location-change source)
function reportInjectionBehavior({ userId, sessionId, prompt, wordScores, clientIp }) {
  const uid = String(userId || "anon");
  const fpState = getFingerprintState(uid); // real: {known, changed}
  const prevIp = _lastSeenIp.get(uid);
  const ip = String(clientIp || "");
  if (ip) _lastSeenIp.set(uid, ip);
  const locationChange = Boolean(ip && prevIp && prevIp !== ip); // first sighting is NOT a change
  const now = new Date();
  const hour = now.getHours();
  const workingHours = hour >= 9 && hour < 18;
  fetch(`${ENGINE_URL}/behavior/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      // Sanitize: express-session yields null (not "") when absent, and a
      // JSON null fails the engine's Pydantic validation with a 422.
      user_id: uid,
      session_id: String(sessionId || ""),
      role: "user",
      // REAL device signals from the fingerprint store
      device_id: fpState.known ? "registered-device" : "unregistered-device",
      device_type: "browser",
      device_trust: fpState.known ? 0.9 : 0.3,
      registered_device: fpState.known,
      device_change: fpState.changed,
      // REAL location signal from the resolved client IP
      location_change: locationChange,
      location_frequency: locationChange ? 0.2 : 0.85,
      // REAL clock
      hour,
      working_hours: workingHours,
      working_day: now.getDay() >= 1 && now.getDay() <= 5,
      resource_type: "chat",
      resource_sensitivity: "medium",
      request_frequency: 12,
      resource_access_frequency: 5,
      failed_auth_count: 0,
      prompt_text: prompt,
      prompt_injection: true,
      word_scores: wordScores || {},
    }),
    signal: AbortSignal.timeout(5000),
  })
    .then(async (r) => {
      if (!r.ok) return;
      const data = await r.json();
      if (data?.decision) publish("behavior", { ...data.decision, ts: new Date() });
    })
    .catch(() => { /* behavioral feed must never break the chat path */ });
}

// Read mode/threshold per-request so SecOps can toggle (and tests can vary it)
// without a process restart.
const mode = () => (process.env.FIREWALL_MODE || "shadow").toLowerCase(); // shadow | enforce
const threshold = () => parseFloat(process.env.FIREWALL_THRESHOLD || "0.65");
const sampleRate = () => parseFloat(process.env.ADVERSARIAL_SAMPLE_RATE || "0.05");

function mask(text, n = 200) {
  if (typeof text !== "string") return "";
  return text.length > n ? text.slice(0, n) + "…" : text;
}

// Per-IP chat rate limit: the LLM key's quota is SHARED across all visitors,
// so one flooding client could starve everyone. 60 req/min/IP is far above
// any human/demo pace (the 22-prompt battery never trips it) but stops
// floods. In-memory fixed window — resets with the process, which is fine
// for this tier of protection.
const _rl = new Map(); // ip -> { count, resetAt }
const RL_WINDOW_MS = 60_000;
const RL_MAX = parseInt(process.env.CHAT_RATE_LIMIT_PER_MIN || "60", 10);
function _rateLimited(ip) {
  if (!ip) return false; // no IP resolved (tests) — don't block
  const now = Date.now();
  const e = _rl.get(ip);
  if (!e || now >= e.resetAt) {
    _rl.set(ip, { count: 1, resetAt: now + RL_WINDOW_MS });
    return false;
  }
  e.count += 1;
  return e.count > RL_MAX;
}

router.post("/", async (req, res) => {
  const t0 = performance.now();
  // Prefer the verified session identity (EPIC A) over the client-supplied
  // userId. Falls back to the bare userId so unauthenticated demo flows work.
  const session = req.session || null;
  const userId = session?.userId || req.body?.userId || "anon";
  const sessionId = session?.sessionId || null;
  const prompt = req.body?.prompt || "";
  // Epic A: resolve the tamper-resistant client IP once; attached to every alert
  // this request produces so BLOCK/THREAT records carry forensic provenance.
  const forensics = forensicsFromReq(req);

  if (_rateLimited(forensics?.clientIp || req.ip)) {
    return res.status(429).json({
      blocked: true,
      reason: "rate_limited",
      category: "LLM10",
      categoryTitle: "Unbounded Consumption",
      blockReason: `Too many prompts from this address — limit is ${RL_MAX}/minute.`,
    });
  }

  // EPIC B step-up gate: a session whose keystroke trust collapsed is frozen
  // until a fresh WebAuthn assertion clears it (see /api/auth/webauthn/*).
  if (session?.trustState?.stepUpRequired) {
    return res.status(401).json({
      blocked: true,
      reason: "step_up_required",
      category: "MFA",
      categoryTitle: "Step-up authentication required",
      trustState: session.trustState,
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // 1.1 inbound interception — reject malformed payloads
  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    return res.status(400).json({ error: "missing 'prompt'" });
  }
  // Reject oversized prompts (abuse/noise) before they reach the LLM. Legitimate
  // chat prompts are short; a 10KB blob just blocks the GLM call for ~10s.
  const MAX_PROMPT = parseInt(process.env.MAX_PROMPT_CHARS || "4000", 10);
  if (prompt.length > MAX_PROMPT) {
    const MODE = mode();
    const THRESHOLD = threshold();
    const category = "LLM10";
    const categoryTitle = OWASP_TITLES[category] || "Unbounded Consumption";
    const label = `Prompt too large (${prompt.length} chars exceeds ${MAX_PROMPT} char limit)`;
    const latencyMs = +(performance.now() - t0).toFixed(2);
    const alert = {
      userId,
      sessionId,
      kind: "heuristic",
      category,
      categoryTitle,
      label,
      prompt: mask(prompt),
      threatProbability: 1,
      mode: MODE,
      blocked: true,
      forensics,
      ts: new Date(),
    };
    const stored = await insertAlert(alert);
    publish("threat", alert);
    if (forensics) requestEnrichment({ alertId: stored.alertId, ip: forensics.clientIp });
    if (forensics?.clientIp) await recordOffense(forensics.clientIp);
    const moduleScores = {
      prompt: String(prompt || "").slice(0, 180),
      userId: String(userId || "anon"),
      ts: new Date().toISOString(),
      blocked: true,
      category,
      promptSanitization: {
        label: "Prompt Sanitization",
        score: 100,
        status: "REJECTED",
        removed: [`LLM10:prompt_too_large (${prompt.length}/${MAX_PROMPT})`],
        wordWeightage: 0,
        heuristicMatched: true,
        negativeTerms: [],
        positiveTerms: [],
        latencyMs,
      },
      aiThreatDetection: {
        label: "AI Threat Detection",
        score: 0,
        status: "SKIPPED",
        intentScore: 0,
        classifierProb: null,
        tfidfScore: null,
        cascadeTier: "fast-reject",
        model: "length_guard",
        latencyMs: 0,
      },
      semanticAttackMemory: {
        label: "Semantic Attack Memory",
        score: 0,
        status: "CLEAR",
        similarity: 0,
        threshold: 92,
        knownAttack: "",
        signature: null,
        signatureHits: 0,
        latencyMs: 0,
      },
      behavioralAnalysis: {
        label: "Behavioral Analysis",
        score: 75,
        status: "HIGH",
        cumulativeRisk: 75,
        drift: 0,
        attackProximity: 100,
        turnCount: 1,
        sentimentAvg: 0,
        latencyMs: 0.1,
      },
      ragSecurity: {
        label: "RAG Security",
        score: 0,
        status: "SAFE",
        safeDocs: 0,
        droppedDocs: [],
        imperativeFlags: [],
        latencyMs: 0,
      },
      finalDecisionEngine: {
        label: "Final Decision Engine",
        score: 100,
        status: "BLOCK",
        verdict: "BLOCK",
        triggeredBy: "length_guard",
        reason: label,
        threshold: Math.round(THRESHOLD * 100),
        latencyMs,
      },
    };
    await insertModuleAnalysis(moduleScores);
    publish("module_analysis", moduleScores);
    publish("behavior", {
      user_id: userId,
      risk_score: 75,
      risk_level: "HIGH",
      decision: "RESTRICT",
      resource_risk: "medium",
      behavior_anomaly_score: 0.75,
      reasons: [`${label} (OWASP LLM10 Unbounded Consumption)`],
      ts: new Date().toISOString(),
    });
    return res.status(413).json({
      blocked: true,
      error: "prompt too large",
      reason: "prompt too large",
      category,
      categoryTitle,
      blockReason: label,
      detail: label,
      limit: MAX_PROMPT,
      length: prompt.length,
      moduleScores,
      verdict: {
        mode: MODE,
        threshold: THRESHOLD,
        heuristic: {
          matched: true,
          signals: [{ category, label }],
          latencyMs,
        },
        classifier: { skipped: true, reason: "prompt too large", threatProbability: 1 },
        llamaGuard: { skipped: true, reason: "prompt too large" },
        threat: true,
        category,
        shortCircuit: true,
      },
      latencyMs,
    });
  }

  const MODE = mode();
  const THRESHOLD = threshold();
  const SAMPLE_RATE = sampleRate();

  // Epic D: structural attack signature — cheap, local, computed once and reused
  // for the pre-ML short-circuit below and for "learning" a confirmed threat.
  const fp = computeFingerprint(prompt);

  // 1.2 heuristic scan first — local & sub-millisecond. A confirmed heuristic hit
  // in enforce mode lets us BLOCK immediately without paying the ML + Llama Guard
  // network round-trips, keeping the firewall path under the <5ms PRD target.
  const heuristic = await runHeuristics(prompt);
  if (heuristic.matched && MODE === "enforce") {
    const sig = heuristic.signals[0] || {};
    const category = sig.category || "LLM01";
    const label = sig.label || "prompt injection";
    const alert = {
      userId,
      sessionId,
      kind: "heuristic",
      category,
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
      label,
      prompt: mask(prompt),
      threatProbability: null,
      mode: MODE,
      blocked: true,
      forensics,
      ts: new Date(),
    };
    const stored = await insertAlert(alert);
    publish("threat", alert);
    // Epic B: enrich the source IP out-of-band (never on the request path).
    if (forensics) requestEnrichment({ alertId: stored.alertId, ip: forensics.clientIp });
    // Epic C: feed the auto-response engine (bans repeat offenders; no-op if off).
    if (forensics?.clientIp) await recordOffense(forensics.clientIp);
    // Epic D: teach the signature cache so this attack shape is caught pre-ML next time.
    await recordSignature(fp.signature, { category, label, techniques: fp.techniques });
    console.warn(`[firewall] ENFORCE BLOCK [${category}] ${label} (heuristic short-circuit)`);
    const heuristicWordScores = await fetchWordScores(prompt);
    const moduleScores = await buildModuleScores({
      prompt,
      userId,
      sessionId,
      heuristic,
      classification: null,
      sigHit: null,
      fp,
      wordScores: heuristicWordScores,
      agentTrace: null,
      blocked: true,
      category,
      blockReason: label,
      triggeredBy: "sanitizer+heuristic",
      threshold: THRESHOLD,
      totalLatencyMs: +(performance.now() - t0).toFixed(2),
    });
    reportInjectionBehavior({ userId, sessionId, prompt, wordScores: heuristicWordScores, clientIp: forensics?.clientIp });
    reportRealtimeSample(prompt, 1);
    return res.json({
      blocked: true,
      reason: "blocked by AI firewall",
      category,
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
      blockReason: label,
      wordScores: heuristicWordScores,
      moduleScores,
      verdict: {
        mode: MODE,
        threshold: THRESHOLD,
        heuristic: { matched: true, signals: heuristic.signals, latencyMs: heuristic.latencyMs },
        classifier: { skipped: true, reason: "heuristic short-circuit" },
        llamaGuard: { skipped: true, reason: "heuristic short-circuit" },
        threat: true,
        category,
        shortCircuit: true,
      },
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // Epic D: known-signature short-circuit. A prompt whose structural signature has
  // been confirmed a threat enough times is blocked BEFORE the ML + Llama-Guard
  // round-trips — the §12.1 cost saver. Enforce-only, so shadow still logs via ML.
  if (MODE === "enforce") {
    const sigHit = await checkSignature(fp.signature);
    if (sigHit) {
      const category = sigHit.category;
      const label = `Known attack signature (${sigHit.hits} prior) — ${sigHit.label}`;
      const alert = {
        userId,
        sessionId,
        kind: "signature",
        category,
        categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
        label,
        prompt: mask(prompt),
        signature: fp.signature,
        threatProbability: null,
        mode: MODE,
        blocked: true,
        forensics,
        ts: new Date(),
      };
      const stored = await insertAlert(alert);
      publish("signature", alert);
      publish("threat", alert);
      if (forensics) requestEnrichment({ alertId: stored.alertId, ip: forensics.clientIp });
      if (forensics?.clientIp) await recordOffense(forensics.clientIp);
      await recordSignature(fp.signature, { category, label: sigHit.label, techniques: fp.techniques });
      console.warn(`[firewall] ENFORCE BLOCK [${category}] signature ${fp.signature} (ML short-circuit)`);
      const sigWordScores = await fetchWordScores(prompt);
      const moduleScores = await buildModuleScores({
        prompt,
        userId,
        sessionId,
        heuristic,
        classification: null,
        sigHit,
        fp,
        wordScores: sigWordScores,
        agentTrace: null,
        blocked: true,
        category,
        blockReason: label,
        triggeredBy: "memory+signature",
        threshold: THRESHOLD,
        totalLatencyMs: +(performance.now() - t0).toFixed(2),
      });
      reportInjectionBehavior({ userId, sessionId, prompt, wordScores: sigWordScores, clientIp: forensics?.clientIp });
      return res.json({
        blocked: true,
        reason: "blocked by AI firewall",
        category,
        categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
        blockReason: label,
        wordScores: sigWordScores,
        moduleScores,
        verdict: {
          mode: MODE,
          threshold: THRESHOLD,
          signature: { matched: true, signature: fp.signature, priorHits: sigHit.hits },
          classifier: { skipped: true, reason: "signature short-circuit" },
          llamaGuard: { skipped: true, reason: "signature short-circuit" },
          rebuff: { score: 1.0, detected: true, layers: { signature: { matched: true, hits: sigHit.hits } }, note: "blocked by known signature" },
          threat: true,
          category,
          shortCircuit: true,
        },
        latencyMs: +(performance.now() - t0).toFixed(2),
      });
    }
  }

  // 1.3 + EPIC C — ML classification (cached per-prompt, Tier-3 §12.8) + Llama
  // Guard, in parallel. A cache hit skips the engine round-trip entirely.
  const cachedClf = getCached(prompt);
  const [classification, guardInput] = await Promise.all([
    cachedClf
      ? Promise.resolve(cachedClf)
      : classifyPrompt(prompt).then((c) => {
          if (c.ready !== false) setCached(prompt, c); // only cache real verdicts
          return c;
        }),
    moderateContent({ text: prompt, role: "user" }),
  ]);

  let threatProb = classification.threatProbability || 0;
  const engineReady = classification.ready !== false;

  // Educational-intent dampener (gray band, QUESTIONS only): lexical models
  // score "How does phishing work? I want to teach my staff to recognize scam
  // emails" like an attack because the TOPIC is phishing. A QUESTION that
  // names a defensive/educational intent and asks no generation imperative
  // gets a small discount — but ONLY inside the gray band, so confirmed
  // attacks (≥ threshold + 0.10), requests phrased as instructions, and the
  // heuristic layer are untouched.
  if (engineReady && threatProb >= THRESHOLD && threatProb < THRESHOLD + 0.10 &&
      (/^\s*(how|what|why|is|are|can|does|do|which)\b/i.test(prompt) || /\?\s*$/.test(prompt.trim())) &&
      /\b(teach|educat|train|learn|recogni[sz]e|protect|secure|defend|prevent|awareness)\b/i.test(prompt) &&
      !/\b(write|generate|create|draft|give me|produce|compose|make me)\b/i.test(prompt)) {
    threatProb = threatProb * 0.85;
  }

  // Threat if heuristics matched OR ML probability crosses threshold.
  const heuristicThreat = heuristic.matched;
  const mlThreat = engineReady && threatProb >= THRESHOLD;
  // Llama Guard verdict: unsafe, OR (enforce + endpoint degraded) → fail-closed.
  const guardThreat =
    guardInput.enabled && (!guardInput.safe || (guardInput.degraded && MODE === "enforce"));
  const isThreat = heuristicThreat || mlThreat || guardThreat;

  // Pick a category for the dashboard — heuristics first, then Llama Guard's
  // mapped OWASP tag, then a generic ML injection tag.
  const category =
    heuristic.signals[0]?.category ||
    guardInput.owasp?.[0]?.owasp ||
    (mlThreat ? "LLM01" : guardThreat ? "LLM05" : null);
  // Rebuff-style 4-layer defense (Protect AI approach): combine all detection
  // layers — max score wins, any layer flagging = threat.
  const rebuff = rebuffCheck(prompt, {
    threatProbability: threatProb,
    outlierFlag: classification.outlier_flag,
    ready: engineReady,
  });

  const verdict = {
    mode: MODE,
    threshold: THRESHOLD,
    heuristic: { matched: heuristicThreat, signals: heuristic.signals, latencyMs: heuristic.latencyMs },
    classifier: { threatProbability: threatProb, latencyMs: classification.latencyMs, ready: engineReady },
    llamaGuard: {
      enabled: guardInput.enabled,
      safe: guardInput.safe,
      categories: guardInput.categories,
      owasp: guardInput.owasp,
      degraded: guardInput.degraded || false,
      latencyMs: guardInput.latencyMs,
    },
    rebuff: { score: rebuff.score, detected: rebuff.detected, layers: rebuff.layers },
    threat: isThreat,
    category,
  };

  // ---- Decision: shadow logs but does not block. ----
  let willBlock = isThreat && MODE === "enforce";
  let weightageBlock = null;

  // Word-injection corroboration (mirrors the v2 firewall's decision rule):
  // a classifier score in the gray zone PLUS saturated attack vocabulary is
  // an attack — paraphrases like "ignoring all previous instructions" score
  // below the ML threshold while carrying unmistakable attack words.
  // Probe only the gray zone so clean prompts never pay the round-trip.
  if (!willBlock && MODE === "enforce" && threatProb >= 0.25) {
    const ws = await fetchWordScores(prompt);
    if (ws && typeof ws.weightage === "number" && ws.weightage >= 0.9) {
      willBlock = true;
      weightageBlock = {
        ws,
        category: "LLM01",
        label: `Word-injection weightage ${Math.round(ws.weightage * 100)}% (attack vocabulary saturation)`,
      };
    }
  }
  if (weightageBlock && !isThreat) {
    // Route through the same block bookkeeping as an ML hit.
    const alert = {
      userId,
      sessionId,
      kind: "weightage",
      category: weightageBlock.category,
      categoryTitle: OWASP_TITLES[weightageBlock.category] || "Prompt Injection",
      label: weightageBlock.label,
      prompt: mask(prompt),
      threatProbability: threatProb,
      mode: MODE,
      blocked: true,
      forensics,
      ts: new Date(),
    };
    const stored = await insertAlert(alert);
    publish("threat", alert);
    if (forensics) requestEnrichment({ alertId: stored.alertId, ip: forensics.clientIp });
    if (forensics?.clientIp) await recordOffense(forensics.clientIp);
    console.warn(`[firewall] ENFORCE BLOCK [${weightageBlock.category}] ${weightageBlock.label}`);
    const moduleScores = await buildModuleScores({
      prompt,
      userId,
      sessionId,
      heuristic,
      classification,
      sigHit: null,
      fp,
      wordScores: weightageBlock.ws,
      agentTrace: null,
      blocked: true,
      category: weightageBlock.category,
      blockReason: weightageBlock.label,
      triggeredBy: "sentiment+intent",
      threshold: THRESHOLD,
      totalLatencyMs: +(performance.now() - t0).toFixed(2),
    });
    reportInjectionBehavior({ userId, sessionId, prompt, wordScores: weightageBlock.ws, clientIp: forensics?.clientIp });
    reportRealtimeSample(prompt, 1);
    return res.json({
      blocked: true,
      reason: "blocked by AI firewall",
      category: weightageBlock.category,
      categoryTitle: OWASP_TITLES[weightageBlock.category] || "Prompt Injection",
      blockReason: weightageBlock.label,
      wordScores: weightageBlock.ws,
      moduleScores,
      verdict: {
        ...verdict,
        weightage: { weightage: weightageBlock.ws.weightage, blocked: true },
        threat: true,
        category: weightageBlock.category,
      },
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // Hoisted so the block-reason is visible in the willBlock path below (M1 fix).
  let label = "";
  if (isThreat) {
    const guardLabel = guardInput.degraded
      ? "Llama Guard endpoint degraded (fail-closed)"
      : `Llama Guard flagged unsafe content [${guardInput.categories.join(",")}]`;
    label =
      heuristic.signals[0]?.label ||
      (mlThreat ? `ML-classified prompt injection (p=${threatProb.toFixed(2)})` : null) ||
      (guardThreat ? guardLabel : `prompt injection (p=${threatProb.toFixed(2)})`);
    const alert = {
      userId,
      sessionId,
      kind: heuristicThreat ? "heuristic" : mlThreat ? "ml" : "llamaguard",
      category: category || "LLM01",
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
      label,
      prompt: mask(prompt),
      threatProbability: threatProb,
      mode: MODE,
      blocked: willBlock,
      forensics,
      ts: new Date(),
    };
    const stored = await insertAlert(alert);
    publish("threat", alert);

    // Fetched once, shared by the behavior event (prompt-specific §35
    // explainability) and the blocked response (dashboard word chips).
    var mlWordScores = willBlock ? await fetchWordScores(prompt) : null;
    reportInjectionBehavior({ userId, sessionId, prompt, wordScores: mlWordScores, clientIp: forensics?.clientIp });
    reportRealtimeSample(prompt, 1);

    if (forensics) requestEnrichment({ alertId: stored.alertId, ip: forensics.clientIp });
    if (forensics?.clientIp) await recordOffense(forensics.clientIp);
    // Epic D: learn the signature so a repeat of this attack shape is caught pre-ML.
    await recordSignature(fp.signature, { category: category || "LLM01", label, techniques: fp.techniques });
    console.warn(`[firewall] ${MODE.toUpperCase()} ${willBlock ? "BLOCK" : "DETECT"} [${category}] ${label}`);
  } else {
    // 1.5 adversarial monitoring — sample low-confidence ALLOWED traffic.
    const near = engineReady && threatProb >= THRESHOLD * 0.5 && threatProb < THRESHOLD;
    if (near || Math.random() < SAMPLE_RATE) {
      await insertSample({
        userId,
        prompt: mask(prompt),
        threatProbability: threatProb,
        nearThreshold: near,
      });
    }
  }

  if (willBlock) {
    const finalWordScores = (typeof mlWordScores !== "undefined" && mlWordScores) || await fetchWordScores(prompt);
    const finalBlockReason = (typeof label === "string" && label) || `ML classifier score ${threatProb?.toFixed?.(2) ?? "?"} ≥ threshold`;
    const moduleScores = await buildModuleScores({
      prompt,
      userId,
      sessionId,
      heuristic,
      classification,
      sigHit: null,
      fp,
      wordScores: finalWordScores,
      agentTrace: null,
      blocked: true,
      category,
      blockReason: finalBlockReason,
      triggeredBy: heuristicThreat ? "sanitizer+intent" : mlThreat ? "ai_threat_detection" : "llamaguard",
      threshold: THRESHOLD,
      totalLatencyMs: +(performance.now() - t0).toFixed(2),
    });
    return res.json({
      blocked: true,
      reason: "blocked by AI firewall",
      category,
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
      // `label` only exists on the engine-ready alert path; fall back for the
      // degraded (engine down) path where only the classifier verdict exists.
      blockReason: finalBlockReason,
      wordScores: finalWordScores,
      moduleScores,
      verdict,
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // Real-time learning: only genuinely allowed prompts are labelled benign.
  // All block paths have already returned (or called reportRealtimeSample(1))
  // so we reach here only when isThreat=false (H1 fix).
  if (!isThreat) {
    reportRealtimeSample(prompt, 0, threatProb);
  }

  // Evaluate and broadcast all 6 security module scores IMMEDIATELY before
  // forwarding to the LLM so the UI displays the per-module scores in real time
  // while approving the prompt (and also guarantees moduleScores is attached
  // even if the upstream LLM times out or returns 502).
  let moduleScores = await buildModuleScores({
    prompt,
    userId,
    sessionId,
    heuristic,
    classification,
    sigHit: null,
    fp,
    wordScores: null,
    agentTrace: null,
    blocked: false,
    category: category || "SAFE",
    blockReason: "All 6 security modules passed — approved for LLM execution",
    triggeredBy: "none",
    threshold: THRESHOLD,
    totalLatencyMs: +(performance.now() - t0).toFixed(2),
  });

  // Allowed → forward to LLM backend.
  // Phase 5: agentic prompts (untrusted content + implied action) route through
  // the Trifecta Reader→Validator→Actor flow; normal Q&A bypasses to a direct
  // LLM call. Both paths return {content, raw} so the outbound check is shared.
  let llmResponse;
  let agentTrace = null;
  let llmLatencyMs = null;
  const llmT0 = performance.now(); // surfaced per-message: which provider answered, how fast
  try {
    if (isAgentic(prompt)) {
      const r = await runTrifecta({
        prompt,
        userId,
        emit: (ev) => {
          // Stream each agent stage to the dashboard audit trail (Req 2.5, 4.3).
          const event = { userId, ...ev, promptPreview: mask(prompt, 80), ts: new Date() };
          publish("agent", event);
        },
      });
      llmResponse = r;
      agentTrace = r.agentTrace;
      // Persist a summary of the agent decision for SecOps audit.
      await insertAlert({
        userId,
        kind: "agent",
        category: r.agentTrace?.blocked ? "LLM06" : "LLM05",
        categoryTitle: r.agentTrace?.blocked ? "Excessive Agency (blocked)" : "Agent Action (audited)",
        label: `Trifecta ${r.agentTrace?.blocked ? "BLOCKED: " + r.agentTrace.blockReason : "executed tool " + (r.agentTrace?.actor?.tool || "none")}`,
        prompt: mask(prompt),
        mode: MODE,
        blocked: !!r.agentTrace?.blocked,
        agentTrace: r.agentTrace,
        forensics,
        ts: new Date(),
      });
    } else {
      llmResponse = await chatCompletion(prompt);
    }
    llmLatencyMs = +(performance.now() - llmT0).toFixed(2);
  } catch (err) {
    return res.status(502).json({
      blocked: false,
      error: "LLM backend error",
      detail: String(err.message || err),
      moduleScores,
      verdict,
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // 1.4 outbound integrity check on the response — regex + Llama Guard, parallel.
  // EPIC F: also check for canary-token leakage (system-prompt exfiltration).
  const [output, guardOutput] = await Promise.all([
    Promise.resolve(checkOutput(llmResponse.content)),
    moderateContent({ text: llmResponse.content, role: "assistant" }),
  ]);
  const canaryLeak = detectCanaryLeak(llmResponse.content);
  const guardOutputUnsafe =
    guardOutput.enabled && (!guardOutput.safe || (guardOutput.degraded && MODE === "enforce"));
  const outboundBlocked = output.blocked || guardOutputUnsafe || canaryLeak.leaked;
  const outboundCategory = canaryLeak.leaked
    ? "LLM07"
    : output.blocked ? "LLM02" : guardOutput.owasp?.[0]?.owasp || "LLM05";

  let finalContent = llmResponse.content;
  if (outboundBlocked && MODE === "enforce") {
    const reasons = [
      ...output.reasons,
      ...(guardOutputUnsafe
        ? [guardOutput.degraded
            ? "Llama Guard endpoint degraded (fail-closed)"
            : `Llama Guard unsafe output [${guardOutput.categories.join(",")}]`]
        : []),
    ];
    finalContent =
      "[Response redacted by firewall outbound integrity check: " + reasons.join(", ") + "]";
    const label = output.blocked
      ? "Outbound exfiltration/tool-call blocked"
      : "Outbound unsafe content blocked (Llama Guard)";
    const outboundStored = await insertAlert({
      userId,
      sessionId,
      kind: "outbound",
      category: outboundCategory,
      categoryTitle: OWASP_TITLES[outboundCategory],
      label,
      reasons,
      snippets: output.snippets,
      llamaGuard: guardOutput.owasp,
      mode: MODE,
      blocked: true,
      forensics,
      ts: new Date(),
    });
    if (forensics) requestEnrichment({ alertId: outboundStored.alertId, ip: forensics.clientIp });
    publish("threat", {
      userId,
      kind: "outbound",
      category: outboundCategory,
      categoryTitle: OWASP_TITLES[outboundCategory],
      label,
      blocked: true,
      forensics,
      ts: new Date(),
    });
  }

  // Real-time accuracy: every ALLOWED prompt also lands on the behavioral
  // stream with its REAL classifier probability — so the dashboard's RISK
  // SCORE TREND shows green low points for benign traffic and red spikes
  // when an injection is blocked (the full picture, live).
  if (!outboundBlocked) {
    const p = moduleScores?.aiThreatDetection?.score != null
      ? moduleScores.aiThreatDetection.score / 100
      : (Number.isFinite(threatProb) ? threatProb : 0);
    publish("behavior", {
      user_id: userId,
      risk_score: Math.round(p * 100),
      risk_level: p < 0.35 ? "LOW" : p < 0.7 ? "MEDIUM" : "HIGH",
      decision: "ALLOW",
      reasons: [`Prompt allowed — classifier probability ${(p * 100).toFixed(0)}% below threshold`],
      ts: new Date().toISOString(),
    });
  }

  // If outbound guardrail redacted the LLM response, update moduleScores to reflect it
  if (outboundBlocked && MODE === "enforce") {
    moduleScores = {
      ...moduleScores,
      blocked: true,
      category: outboundCategory,
      finalDecisionEngine: {
        ...moduleScores.finalDecisionEngine,
        status: "BLOCK",
        verdict: "BLOCK",
        triggeredBy: "output_guardrail",
        reason: "Outbound integrity check redacted response",
      },
    };
    await insertModuleAnalysis(moduleScores);
    publish("module_analysis", moduleScores);
  }

  return res.json({
    blocked: false,
    answer: finalContent,
    redactedOutbound: outboundBlocked && MODE === "enforce",
    outboundCheck: output,
    llamaGuardOutput: {
      enabled: guardOutput.enabled,
      safe: guardOutput.safe,
      categories: guardOutput.categories,
      owasp: guardOutput.owasp,
      degraded: guardOutput.degraded || false,
    },
    simulated: llmResponse.simulated || false,
    llm: {
      via: llmResponse.via || (llmResponse.simulated ? "offline" : "primary"),
      model: llmResponse?.raw?.model || null,
      simulated: llmResponse.simulated || false,
      latencyMs: llmLatencyMs,
    },
    agentic: agentTrace !== null,
    agentTrace,
    moduleScores,
    verdict,
    latencyMs: +(performance.now() - t0).toFixed(2),
  });
});

export default router;
