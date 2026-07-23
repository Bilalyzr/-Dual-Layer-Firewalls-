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
import { moderateContent } from "../firewall/llamaGuard.js";
import { chatCompletion } from "../llm/client.js";
import { isAgentic, runTrifecta } from "../agents/orchestrator.js";
import { insertAlert, insertSample } from "../db/mongo.js";
import { publish } from "../middleware/eventBus.js";

const router = Router();

// Read mode/threshold per-request so SecOps can toggle (and tests can vary it)
// without a process restart.
const mode = () => (process.env.FIREWALL_MODE || "shadow").toLowerCase(); // shadow | enforce
const threshold = () => parseFloat(process.env.FIREWALL_THRESHOLD || "0.65");
const sampleRate = () => parseFloat(process.env.ADVERSARIAL_SAMPLE_RATE || "0.05");

function mask(text, n = 200) {
  if (typeof text !== "string") return "";
  return text.length > n ? text.slice(0, n) + "…" : text;
}

router.post("/", async (req, res) => {
  const t0 = performance.now();
  // Prefer the verified session identity (EPIC A) over the client-supplied
  // userId. Falls back to the bare userId so unauthenticated demo flows work.
  const session = req.session || null;
  const userId = session?.userId || req.body?.userId || "anon";
  const sessionId = session?.sessionId || null;
  const prompt = req.body?.prompt || "";

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
    return res.status(413).json({
      error: "prompt too large",
      limit: MAX_PROMPT,
      length: prompt.length,
    });
  }

  const MODE = mode();
  const THRESHOLD = threshold();
  const SAMPLE_RATE = sampleRate();

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
      ts: new Date(),
    };
    await insertAlert(alert);
    publish("threat", alert);
    console.warn(`[firewall] ENFORCE BLOCK [${category}] ${label} (heuristic short-circuit)`);
    return res.json({
      blocked: true,
      reason: "blocked by AI firewall",
      category,
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
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

  const threatProb = classification.threatProbability || 0;
  const engineReady = classification.ready !== false;

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
    threat: isThreat,
    category,
  };

  // ---- Decision: shadow logs but does not block. ----
  const willBlock = isThreat && MODE === "enforce";

  if (isThreat) {
    const guardLabel = guardInput.degraded
      ? "Llama Guard endpoint degraded (fail-closed)"
      : `Llama Guard flagged unsafe content [${guardInput.categories.join(",")}]`;
    const label =
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
      ts: new Date(),
    };
    await insertAlert(alert);
    publish("threat", alert);
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
    return res.json({
      blocked: true,
      reason: "blocked by AI firewall",
      category,
      categoryTitle: OWASP_TITLES[category] || "Prompt Injection",
      verdict,
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // Allowed → forward to LLM backend.
  // Phase 5: agentic prompts (untrusted content + implied action) route through
  // the Trifecta Reader→Validator→Actor flow; normal Q&A bypasses to a direct
  // LLM call. Both paths return {content, raw} so the outbound check is shared.
  let llmResponse;
  let agentTrace = null;
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
        ts: new Date(),
      });
    } else {
      llmResponse = await chatCompletion(prompt);
    }
  } catch (err) {
    return res.status(502).json({
      blocked: false,
      error: "LLM backend error",
      detail: String(err.message || err),
      verdict,
      latencyMs: +(performance.now() - t0).toFixed(2),
    });
  }

  // 1.4 outbound integrity check on the response — regex + Llama Guard, parallel.
  const [output, guardOutput] = await Promise.all([
    Promise.resolve(checkOutput(llmResponse.content)),
    moderateContent({ text: llmResponse.content, role: "assistant" }),
  ]);
  const guardOutputUnsafe =
    guardOutput.enabled && (!guardOutput.safe || (guardOutput.degraded && MODE === "enforce"));
  const outboundBlocked = output.blocked || guardOutputUnsafe;
  const outboundCategory = output.blocked ? "LLM02" : guardOutput.owasp?.[0]?.owasp || "LLM05";

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
    await insertAlert({
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
      ts: new Date(),
    });
    publish("threat", {
      userId,
      kind: "outbound",
      category: outboundCategory,
      categoryTitle: OWASP_TITLES[outboundCategory],
      label,
      blocked: true,
      ts: new Date(),
    });
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
    agentic: agentTrace !== null,
    agentTrace,
    verdict,
    latencyMs: +(performance.now() - t0).toFixed(2),
  });
});

export default router;
