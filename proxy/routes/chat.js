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
import { checkOutput } from "../firewall/outputCheck.js";
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
  const userId = req.body?.userId || "anon";
  const prompt = req.body?.prompt || "";

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

  // 1.2 + 1.3 — heuristic + ML, run in parallel
  const [heuristic, classification] = await Promise.all([
    runHeuristics(prompt),
    classifyPrompt(prompt),
  ]);

  const threatProb = classification.threatProbability || 0;
  const engineReady = classification.ready !== false;

  const MODE = mode();
  const THRESHOLD = threshold();
  const SAMPLE_RATE = sampleRate();

  // Threat if heuristics matched OR ML probability crosses threshold.
  const heuristicThreat = heuristic.matched;
  const mlThreat = engineReady && threatProb >= THRESHOLD;
  const isThreat = heuristicThreat || mlThreat;

  // Pick a category for the dashboard.
  const category = heuristic.signals[0]?.category || (mlThreat ? "LLM01" : null);
  const verdict = {
    mode: MODE,
    threshold: THRESHOLD,
    heuristic: { matched: heuristicThreat, signals: heuristic.signals, latencyMs: heuristic.latencyMs },
    classifier: { threatProbability: threatProb, latencyMs: classification.latencyMs, ready: engineReady },
    threat: isThreat,
    category,
  };

  // ---- Decision: shadow logs but does not block. ----
  const willBlock = isThreat && MODE === "enforce";

  if (isThreat) {
    const label =
      heuristic.signals[0]?.label ||
      `ML-classified prompt injection (p=${threatProb.toFixed(2)})`;
    const alert = {
      userId,
      kind: heuristicThreat ? "heuristic" : "ml",
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

  // 1.4 outbound integrity check on the response.
  const output = checkOutput(llmResponse.content);
  let finalContent = llmResponse.content;
  if (output.blocked && MODE === "enforce") {
    finalContent =
      "[Response redacted by firewall outbound integrity check: " +
      output.reasons.join(", ") + "]";
    await insertAlert({
      userId,
      kind: "outbound",
      category: "LLM02",
      categoryTitle: OWASP_TITLES.LLM02,
      label: "Outbound exfiltration/tool-call blocked",
      reasons: output.reasons,
      snippets: output.snippets,
      mode: MODE,
      blocked: true,
      ts: new Date(),
    });
    publish("threat", {
      userId,
      kind: "outbound",
      category: "LLM02",
      categoryTitle: OWASP_TITLES.LLM02,
      label: "Outbound exfiltration/tool-call blocked",
      blocked: true,
      ts: new Date(),
    });
  }

  return res.json({
    blocked: false,
    answer: finalContent,
    redactedOutbound: output.blocked && MODE === "enforce",
    outboundCheck: output,
    simulated: llmResponse.simulated || false,
    agentic: agentTrace !== null,
    agentTrace,
    verdict,
    latencyMs: +(performance.now() - t0).toFixed(2),
  });
});

export default router;
