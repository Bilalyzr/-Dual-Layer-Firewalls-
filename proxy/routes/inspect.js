/**
 * /api/inspect — lightweight firewall-only scan (no LLM call).
 *
 * Runs the inbound heuristic + ML pipeline but does NOT forward to the LLM
 * backend. Used by scripts/benchmark.js for latency/throughput measurement so
 * those numbers reflect the *firewall's* performance, not the LLM's latency.
 *
 * Returns the same verdict shape as /api/chat.
 */
import { Router } from "express";
import { runHeuristics, OWASP_TITLES } from "../firewall/heuristics.js";
import { classifyPrompt } from "../firewall/mlClient.js";

const router = Router();

const threshold = () => parseFloat(process.env.FIREWALL_THRESHOLD || "0.65");

function mask(text, n = 200) {
  if (typeof text !== "string") return "";
  return text.length > n ? text.slice(0, n) + "…" : text;
}

router.post("/", async (req, res) => {
  const t0 = performance.now();
  const prompt = req.body?.prompt || "";
  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    return res.status(400).json({ error: "missing 'prompt'" });
  }
  const MAX_PROMPT = parseInt(process.env.MAX_PROMPT_CHARS || "4000", 10);
  if (prompt.length > MAX_PROMPT) {
    return res.status(413).json({ error: "prompt too large", limit: MAX_PROMPT });
  }
  const THRESHOLD = threshold();
  const [heuristic, classification] = await Promise.all([
    runHeuristics(prompt),
    classifyPrompt(prompt),
  ]);
  const threatProb = classification.threatProbability || 0;
  const engineReady = classification.ready !== false;
  const heuristicThreat = heuristic.matched;
  const mlThreat = engineReady && threatProb >= THRESHOLD;
  const isThreat = heuristicThreat || mlThreat;
  const category = heuristic.signals[0]?.category || (mlThreat ? "LLM01" : null);

  return res.json({
    threat: isThreat,
    blocked: isThreat && (process.env.FIREWALL_MODE || "shadow").toLowerCase() === "enforce",
    category,
    categoryTitle: OWASP_TITLES[category] || null,
    prompt: mask(prompt),
    verdict: {
      threshold: THRESHOLD,
      heuristic: { matched: heuristicThreat, latencyMs: heuristic.latencyMs },
      classifier: { threatProbability: threatProb, latencyMs: classification.latencyMs, ready: engineReady },
    },
    latencyMs: +(performance.now() - t0).toFixed(2),
  });
});

export default router;
