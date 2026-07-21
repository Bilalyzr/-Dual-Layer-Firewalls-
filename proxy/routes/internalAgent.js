/**
 * Internal Trifecta endpoint for the dedicated agent service (Tier 2 · EPIC G).
 *
 * In the distributed topology the firewall service delegates agentic prompts to
 * `agent-svc` over HTTP (see agents/orchestrator.js), mirroring the reader-svc
 * split from EPIC E. This route is NOT exposed publicly by the gateway — it lives
 * on the internal service network only.
 *
 * Agent-stage audit events are published straight to the shared event bus so the
 * dashboard Agent Audit Trail sees the full reasoning chain regardless of which
 * service produced it.
 */
import { Router } from "express";
import { runTrifecta } from "../agents/orchestrator.js";
import { publish } from "../middleware/eventBus.js";

const router = Router();

const mask = (t, n = 80) =>
  typeof t === "string" && t.length > n ? t.slice(0, n) + "…" : t || "";

router.post("/run", async (req, res) => {
  const prompt = req.body?.prompt;
  const userId = req.body?.userId || "anon";
  if (!prompt || typeof prompt !== "string") {
    return res.status(400).json({ error: "missing 'prompt'" });
  }
  try {
    const result = await runTrifecta({
      prompt,
      userId,
      emit: (ev) =>
        publish("agent", { userId, ...ev, promptPreview: mask(prompt), ts: new Date() }),
    });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: "agent_error", detail: String(err.message || err) });
  }
});

export default router;
