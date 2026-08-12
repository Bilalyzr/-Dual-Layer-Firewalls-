/**
 * /api/behavior — Behavioral Risk Analysis routes (PRD §42).
 *
 * Proxies behavioral analysis requests to the engine and publishes decisions
 * to the SSE stream so the dashboard can render the risk panel live.
 */
import { Router } from "express";
import { publish } from "../middleware/eventBus.js";

const router = Router();
const ENGINE_URL = process.env.ENGINE_URL || "http://localhost:8011";

router.post("/analyze", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(15000),
    });
    const data = await r.json();
    // Publish to SSE for live dashboard updates
    publish("behavior", { ...data, ts: new Date() });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: "behavior engine error", detail: String(err.message || err) });
  }
});

router.post("/event", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(15000),
    });
    const data = await r.json();
    // Publish the decision to SSE so the dashboard updates live.
    if (data?.decision) publish("behavior", { ...data.decision, ts: new Date() });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: "behavior engine error", detail: String(err.message || err) });
  }
});

router.get("/events", async (req, res) => {
  try {
    const qs = new URLSearchParams();
    if (req.query.user_id) qs.set("user_id", req.query.user_id);
    if (req.query.risk_level) qs.set("risk_level", req.query.risk_level);
    if (req.query.limit) qs.set("limit", req.query.limit);
    const r = await fetch(`${ENGINE_URL}/behavior/events?${qs.toString()}`, {
      signal: AbortSignal.timeout(5000),
    });
    res.json(await r.json());
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

router.get("/stats", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/stats`, {
      signal: AbortSignal.timeout(5000),
    });
    res.json(await r.json());
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

router.get("/profile/:userId", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/profile/${req.params.userId}`, {
      signal: AbortSignal.timeout(5000),
    });
    res.json(await r.json());
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

router.get("/risk/:userId", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/risk/${req.params.userId}`, {
      signal: AbortSignal.timeout(5000),
    });
    res.json(await r.json());
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

router.post("/recalculate", async (req, res) => {
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/recalculate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(5000),
    });
    res.json(await r.json());
  } catch (err) {
    res.status(502).json({ error: String(err.message || err) });
  }
});

export default router;
