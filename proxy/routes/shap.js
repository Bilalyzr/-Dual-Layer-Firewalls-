/**
 * /api/shap/:requestId — passthrough to the engine's async SHAP store (Req 3.4).
 *
 * The engine computes SHAP off the scoring path and stores it by request id;
 * the dashboard polls here to render the explanation once it's ready.
 */
import { Router } from "express";

const router = Router();
const ENGINE_URL = process.env.ENGINE_URL || "http://localhost:8011";

router.get("/:requestId", async (req, res) => {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 2000);
  try {
    const r = await fetch(`${ENGINE_URL}/shap/${encodeURIComponent(req.params.requestId)}`, {
      signal: ctrl.signal,
    });
    const body = await r.json();
    return res.json(body);
  } catch (err) {
    return res.json({ status: "error", error: String(err.message || err) });
  } finally {
    clearTimeout(timeout);
  }
});

export default router;
