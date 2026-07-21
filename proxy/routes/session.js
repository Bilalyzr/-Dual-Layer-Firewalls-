/**
 * /api/session — session bootstrap + introspection (Tier 2 · EPIC A).
 *
 *   POST /api/session   → issue a fresh signed session token (called on first
 *                         client load). Optionally binds a client-supplied
 *                         userId so existing baselines/history carry over.
 *   GET  /api/session    → return the current session's state (requires a valid
 *                         token via the global sessionMiddleware).
 *
 * The token must be sent back on every subsequent request as
 * `Authorization: Bearer <token>` (or `x-session-token`).
 */
import { Router } from "express";
import { createSession } from "../auth/session.js";

const router = Router();

router.post("/", async (req, res) => {
  const userId = typeof req.body?.userId === "string" ? req.body.userId.slice(0, 64) : undefined;
  const session = await createSession({ userId });
  res.json({
    token: session.token,
    sessionId: session.sessionId,
    userId: session.userId,
    trustState: session.trustState,
  });
});

router.get("/", (req, res) => {
  if (!req.session) {
    return res.status(401).json({ error: "no_session", reason: "missing or invalid session token" });
  }
  res.json({
    sessionId: req.session.sessionId,
    userId: req.session.userId,
    trustState: req.session.trustState,
  });
});

export default router;
