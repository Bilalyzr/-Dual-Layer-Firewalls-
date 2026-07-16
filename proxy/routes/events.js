/**
 * /api/events — Server-Sent Events stream (Req 4.1/4.2 live dashboard feed).
 */
import { Router } from "express";
import { subscribe, subscriberCount } from "../middleware/eventBus.js";

const router = Router();

router.get("/", (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders?.();
  // Initial hello so EventSource.onopen fires reliably.
  res.write(`event: hello\ndata: ${JSON.stringify({ connected: true })}\n\n`);
  subscribe(res);
  // Keepalive ping every 25s.
  const ka = setInterval(() => res.write(`: keepalive\n\n`), 25000);
  req.on("close", () => clearInterval(ka));
});

router.get("/subscribers", (_req, res) => {
  res.json({ subscribers: subscriberCount() });
});

export default router;
