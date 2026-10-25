/**
 * /api/events — Server-Sent Events stream (Req 4.1/4.2 live dashboard feed).
 */
import { Router } from "express";
import { subscribe, subscriberCount } from "../middleware/eventBus.js";

const router = Router();

router.get("/", (req, res) => {
  // Prevent legacy/multiple tabs from exhausting the browser's 6-connection
  // HTTP/1.1 pool. Returning 204 No Content tells EventSource to stop
  // reconnecting permanently per the WHATWG SSE specification.
  if ((!req.query?.v && subscriberCount() >= 1) || subscriberCount() >= 3) {
    return res.status(204).end();
  }
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
  // Keepalive ping every 25s. Guard the write: if the socket died between ticks,
  // writing throws — stop pinging rather than let the error propagate.
  const ka = setInterval(() => {
    try {
      res.write(`: keepalive\n\n`);
    } catch {
      clearInterval(ka);
    }
  }, 25000);
  const stop = () => clearInterval(ka);
  req.on("close", stop);
  res.on("error", stop);
});

router.get("/subscribers", (_req, res) => {
  res.json({ subscribers: subscriberCount() });
});

export default router;
