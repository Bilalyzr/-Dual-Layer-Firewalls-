/**
 * Pub/sub for Server-Sent Events (Req 4.1/4.2 live feed) with an optional Redis
 * message bus for the distributed topology (Tier 2 · EPIC G).
 *
 * Two modes, selected at startup by REDIS_URL:
 *   • In-process (REDIS_URL unset) — the original behavior: publishers write
 *     straight to the locally-connected SSE clients. Perfect for the single
 *     monolith and for tests (no Redis required).
 *   • Distributed (REDIS_URL set)  — publishers fan out through a Redis channel;
 *     a relay in every process re-delivers to its local SSE clients. This is what
 *     lets a threat detected in `firewall-svc` reach a browser connected to the
 *     `gateway`, and lets the gateway scale to multiple replicas.
 *
 * The `redis` client is imported lazily and only when REDIS_URL is set, so the
 * dependency is never touched in the default/monolith/test paths. If Redis is
 * configured but unreachable, we log and fall back to in-process rather than
 * crash — matching the fail-soft posture of the rest of the stack.
 */
import { log } from "../lib/logger.js";

const subscribers = new Set();
const CHANNEL = process.env.EVENT_BUS_CHANNEL || "firewall:events";

let redisPub = null;
let redisSub = null;
let redisReady = false;

export function subscribe(res) {
  subscribers.add(res);
  res.on("close", () => subscribers.delete(res));
  return () => subscribers.delete(res);
}

function deliverLocal(line) {
  for (const res of subscribers) res.write(line);
  return subscribers.size;
}

/**
 * Publish an event. In distributed mode this goes to Redis (and comes back to
 * every process — including this one — via the relay, so delivery is exactly
 * once per SSE client). In in-process mode it writes to local clients directly.
 */
export function publish(type, payload) {
  const event = { type, ts: new Date().toISOString(), payload };
  const line = `event: ${type}\ndata: ${JSON.stringify(event)}\n\n`;
  if (redisReady && redisPub) {
    redisPub.publish(CHANNEL, line).catch((err) =>
      log.warn("event bus: publish failed", { error: String(err.message || err) })
    );
    return subscribers.size;
  }
  return deliverLocal(line);
}

export function subscriberCount() {
  return subscribers.size;
}

/** True when the Redis relay is active (distributed mode). */
export function busMode() {
  return redisReady ? "redis" : "in-process";
}

/**
 * Connect the Redis relay if REDIS_URL is set. Idempotent; safe to call once per
 * process at startup. Returns true when the distributed bus is active, false when
 * running in-process (unset URL or unreachable Redis).
 */
export async function startBusRelay() {
  if (redisReady) return true;
  const url = process.env.REDIS_URL;
  if (!url) return false; // in-process mode — nothing to wire up

  // Bail out fast if Redis is unreachable. node-redis's default reconnect
  // strategy retries forever, so a naive `await connect()` would wedge start-up
  // when Redis is down. We cap the connect with a timeout AND give up
  // reconnecting after a few tries, then fall back to in-process fan-out.
  const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || "3000", 10);
  let pub, sub, timer;
  try {
    const { createClient } = await import("redis");
    const opts = {
      url,
      socket: {
        connectTimeout: Math.min(CONNECT_TIMEOUT, 2000),
        reconnectStrategy: (retries) => (retries > 5 ? false : Math.min(retries * 200, 1000)),
      },
    };
    pub = createClient(opts);
    sub = pub.duplicate();
    pub.on("error", (e) => log.warn("event bus: redis pub error", { error: String(e.message || e) }));
    sub.on("error", (e) => log.warn("event bus: redis sub error", { error: String(e.message || e) }));

    const timeout = new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`redis connect timeout after ${CONNECT_TIMEOUT}ms`)),
        CONNECT_TIMEOUT
      );
      timer.unref?.();
    });
    await Promise.race([Promise.all([pub.connect(), sub.connect()]), timeout]);
    clearTimeout(timer);

    await sub.subscribe(CHANNEL, (line) => deliverLocal(line));
    redisPub = pub;
    redisSub = sub;
    redisReady = true;
    log.info("event bus: redis relay active", { channel: CHANNEL });
    return true;
  } catch (err) {
    clearTimeout(timer);
    log.warn("event bus: redis unavailable, using in-process fan-out", {
      error: String(err.message || err),
    });
    // Stop any background reconnection so a dead Redis never leaks timers or
    // wedges graceful shutdown.
    try { await pub?.disconnect(); } catch { /* ignore */ }
    try { await sub?.disconnect(); } catch { /* ignore */ }
    redisPub = null;
    redisSub = null;
    redisReady = false;
    return false;
  }
}

/** Tear the relay down (graceful shutdown / tests). */
export async function stopBusRelay() {
  try {
    await redisSub?.quit();
    await redisPub?.quit();
  } catch {
    /* ignore */
  }
  redisReady = false;
  redisPub = null;
  redisSub = null;
}
