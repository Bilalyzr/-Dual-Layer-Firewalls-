/**
 * Tier 3 · Wave 1 — shared Redis store with an in-memory fallback.
 *
 * Two Tier-3 features need a small amount of shared, TTL'd state:
 *   • Epic B  — cache IP reputation lookups so an external API is hit at most once
 *               per IP per TTL (and NEVER on the request path).
 *   • Epic C  — an offense sorted-set (score = offence count, member = IP) plus
 *               per-IP ban keys backing the edge ipGuard.
 *
 * The existing event bus (middleware/eventBus.js) already owns Redis pub/sub, but
 * a subscribed connection can't run ordinary commands, so a dedicated *command*
 * client is the standard pattern. Same REDIS_URL, same fail-soft posture: if
 * Redis is unset or unreachable we transparently use process-local Maps, so the
 * monolith and the whole test suite work with zero external dependencies.
 *
 * Everything here is async and never throws — a Redis hiccup degrades to the
 * in-memory path rather than surfacing to a caller on a security-critical path.
 */
import { log } from "./logger.js";

let client = null;
let ready = false;
let connecting = null;

// ---- In-memory fallbacks ------------------------------------------------- //
const kv = new Map(); // key -> { value:string, expireAt:number|0 }
const zsets = new Map(); // key -> { members:Map<member,score>, expireAt:number|0 }

function now() {
  return Date.now();
}

function kvLive(key) {
  const e = kv.get(key);
  if (!e) return null;
  if (e.expireAt && e.expireAt <= now()) {
    kv.delete(key);
    return null;
  }
  return e;
}

function zLive(key) {
  const e = zsets.get(key);
  if (!e) return null;
  if (e.expireAt && e.expireAt <= now()) {
    zsets.delete(key);
    return null;
  }
  return e;
}

/**
 * Connect the command client if REDIS_URL is set. Idempotent, timeout-capped, and
 * falls back to memory on any failure (mirrors eventBus.startBusRelay's posture).
 */
export async function connectStore() {
  if (ready) return true;
  if (connecting) return connecting;
  const url = process.env.REDIS_URL;
  if (!url) return false; // memory mode

  const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || "3000", 10);
  connecting = (async () => {
    let c, timer;
    try {
      const { createClient } = await import("redis");
      c = createClient({
        url,
        socket: {
          connectTimeout: Math.min(CONNECT_TIMEOUT, 2000),
          reconnectStrategy: (retries) => (retries > 5 ? false : Math.min(retries * 200, 1000)),
        },
      });
      c.on("error", (e) => log.warn("store: redis error", { error: String(e.message || e) }));
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`redis connect timeout ${CONNECT_TIMEOUT}ms`)), CONNECT_TIMEOUT);
        timer.unref?.();
      });
      await Promise.race([c.connect(), timeout]);
      clearTimeout(timer);
      client = c;
      ready = true;
      log.info("store: redis command client active");
      return true;
    } catch (err) {
      clearTimeout(timer);
      log.warn("store: redis unavailable, using in-memory store", { error: String(err.message || err) });
      try { await c?.disconnect(); } catch { /* ignore */ }
      client = null;
      ready = false;
      return false;
    } finally {
      connecting = null;
    }
  })();
  return connecting;
}

/** True when the Redis command client is live (else memory mode). */
export function storeMode() {
  return ready ? "redis" : "memory";
}

// ---- Key/value with TTL -------------------------------------------------- //
export async function kvSetEx(key, ttlSec, value) {
  const v = typeof value === "string" ? value : JSON.stringify(value);
  if (ready && client) {
    try { await client.set(key, v, { EX: ttlSec }); return; } catch { /* fall through */ }
  }
  kv.set(key, { value: v, expireAt: ttlSec > 0 ? now() + ttlSec * 1000 : 0 });
}

export async function kvGet(key) {
  if (ready && client) {
    try { return await client.get(key); } catch { /* fall through */ }
  }
  return kvLive(key)?.value ?? null;
}

/** JSON convenience wrappers around kvGet/kvSetEx. */
export async function kvGetJson(key) {
  const raw = await kvGet(key);
  if (raw == null) return null;
  try { return JSON.parse(raw); } catch { return null; }
}
export async function kvSetJson(key, ttlSec, obj) {
  await kvSetEx(key, ttlSec, JSON.stringify(obj));
}

export async function kvDel(key) {
  if (ready && client) {
    try { await client.del(key); return; } catch { /* fall through */ }
  }
  kv.delete(key);
}

export async function kvExists(key) {
  if (ready && client) {
    try { return (await client.exists(key)) === 1; } catch { /* fall through */ }
  }
  return kvLive(key) != null;
}

// ---- Sorted set (offense counters) --------------------------------------- //
export async function zIncrBy(key, increment, member) {
  if (ready && client) {
    try { return await client.zIncrBy(key, increment, member); } catch { /* fall through */ }
  }
  const e = zLive(key) || { members: new Map(), expireAt: 0 };
  const next = (e.members.get(member) || 0) + increment;
  e.members.set(member, next);
  zsets.set(key, e);
  return next;
}

export async function zScore(key, member) {
  if (ready && client) {
    try { const s = await client.zScore(key, member); return s == null ? null : Number(s); } catch { /* fall through */ }
  }
  const e = zLive(key);
  const s = e?.members.get(member);
  return s == null ? null : s;
}

export async function zRem(key, member) {
  if (ready && client) {
    try { await client.zRem(key, member); return; } catch { /* fall through */ }
  }
  zLive(key)?.members.delete(member);
}

/** Return [{ member, score }] sorted by score descending. */
export async function zEntries(key) {
  if (ready && client) {
    try {
      const arr = await client.zRangeWithScores(key, 0, -1);
      return arr.map((x) => ({ member: x.value, score: Number(x.score) })).sort((a, b) => b.score - a.score);
    } catch { /* fall through */ }
  }
  const e = zLive(key);
  if (!e) return [];
  return [...e.members.entries()].map(([member, score]) => ({ member, score })).sort((a, b) => b.score - a.score);
}

export async function expire(key, ttlSec) {
  if (ready && client) {
    try { await client.expire(key, ttlSec); return; } catch { /* fall through */ }
  }
  const e = kvLive(key);
  if (e) e.expireAt = now() + ttlSec * 1000;
  const z = zLive(key);
  if (z) z.expireAt = now() + ttlSec * 1000;
}

/** Tear down (graceful shutdown / tests). Also clears the memory maps. */
export async function stopStore() {
  try { await client?.quit(); } catch { /* ignore */ }
  client = null;
  ready = false;
  kv.clear();
  zsets.clear();
}

/** Test hook: wipe in-memory state without touching a real Redis. */
export function __clearMemoryStore() {
  kv.clear();
  zsets.clear();
}
