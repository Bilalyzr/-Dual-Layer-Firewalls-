/**
 * Tier 3 · Wave 2 · Epic E — automated-client (bot) scoring.
 *
 * Humans and scripts leave different traffic shapes. This scores each client on
 * three request-path-cheap signals and, when the score crosses a threshold, feeds
 * the finding to the auto-response engine (Epic C `recordOffense`) — it does NOT
 * block directly, so a single knob (RESPONSE_MODE) still governs whether scoring
 * ever results in a ban. Observe-by-default: BOT_SCORE_ENABLED=false.
 *
 * Signals:
 *   • Cadence — a per-IP sliding window of request timestamps (shared store). A
 *     mean gap below CADENCE_MIN_INTERVAL_MS ("too fast") or a near-zero interval
 *     variance ("too regular" — a cron/loop, not a human) both score.
 *   • TLS fingerprint — a JA3/JA4 hash exported by the nginx edge in X-JA3 / X-JA4.
 *     A hash on the JA3_BLOCKLIST (known bot/automation stacks) scores heavily.
 *
 * Client-side (canvas/WebGL/audio) fingerprinting is intentionally NOT here — it is
 * personal data under GDPR and gated on the Epic I consent pipeline (see docs).
 */
import { kvGetJson, kvSetJson } from "../lib/store.js";
import { recordOffense } from "../response/banStore.js";
import { publish } from "./eventBus.js";
import { normalizeIp } from "../lib/cidr.js";
import { log } from "../lib/logger.js";
import { readFileSync, existsSync } from "node:fs";

const EXEMPT = new Set(["/", "/healthz", "/metrics"]);

export function botScoreEnabled() {
  return String(process.env.BOT_SCORE_ENABLED || "false").toLowerCase() === "true";
}
const windowSec = () => parseInt(process.env.CADENCE_WINDOW || "60", 10);
const minIntervalMs = () => parseInt(process.env.CADENCE_MIN_INTERVAL_MS || "300", 10);
const cvThreshold = () => parseFloat(process.env.CADENCE_CV_THRESHOLD || "0.12");
const scoreThreshold = () => parseInt(process.env.BOT_SCORE_THRESHOLD || "60", 10);
const minSamples = () => parseInt(process.env.CADENCE_MIN_SAMPLES || "5", 10);

// ---- JA3/JA4 blocklist (inline env list and/or a file) ------------------- //
let _ja3Set = null;
let _ja3LoadedFrom = null;
function ja3Blocklist() {
  const inline = (process.env.JA3_BLOCKLIST || "")
    .split(/[,\s]+/)
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  const path = process.env.JA3_BLOCKLIST_PATH || "";
  const key = `${path}::${inline.join(",")}`;
  if (_ja3Set && _ja3LoadedFrom === key) return _ja3Set;
  const set = new Set(inline);
  if (path && existsSync(path)) {
    try {
      for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
        const h = line.trim().toLowerCase();
        if (h && !h.startsWith("#")) set.add(h);
      }
    } catch {
      /* fail open — ignore an unreadable list */
    }
  }
  _ja3Set = set;
  _ja3LoadedFrom = key;
  return set;
}

/**
 * Record a request timestamp for an IP and return cadence stats over the window.
 * @returns {Promise<{count:number, meanIntervalMs:number|null, cv:number|null}>}
 */
export async function recordCadence(ip, ts = Date.now()) {
  const key = `fx:cad:${ip}`;
  const cutoff = ts - windowSec() * 1000;
  const arr = ((await kvGetJson(key)) || []).filter((t) => t > cutoff);
  arr.push(ts);
  await kvSetJson(key, windowSec(), arr);

  if (arr.length < 2) return { count: arr.length, meanIntervalMs: null, cv: null };
  const intervals = [];
  for (let i = 1; i < arr.length; i++) intervals.push(arr[i] - arr[i - 1]);
  const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
  const cv = mean > 0 ? Math.sqrt(variance) / mean : null;
  return { count: arr.length, meanIntervalMs: mean, cv };
}

/**
 * Compute a bot score (0..100) for a request from its cadence + TLS fingerprint.
 * Pure enough to unit-test: pass the header values in via `req`-like object.
 * @returns {Promise<{ score:number, bot:boolean, signals:string[], cadence:object, ja3?:string }>}
 */
export async function evaluateBot(ip, headers = {}) {
  const signals = [];
  let score = 0;

  const cadence = await recordCadence(ip);
  if (cadence.count >= minSamples()) {
    if (cadence.meanIntervalMs != null && cadence.meanIntervalMs < minIntervalMs()) {
      score += 40;
      signals.push("too-fast");
    }
    if (cadence.cv != null && cadence.cv < cvThreshold()) {
      score += 40;
      signals.push("too-regular");
    }
  }

  const ja3 = (headers["x-ja3"] || headers["x-ja4"] || "").toString().trim().toLowerCase();
  if (ja3 && ja3Blocklist().has(ja3)) {
    score += 70;
    signals.push("ja3-blocklist");
  }

  score = Math.min(100, score);
  return { score, bot: score >= scoreThreshold(), signals, cadence, ja3: ja3 || null };
}

/** Express middleware: score the client and feed Epic C. Never blocks directly. */
export function botScoreMiddleware(req, _res, next) {
  if (!botScoreEnabled()) return next();
  const path = req.path || req.url || "";
  if (EXEMPT.has(path)) return next();
  const ip = normalizeIp(req.ipContext?.clientIp || "");
  if (!ip) return next();

  // Detach: scoring must never add latency or fail the request.
  evaluateBot(ip, req.headers || {})
    .then((result) => {
      req.botScore = result;
      if (!result.bot) return;
      publish("bot_detected", { ip, score: result.score, signals: result.signals, path, ts: new Date().toISOString() });
      log.warn("bot score: automated client", { ip, score: result.score, signals: result.signals });
      // Feed the auto-response engine — it bans only if RESPONSE_MODE is on.
      recordOffense(ip).catch(() => {});
    })
    .catch((err) => log.debug("bot score: eval failed", { ip, error: String(err.message || err) }));

  // Do not wait on the scorer.
  next();
}

/** Test hook: forget the cached JA3 blocklist. */
export function __resetJa3Cache() {
  _ja3Set = null;
  _ja3LoadedFrom = null;
}
