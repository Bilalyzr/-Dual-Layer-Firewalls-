/**
 * Tier 3 · Wave 1 · Epic C — automated response state (bans + offense tracking).
 *
 * Moves the firewall from *observe* to *act*: an IP that trips the threshold is
 * blocked on its next request without human action, bans expire on their own, and
 * a whole /24 can be banned when several offenders share it.
 *
 * State lives in the shared store (lib/store.js → Redis when configured, else an
 * in-memory map), so it survives across the distributed services:
 *   fx:ban:<ip>        — per-IP ban marker, TTL = the ban duration (auto-expiry)
 *   fx:offenses        — sorted set (score = cumulative offences, member = IP) for
 *                        the dashboard's "top offenders" + escalation decisions
 *   fx:win:<ip>        — sliding-window offence timestamps (JSON, TTL = window)
 *   fx:banct:<ip>      — how many times this IP has been banned (escalation)
 *   fx:cidrwin:<net>   — per-/24 distinct offender window (JSON)
 *   fx:banned_cidrs    — persisted CIDR bans, hydrated into an in-memory index
 *
 * Enforcement is OFF by default (RESPONSE_MODE=off) so shadow deployments observe
 * without acting — matching firewall semantics. Every auto-ban emits an alert and
 * an SSE event, and a kill switch disables the whole engine instantly.
 */
import { log } from "../lib/logger.js";
import { insertAlert } from "../db/mongo.js";
import { publish } from "../middleware/eventBus.js";
import { normalizeIp, enclosingNetwork, ipInAnyCidr } from "../lib/cidr.js";
import {
  kvSetEx,
  kvExists,
  kvDel,
  kvGetJson,
  kvSetJson,
  zIncrBy,
  zRem,
  zEntries,
} from "../lib/store.js";

// ---- Config (read per-call so ops can toggle without a restart) ---------- //
export const responseMode = () => (process.env.RESPONSE_MODE || "off").toLowerCase(); // off|block|honeypot
const autoBanThreshold = () => parseInt(process.env.AUTO_BAN_THRESHOLD || "5", 10);
const autoBanWindowSec = () => parseInt(process.env.AUTO_BAN_WINDOW || "600", 10);
const autoBanTtlSec = () => parseInt(process.env.AUTO_BAN_TTL || "3600", 10);
const cidrThreshold = () => parseInt(process.env.AUTO_BAN_CIDR_THRESHOLD || "3", 10);
const cidrTtlSec = () => parseInt(process.env.AUTO_BAN_CIDR_TTL || String(autoBanTtlSec() * 4), 10);
export const honeypotDelayMs = () => parseInt(process.env.HONEYPOT_DELAY_MS || "1200", 10);

// Runtime kill switch: env sets the initial value; the ops endpoint can flip it
// live. When engaged the engine tracks nothing and blocks nothing.
let _killSwitch = null;
export function killSwitchEngaged() {
  if (_killSwitch !== null) return _killSwitch;
  return String(process.env.RESPONSE_KILL_SWITCH || "false").toLowerCase() === "true";
}
export function setKillSwitch(on) {
  _killSwitch = !!on;
  log.warn("response engine kill switch " + (_killSwitch ? "ENGAGED" : "released"));
  return _killSwitch;
}

/** True when auto-response should actually act (not off, not killed). */
export function autoResponseActive() {
  return responseMode() !== "off" && !killSwitchEngaged();
}

const now = () => Date.now();

// ---- In-memory CIDR ban index (hydrated from the store) ------------------ //
// A small index of active CIDR bans. Membership is checked on every guarded
// request, so it's kept in-process; the store is the source of truth across
// replicas and is re-read on hydrate. (A bit-trie is the perf upgrade if the
// banned-range count ever grows large; a scan is ample for /24-scale bans.)
let _cidrBans = []; // [{ cidr, until, reason }]
let _hydrated = false;

function pruneCidr() {
  const t = now();
  _cidrBans = _cidrBans.filter((b) => !b.until || b.until > t);
}

export async function hydrateBans() {
  const rows = (await kvGetJson("fx:banned_cidrs")) || [];
  _cidrBans = Array.isArray(rows) ? rows : [];
  pruneCidr();
  _hydrated = true;
  return _cidrBans.length;
}

async function persistCidrBans() {
  await kvSetJson("fx:banned_cidrs", cidrTtlSec(), _cidrBans);
}

async function ensureHydrated() {
  if (!_hydrated) await hydrateBans();
}

// ---- Membership ---------------------------------------------------------- //
/**
 * Is this IP banned (directly or via a banned CIDR)?
 * @returns {Promise<{ banned:boolean, scope?:string, reason?:string, cidr?:string }>}
 */
export async function isBanned(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return { banned: false };
  await ensureHydrated();
  pruneCidr();
  const hit = _cidrBans.find((b) => ipInAnyCidr(norm, b.cidr));
  if (hit) return { banned: true, scope: "cidr", cidr: hit.cidr, reason: hit.reason };
  if (await kvExists(`fx:ban:${norm}`)) return { banned: true, scope: "ip", reason: "auto-ban" };
  return { banned: false };
}

// ---- Bans ---------------------------------------------------------------- //
export async function banIp(ip, ttlSec, reason = "manual", { emit = true } = {}) {
  const norm = normalizeIp(ip);
  if (!norm) return null;
  const ttl = ttlSec || autoBanTtlSec();
  await kvSetEx(`fx:ban:${norm}`, ttl, JSON.stringify({ reason, at: new Date().toISOString(), ttl }));
  // Register in the offenses set (score unchanged) so a manual ban is enumerable
  // by listBans, which walks that set.
  await zIncrBy("fx:offenses", 0, norm);
  const until = new Date(now() + ttl * 1000).toISOString();
  if (emit) await emitBanEvent({ scope: "ip", target: norm, ttl, until, reason });
  log.warn("auto-response: banned IP", { ip: norm, ttl, reason });
  return { ip: norm, ttl, until, reason };
}

export async function banCidr(cidr, ttlSec, reason = "cidr-escalation", { emit = true } = {}) {
  await ensureHydrated();
  const ttl = ttlSec || cidrTtlSec();
  const until = now() + ttl * 1000;
  _cidrBans = _cidrBans.filter((b) => b.cidr !== cidr);
  _cidrBans.push({ cidr, until, reason });
  await persistCidrBans();
  if (emit) {
    await emitBanEvent({ scope: "cidr", target: cidr, ttl, until: new Date(until).toISOString(), reason });
  }
  log.warn("auto-response: banned CIDR", { cidr, ttl, reason });
  return { cidr, ttl, until: new Date(until).toISOString(), reason };
}

export async function unbanIp(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return false;
  await kvDel(`fx:ban:${norm}`);
  await zRem("fx:offenses", norm);
  await kvDel(`fx:win:${norm}`);
  await kvDel(`fx:banct:${norm}`);
  log.info("auto-response: unbanned IP", { ip: norm });
  return true;
}

export async function unbanCidr(cidr) {
  await ensureHydrated();
  const before = _cidrBans.length;
  _cidrBans = _cidrBans.filter((b) => b.cidr !== cidr);
  await persistCidrBans();
  const removed = _cidrBans.length < before;
  if (removed) log.info("auto-response: unbanned CIDR", { cidr });
  return removed;
}

// ---- Offense tracking + auto-ban ----------------------------------------- //
async function windowCount(key, windowSec) {
  const cutoff = now() - windowSec * 1000;
  const arr = ((await kvGetJson(key)) || []).filter((t) => t > cutoff);
  arr.push(now());
  await kvSetJson(key, windowSec, arr);
  return arr.length;
}

async function distinctOffenders(net, ip, windowSec) {
  const key = `fx:cidrwin:${net}`;
  const cutoff = now() - windowSec * 1000;
  const arr = ((await kvGetJson(key)) || []).filter((e) => e.at > cutoff);
  if (!arr.some((e) => e.ip === ip)) arr.push({ ip, at: now() });
  await kvSetJson(key, windowSec, arr);
  return new Set(arr.map((e) => e.ip)).size;
}

/**
 * Record a confirmed offence (a threat/block) from an IP. Increments the sliding
 * window; when it crosses AUTO_BAN_THRESHOLD the IP is temp-banned (TTL escalates
 * on repeat bans). When enough distinct offenders share a /24, the range is banned.
 * Purely observational (no bans) when the engine is off/killed.
 *
 * @returns {Promise<{ip, offenses, banned, ban?, cidrBan?}>}
 */
export async function recordOffense(ip) {
  const norm = normalizeIp(ip);
  if (!norm) return { ip: null, offenses: 0, banned: false };

  const cumulative = await zIncrBy("fx:offenses", 1, norm);
  const windowSec = autoBanWindowSec();
  const windowed = await windowCount(`fx:win:${norm}`, windowSec);

  const result = { ip: norm, offenses: windowed, cumulative, banned: false };
  if (!autoResponseActive()) return result; // shadow/off — track only

  // Already banned? Nothing more to do (the guard will catch the next request).
  if (await kvExists(`fx:ban:${norm}`)) {
    result.banned = true;
    return result;
  }

  if (windowed >= autoBanThreshold()) {
    // Escalate the TTL geometrically with the number of prior bans (capped 8×).
    const priorBans = Number((await kvGetJson(`fx:banct:${norm}`)) || 0);
    const factor = Math.min(2 ** priorBans, 8);
    await kvSetJson(`fx:banct:${norm}`, cidrTtlSec(), priorBans + 1);
    const ban = await banIp(norm, autoBanTtlSec() * factor, `${windowed} offences in ${windowSec}s`);
    result.banned = true;
    result.ban = ban;
  }

  // CIDR escalation: several distinct offenders in one /24 → ban the range.
  const net = enclosingNetwork(norm);
  if (net) {
    const distinct = await distinctOffenders(net, norm, windowSec);
    if (distinct >= cidrThreshold()) {
      const already = _cidrBans.some((b) => b.cidr === net);
      if (!already) {
        result.cidrBan = await banCidr(net, cidrTtlSec(), `${distinct} distinct offenders in ${net}`);
      }
    }
  }

  return result;
}

// ---- Ops read model ------------------------------------------------------ //
export async function listBans() {
  await ensureHydrated();
  pruneCidr();
  const offenders = await zEntries("fx:offenses");
  const ips = [];
  for (const { member, score } of offenders.slice(0, 100)) {
    if (await kvExists(`fx:ban:${member}`)) {
      const meta = (await kvGetJson(`fx:ban:${member}`)) || {};
      ips.push({ ip: member, offenses: score, reason: meta.reason || "auto-ban" });
    }
  }
  return {
    mode: responseMode(),
    killSwitch: killSwitchEngaged(),
    ips,
    cidrs: _cidrBans.map((b) => ({ cidr: b.cidr, reason: b.reason, until: new Date(b.until).toISOString() })),
    topOffenders: offenders.slice(0, 20),
  };
}

async function emitBanEvent({ scope, target, ttl, until, reason }) {
  const alert = {
    kind: "autoban",
    category: "LLM10", // Unbounded Consumption / abusive volume
    categoryTitle: "Automated IP ban",
    label: `Auto-banned ${scope} ${target} — ${reason}`,
    scope,
    target,
    banTtlSec: ttl,
    banUntil: until,
    mode: responseMode(),
    blocked: true,
    forensics: scope === "ip" ? { clientIp: target } : null,
    ts: new Date(),
  };
  try {
    await insertAlert(alert);
    publish("ban", alert);
    publish("threat", alert); // surface in the existing threat feed too
  } catch (err) {
    log.warn("auto-response: failed to emit ban event", { error: String(err.message || err) });
  }
}

/** Test hook: drop the in-memory CIDR index + kill-switch override. */
export function __resetBanStoreForTests() {
  _cidrBans = [];
  _hydrated = false;
  _killSwitch = null;
}
