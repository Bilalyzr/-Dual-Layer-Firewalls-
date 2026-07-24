/**
 * Tier 3 · Wave 1 · Epic B — IP reputation (AbuseIPDB + proxy/VPN/Tor flags).
 *
 * Two external signals, both OPTIONAL and both CACHED in the shared store so an
 * IP is looked up at most once per ENRICHMENT_CACHE_TTL. This module is only ever
 * called out-of-band (post-response) — it must never sit on the request path.
 *
 *   • AbuseIPDB  — confidence score (0..100) + previous-report count (ABUSEIPDB_KEY).
 *   • proxycheck.io — VPN/proxy classification (PROXYCHECK_KEY). A local Tor
 *     exit-node list (TOR_EXIT_LIST_PATH) is checked with no network call.
 *
 * When a key is absent that signal is skipped (source stays null) — demo-safe,
 * matching the Tier-2 fallback convention. Fail-open: any API error yields the
 * neutral default rather than throwing.
 */
import { readFileSync, existsSync } from "node:fs";
import { kvGetJson, kvSetJson } from "../lib/store.js";
import { normalizeIp } from "../lib/cidr.js";
import { log } from "../lib/logger.js";

const abuseKey = () => process.env.ABUSEIPDB_KEY || "";
const proxycheckKey = () => process.env.PROXYCHECK_KEY || "";
const torListPath = () => process.env.TOR_EXIT_LIST_PATH || "";
const cacheTtl = () => parseInt(process.env.ENRICHMENT_CACHE_TTL || "86400", 10);

const NEUTRAL = {
  abuseScore: null,
  previousOffenses: null,
  vpnDetected: false,
  torExit: false,
  proxyType: null,
  usageType: null,
  sources: [],
};

let _torSet = null;
let _torLoadedFrom = null;
function torExitSet() {
  const path = torListPath();
  if (!path) return null;
  if (_torSet && _torLoadedFrom === path) return _torSet;
  try {
    if (!existsSync(path)) return null;
    const lines = readFileSync(path, "utf8").split(/\r?\n/);
    _torSet = new Set(lines.map((l) => normalizeIp(l.trim())).filter(Boolean));
    _torLoadedFrom = path;
    return _torSet;
  } catch {
    return null;
  }
}

async function fetchJson(url, opts, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...opts, signal: ctrl.signal });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (err) {
    log.debug("forensics: reputation fetch failed", { url, error: String(err.message || err) });
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function fromAbuseIpDb(ip) {
  const key = abuseKey();
  if (!key) return null;
  const j = await fetchJson(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { headers: { Key: key, Accept: "application/json" } }
  );
  const d = j?.data;
  if (!d) return null;
  return {
    abuseScore: typeof d.abuseConfidenceScore === "number" ? d.abuseConfidenceScore : null,
    previousOffenses: typeof d.totalReports === "number" ? d.totalReports : null,
    torExit: !!d.isTor,
    usageType: d.usageType || null,
    source: "abuseipdb",
  };
}

async function fromProxycheck(ip) {
  const key = proxycheckKey();
  if (!key) return null;
  const j = await fetchJson(
    `https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}&vpn=1&risk=1`,
    {}
  );
  const rec = j?.[ip];
  if (!rec) return null;
  return {
    vpnDetected: rec.proxy === "yes",
    proxyType: rec.type || null,
    source: "proxycheck",
  };
}

/**
 * Combined reputation for an IP, cached in the shared store.
 * @returns {Promise<typeof NEUTRAL>}
 */
export async function lookupReputation(ip) {
  if (!ip) return { ...NEUTRAL };
  const cacheKey = `fx:rep:${ip}`;
  const cached = await kvGetJson(cacheKey);
  if (cached) return cached;

  const out = { ...NEUTRAL };
  const [abuse, proxy] = await Promise.all([fromAbuseIpDb(ip), fromProxycheck(ip)]);

  if (abuse) {
    out.abuseScore = abuse.abuseScore;
    out.previousOffenses = abuse.previousOffenses;
    out.torExit = out.torExit || abuse.torExit;
    out.usageType = abuse.usageType;
    out.sources.push("abuseipdb");
  }
  if (proxy) {
    out.vpnDetected = proxy.vpnDetected;
    out.proxyType = proxy.proxyType;
    out.sources.push("proxycheck");
  }

  const tor = torExitSet();
  if (tor) {
    out.sources.push("tor-list");
    if (tor.has(normalizeIp(ip))) {
      out.torExit = true;
      out.vpnDetected = true;
    }
  }

  // Cache even a fully-neutral result so we don't retry unconfigured lookups per
  // request; a short TTL is fine because it just avoids redundant no-op work.
  await kvSetJson(cacheKey, cacheTtl(), out);
  return out;
}

/** Test hook: forget the loaded Tor exit list. */
export function __resetTorCache() {
  _torSet = null;
  _torLoadedFrom = null;
}
