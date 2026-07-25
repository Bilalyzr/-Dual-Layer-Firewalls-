/**
 * Tier 3 · Wave 2 · Epic E — DNSBL (DNS blocklist) check.
 *
 * Asks well-known DNS blocklists (Spamhaus ZEN, Barracuda, SpamCop, …) whether an
 * IP is a known-bad source. The check is a reverse-octet A-record lookup:
 *   1.2.3.4  →  4.3.2.1.zen.spamhaus.org   (an answer of 127.0.0.x = listed).
 *
 * Two hard rules keep this safe on a security-critical edge:
 *   • CACHED in the shared store (Redis/in-mem) — an IP is queried at most once per
 *     DNSBL_CACHE_TTL, and never re-queried on the hot path once cached.
 *   • FAIL-OPEN with a short timeout — a slow/broken resolver yields "not listed"
 *     rather than blocking legitimate traffic or throwing.
 *
 * Disabled by default (DNSBL_ENABLED=false): DNS blocklists are noisy for consumer
 * IPs, so an operator opts in explicitly. Private/loopback IPs are never queried.
 */
import dns from "node:dns";
import { kvGetJson, kvSetJson } from "../lib/store.js";
import { ipToBytes } from "../lib/cidr.js";
import { log } from "../lib/logger.js";

const resolver = dns.promises;

export function dnsblEnabled() {
  return String(process.env.DNSBL_ENABLED || "false").toLowerCase() === "true";
}
const zones = () =>
  (process.env.DNSBL_ZONES || "zen.spamhaus.org,b.barracudacentral.org")
    .split(/[,\s]+/)
    .map((z) => z.trim())
    .filter(Boolean);
const cacheTtl = () => parseInt(process.env.DNSBL_CACHE_TTL || "3600", 10);
const timeoutMs = () => parseInt(process.env.DNSBL_TIMEOUT_MS || "1500", 10);

function isPrivateV4(bytes) {
  if (bytes[0] === 10 || bytes[0] === 127) return true;
  if (bytes[0] === 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
  if (bytes[0] === 192 && bytes[1] === 168) return true;
  if (bytes[0] === 169 && bytes[1] === 254) return true;
  return false;
}

/** Reverse a dotted-quad for a DNSBL query (1.2.3.4 → 4.3.2.1). IPv4-only (as DNSBLs are). */
function reverseV4(bytes) {
  return `${bytes[3]}.${bytes[2]}.${bytes[1]}.${bytes[0]}`;
}

async function queryZone(rev, zone) {
  const name = `${rev}.${zone}`;
  const ctrl = new Promise((resolve) => {
    const t = setTimeout(() => resolve(null), timeoutMs());
    t.unref?.();
    resolver
      .resolve4(name)
      .then((addrs) => {
        clearTimeout(t);
        resolve(addrs);
      })
      .catch((err) => {
        clearTimeout(t);
        // ENOTFOUND / NXDOMAIN = not listed (the normal, common case).
        if (err && (err.code === "ENOTFOUND" || err.code === "ENODATA")) resolve([]);
        else resolve(null); // resolver error → unknown, fail-open
      });
  });
  return ctrl;
}

/**
 * Check an IP against the configured DNSBLs (cached, fail-open).
 * @returns {Promise<{ listed:boolean, zones:string[], cached?:boolean }>}
 */
export async function checkDnsbl(ip) {
  const neutral = { listed: false, zones: [] };
  if (!dnsblEnabled() || !ip) return neutral;
  const bytes = ipToBytes(ip);
  if (!bytes || bytes.length !== 4 || isPrivateV4(bytes)) return neutral; // v4 public only

  const cacheKey = `fx:dnsbl:${ip}`;
  const cached = await kvGetJson(cacheKey);
  if (cached) return { ...cached, cached: true };

  const rev = reverseV4(bytes);
  const hits = [];
  await Promise.all(
    zones().map(async (zone) => {
      const answer = await queryZone(rev, zone);
      if (Array.isArray(answer) && answer.length) hits.push(zone);
    })
  );

  const result = { listed: hits.length > 0, zones: hits };
  await kvSetJson(cacheKey, cacheTtl(), result);
  if (result.listed) log.warn("dnsbl: listed IP", { ip, zones: hits });
  return result;
}
