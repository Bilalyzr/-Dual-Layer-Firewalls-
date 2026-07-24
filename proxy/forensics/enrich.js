/**
 * Tier 3 · Wave 1 · Epic B — threat-enrichment orchestrator.
 *
 * Assembles the §12.1 forensics schema for an IP:
 *     { geoip, asn, vpnDetected, abuseScore, previousOffenses, ... }
 * by fanning out to geoip / asn / reputation in parallel, and CACHES the combined
 * result in the shared store so repeat offenders don't re-trigger lookups.
 *
 * `requestEnrichment` is the request-path entry point: it is FIRE-AND-FORGET
 * (never awaited by the handler) so enrichment adds ZERO latency to the response.
 * When it completes it patches the stored alert (patchAlertForensics) and pushes
 * an `enrichment` SSE event so the dashboard updates live. It never throws — a
 * degraded API leaves the already-stored alert untouched.
 */
import { lookupGeo } from "./geoip.js";
import { lookupAsn } from "./asn.js";
import { lookupReputation } from "./reputation.js";
import { kvGetJson, kvSetJson } from "../lib/store.js";
import { patchAlertForensics } from "../db/mongo.js";
import { publish } from "../middleware/eventBus.js";
import { log } from "../lib/logger.js";

const cacheTtl = () => parseInt(process.env.ENRICHMENT_CACHE_TTL || "86400", 10);

export function enrichmentEnabled() {
  return String(process.env.ENRICHMENT_ENABLED ?? "true").toLowerCase() !== "false";
}

/**
 * Enrich a single IP (cached). Returns the §12.1-shaped enrichment object.
 * @returns {Promise<object>}
 */
export async function enrichIp(ip) {
  const cacheKey = `fx:enrich:${ip}`;
  const cached = await kvGetJson(cacheKey);
  if (cached) return { ...cached, cached: true };

  const [geoip, asn, rep] = await Promise.all([
    lookupGeo(ip).catch(() => null),
    lookupAsn(ip).catch(() => null),
    lookupReputation(ip).catch(() => null),
  ]);

  const enrichment = {
    geoip: geoip || null,
    asn: asn || null,
    org: asn?.org || null,
    network: asn?.network || null,
    vpnDetected: rep?.vpnDetected || false,
    torExit: rep?.torExit || false,
    abuseScore: rep?.abuseScore ?? null,
    previousOffenses: rep?.previousOffenses ?? null,
    proxyType: rep?.proxyType || null,
    usageType: rep?.usageType || null,
    sources: rep?.sources || [],
    enrichedAt: new Date().toISOString(),
    cached: false,
  };

  await kvSetJson(cacheKey, cacheTtl(), enrichment);
  return enrichment;
}

/**
 * Out-of-band enrichment trigger. Fire-and-forget — DO NOT await in a handler.
 * @param {{ alertId: string, ip: string }} args
 */
export function requestEnrichment({ alertId, ip } = {}) {
  if (!enrichmentEnabled() || !alertId || !ip) return;
  // Detach from the request lifecycle entirely.
  Promise.resolve().then(async () => {
    try {
      const enrichment = await enrichIp(ip);
      await patchAlertForensics(alertId, enrichment);
      publish("enrichment", { alertId, ip, enrichment });
    } catch (err) {
      log.warn("forensics: enrichment failed", { alertId, error: String(err.message || err) });
    }
  });
}
