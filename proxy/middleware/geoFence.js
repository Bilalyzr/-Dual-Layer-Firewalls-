/**
 * Tier 3 · Wave 2 · Epic E — geo/ASN fencing at the gateway.
 *
 * Allow- or deny-lists traffic by country or ASN before the pipeline runs. Unlike
 * enrichment (Epic B), this DECIDES on the request path — so it relies only on the
 * LOCAL MaxMind lookups (memory-mapped .mmdb, no network call). When those aren't
 * configured, or the IP has no geo (private/unknown), it FAILS OPEN: a firewall
 * must never black-hole traffic because a data file is missing.
 *
 * GEOFENCE_MODE:
 *   off    — disabled (default)
 *   deny   — block IPs whose country/ASN is in GEOFENCE_LIST (everything else allowed)
 *   allow  — block IPs whose country/ASN is NOT in GEOFENCE_LIST (allow-list only)
 *
 * GEOFENCE_LIST is a comma list mixing ISO country codes and AS numbers, e.g.
 *   GEOFENCE_LIST=RU,KP,AS12345    (deny those countries + that ASN)
 *   GEOFENCE_LIST=US,CA,GB         (allow-only these countries)
 *
 * A denied request is refused with 403 and recorded as an offense so the auto-
 * response engine (Epic C) can act on repeat attempts; every decision emits an event.
 */
import { lookupGeo } from "../forensics/geoip.js";
import { lookupAsn } from "../forensics/asn.js";
import { recordOffense } from "../response/banStore.js";
import { publish } from "./eventBus.js";
import { insertAlert } from "../db/mongo.js";
import { log } from "../lib/logger.js";

const EXEMPT = new Set(["/", "/healthz", "/metrics"]);

export const geofenceMode = () => (process.env.GEOFENCE_MODE || "off").toLowerCase(); // off|deny|allow

function geofenceList() {
  return (process.env.GEOFENCE_LIST || "")
    .split(/[,\s]+/)
    .map((x) => x.trim().toUpperCase())
    .filter(Boolean);
}

/**
 * Decide whether an IP is geo-fenced. Pure + reusable (tests call it directly).
 * @returns {Promise<{ blocked:boolean, reason?:string, country?:string, asn?:number }>}
 */
export async function evaluateGeofence(ip) {
  const mode = geofenceMode();
  if (mode !== "deny" && mode !== "allow") return { blocked: false };
  const list = geofenceList();
  if (!list.length) return { blocked: false };

  const [geo, asn] = await Promise.all([
    lookupGeo(ip).catch(() => null),
    lookupAsn(ip).catch(() => null),
  ]);
  const country = geo?.country ? String(geo.country).toUpperCase() : null;
  const asNum = asn?.asn != null ? `AS${asn.asn}` : null;

  // No geo signal at all → fail open (can't fence what we can't locate).
  if (!country && !asNum) return { blocked: false, reason: "no-geo" };

  const inList = (country && list.includes(country)) || (asNum && list.includes(asNum));
  const blocked = mode === "deny" ? inList : !inList;
  return {
    blocked,
    reason: blocked ? (mode === "deny" ? "denied-geo" : "not-in-allowlist") : "permitted",
    country,
    asn: asn?.asn ?? null,
  };
}

/** Express middleware. No-op unless GEOFENCE_MODE is deny|allow. */
export function geoFenceMiddleware(req, res, next) {
  if (geofenceMode() === "off") return next();
  const path = req.path || req.url || "";
  if (EXEMPT.has(path)) return next();
  const ip = req.ipContext?.clientIp;
  if (!ip) return next();

  evaluateGeofence(ip)
    .then(async (verdict) => {
      if (!verdict.blocked) return next();
      publish("geofence_block", {
        ip,
        country: verdict.country,
        asn: verdict.asn,
        reason: verdict.reason,
        mode: geofenceMode(),
        path,
        ts: new Date().toISOString(),
      });
      log.warn("geofence: refused client", { ip, country: verdict.country, asn: verdict.asn, reason: verdict.reason });
      // Feed the auto-response engine + audit trail (fire-and-forget on the audit).
      recordOffense(ip).catch(() => {});
      insertAlert({
        kind: "geofence",
        category: "LLM10",
        categoryTitle: "Geo/ASN fenced",
        label: `Geo-fenced ${verdict.country || verdict.asn || ip} (${verdict.reason})`,
        blocked: true,
        mode: geofenceMode(),
        forensics: { clientIp: ip },
        ts: new Date(),
      }).catch(() => {});
      return res.status(403).json({ blocked: true, reason: "forbidden" });
    })
    .catch((err) => {
      // Fail open — a fencing error must never take the gateway down.
      log.warn("geofence: check failed, allowing", { ip, error: String(err.message || err) });
      next();
    });
}
