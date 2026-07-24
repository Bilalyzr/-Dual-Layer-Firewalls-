/**
 * Tier 3 · Wave 1 · Epic B — ASN + network + org lookup.
 *
 * Primary source is the local MaxMind GeoLite2-ASN `.mmdb` (MAXMIND_ASN_DB_PATH) —
 * offline, no network call. When it's absent AND ASN_BGPVIEW_FALLBACK=true we make
 * a single cached call to the free bgpview.io API as a fallback (the ONLY network
 * hit in this module, and it's off the request path since enrichment is out-of-band).
 *
 * Returns { asn, org, network, abuseContact } or null. Fail-open, never throws.
 */
import { openReader } from "./_mmdb.js";
import { enclosingNetwork } from "../lib/cidr.js";
import { kvGetJson, kvSetJson } from "../lib/store.js";
import { log } from "../lib/logger.js";

const asnDbPath = () => process.env.MAXMIND_ASN_DB_PATH || "";
const bgpviewEnabled = () => String(process.env.ASN_BGPVIEW_FALLBACK || "false").toLowerCase() === "true";
const cacheTtl = () => parseInt(process.env.ENRICHMENT_CACHE_TTL || "86400", 10);

async function fromMaxmind(ip) {
  const reader = await openReader(asnDbPath());
  if (!reader) return null;
  try {
    const r = reader.get(ip);
    if (!r) return null;
    return {
      asn: r.autonomous_system_number ?? null,
      org: r.autonomous_system_organization || null,
      network: r.network || enclosingNetwork(ip),
      abuseContact: null, // MaxMind ASN db carries no abuse contact
    };
  } catch {
    return null;
  }
}

async function fromBgpview(ip) {
  if (!bgpviewEnabled()) return null;
  const cacheKey = `fx:asn:${ip}`;
  const cached = await kvGetJson(cacheKey);
  if (cached) return cached;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const resp = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return null;
    const j = await resp.json();
    const pfx = j?.data?.prefixes?.[0];
    const out = {
      asn: pfx?.asn?.asn ?? null,
      org: pfx?.asn?.name || pfx?.asn?.description || null,
      network: pfx?.prefix || enclosingNetwork(ip),
      abuseContact: j?.data?.abuse_contacts?.[0]?.email || null,
    };
    await kvSetJson(cacheKey, cacheTtl(), out);
    return out;
  } catch (err) {
    log.debug("forensics: bgpview fallback failed", { error: String(err.message || err) });
    return null;
  }
}

export async function lookupAsn(ip) {
  if (!ip) return null;
  const mm = await fromMaxmind(ip);
  if (mm && (mm.asn || mm.org)) return mm;
  return (await fromBgpview(ip)) || mm;
}
