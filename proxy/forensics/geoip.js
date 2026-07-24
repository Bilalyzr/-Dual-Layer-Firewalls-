/**
 * Tier 3 · Wave 1 · Epic B — GeoIP lookup (MaxMind GeoLite2-City).
 *
 * Turns a bare IP into { country, countryName, city, region, lat, lon }. Reads a
 * local `.mmdb` (MAXMIND_DB_PATH) so there is no per-request network call. ISP/org
 * come from the ASN database (see asn.js) — the City db doesn't carry them.
 *
 * Fail-open: private/loopback IPs, a missing db, or an unparseable record all
 * yield null and the alert is simply stored without geo. Never throws.
 */
import { openReader } from "./_mmdb.js";
import { ipToBytes } from "../lib/cidr.js";

const dbPath = () => process.env.MAXMIND_DB_PATH || "";

/** Private/loopback/link-local addresses have no meaningful geo — skip them. */
function isPrivate(ip) {
  const b = ipToBytes(ip);
  if (!b) return true;
  if (b.length === 4) {
    if (b[0] === 10) return true;
    if (b[0] === 127) return true;
    if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return true;
    if (b[0] === 192 && b[1] === 168) return true;
    if (b[0] === 169 && b[1] === 254) return true;
    return false;
  }
  if (b[0] === 0 && b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true; // ::1
  if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  return false;
}

/**
 * @returns {Promise<null | { country, countryName, city, region, lat, lon }>}
 */
export async function lookupGeo(ip) {
  if (!ip || isPrivate(ip)) return null;
  const reader = await openReader(dbPath());
  if (!reader) return null;
  try {
    const r = reader.get(ip);
    if (!r) return null;
    return {
      country: r.country?.iso_code || r.registered_country?.iso_code || null,
      countryName: r.country?.names?.en || r.registered_country?.names?.en || null,
      city: r.city?.names?.en || null,
      region: r.subdivisions?.[0]?.names?.en || null,
      lat: r.location?.latitude ?? null,
      lon: r.location?.longitude ?? null,
    };
  } catch {
    return null;
  }
}
