/**
 * Tier 3 · Wave 1 · Epic B — lazy MaxMind .mmdb reader cache.
 *
 * GeoIP + ASN both read local MaxMind databases: a memory-mapped `.mmdb` file, so
 * a lookup is a local B-tree walk with NO per-request network call. The `maxmind`
 * npm package and the database files are BOTH optional — if either is missing we
 * degrade to null (enrichment simply omits geo/asn), keeping the base demo and
 * the test suite dependency-free. Install for real use with:
 *     npm i maxmind   # then set MAXMIND_DB_PATH / MAXMIND_ASN_DB_PATH
 *
 * Readers are opened once and cached by path; a failed open is remembered as
 * `false` so we don't thrash the filesystem on every lookup.
 */
import { existsSync } from "node:fs";
import { log } from "../lib/logger.js";

const readers = new Map(); // path -> reader | false (open failed) | Promise

let maxmindMod = null;
let maxmindTried = false;

async function loadMaxmind() {
  if (maxmindTried) return maxmindMod;
  maxmindTried = true;
  try {
    maxmindMod = (await import("maxmind")).default;
  } catch {
    log.warn("forensics: 'maxmind' package not installed — geo/asn enrichment disabled");
    maxmindMod = false;
  }
  return maxmindMod;
}

/**
 * Open (and cache) an mmdb reader for `dbPath`. Returns a reader with `.get(ip)`
 * or null when the package/file is unavailable.
 */
export async function openReader(dbPath) {
  if (!dbPath) return null;
  const cached = readers.get(dbPath);
  if (cached !== undefined) return cached === false ? null : await cached;

  const promise = (async () => {
    const mm = await loadMaxmind();
    if (!mm) return false;
    if (!existsSync(dbPath)) {
      log.warn("forensics: mmdb file not found", { dbPath });
      return false;
    }
    try {
      const reader = await mm.open(dbPath);
      log.info("forensics: mmdb loaded", { dbPath });
      return reader;
    } catch (err) {
      log.warn("forensics: mmdb open failed", { dbPath, error: String(err.message || err) });
      return false;
    }
  })();

  readers.set(dbPath, promise);
  const resolved = await promise;
  readers.set(dbPath, resolved); // replace the promise with the settled value
  return resolved === false ? null : resolved;
}

/** Test hook: forget cached readers (and the package-load attempt). */
export function __resetReaders() {
  readers.clear();
  maxmindMod = null;
  maxmindTried = false;
}
