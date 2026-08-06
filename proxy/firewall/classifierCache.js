/**
 * EPIC J — Edge cache of classifier decisions for repeated prompts.
 *
 * Repeated benign prompts ("hello", "what is x") hit the cache and skip the ML
 * call entirely. LRU + TTL so the cache can't grow unbounded or serve stale
 * decisions forever. Cuts ML cost meaningfully on real traffic where a long
 * tail of prompts repeat.
 *
 * Only caches NON-THREAT decisions (threats always re-evaluate — never cache a
 * block, in case the threshold is later tightened).
 */

const _cache = new Map(); // key (hash) -> { decision, ts }
const TTL_MS = parseInt(process.env.CLASSIFIER_CACHE_TTL_MS || "300000", 10); // 5 min
const MAX = parseInt(process.env.CLASSIFIER_CACHE_MAX || "1000", 10);

function _key(text) {
  // simple djb2 hash; cache key is text-derived, content is never stored
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
  return String(h);
}

/** Try to get a cached ALLOW decision. Returns null on miss/expiry/threat. */
export function getCachedDecision(text) {
  if (process.env.CLASSIFIER_CACHE_ENABLED !== "true") return null;
  const k = _key(text);
  const entry = _cache.get(k);
  if (!entry) return null;
  if (Date.now() - entry.ts > TTL_MS) {
    _cache.delete(k);
    return null;
  }
  // LRU touch
  _cache.delete(k);
  _cache.set(k, entry);
  return entry.decision;
}

/** Store a decision. Threats are never cached. */
export function setCachedDecision(text, decision) {
  if (process.env.CLASSIFIER_CACHE_ENABLED !== "true") return;
  if (decision.threat) return; // never cache a block
  if (_cache.size >= MAX) {
    // evict oldest (first map key = LRU)
    const oldest = _cache.keys().next().value;
    if (oldest !== undefined) _cache.delete(oldest);
  }
  _cache.set(_key(text), { decision, ts: Date.now() });
}

export function cacheStats() {
  return { size: _cache.size, max: MAX, ttlMs: TTL_MS, enabled: process.env.CLASSIFIER_CACHE_ENABLED === "true" };
}

/** Test hook. */
export function _resetCache() {
  _cache.clear();
}
