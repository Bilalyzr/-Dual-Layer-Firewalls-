/**
 * In-process LRU + TTL cache for classifier verdicts (Tier-3 §12.8 "Edge Caching").
 *
 * The ML classify step (Req 1.3) is a network round-trip to the Python engine —
 * the dominant cost in the firewall path. A prompt's verdict is deterministic
 * for a given model, so identical prompts can reuse the last verdict instead of
 * paying the hop again. This is what brings the combined firewall path back under
 * the PRD's <5ms target on repeated/benign traffic.
 *
 * Safety: cache keyed on the exact prompt text; a cache hit returns the same
 * verdict the engine would have. Entries expire after CLF_CACHE_TTL_MS so a
 * retrained model propagates. Bounded to CLF_CACHE_MAX entries (LRU eviction).
 * Disabled entirely when CLF_CACHE_MAX <= 0.
 */

const MAX = () => parseInt(process.env.CLF_CACHE_MAX || "1000", 10);
const TTL = () => parseInt(process.env.CLF_CACHE_TTL_MS || "300000", 10); // 5 min

// Map preserves insertion order → cheap LRU: delete+set moves a key to the tail.
const store = new Map();

function now() {
  return Date.now();
}

/** Return a cached verdict for `prompt`, or undefined on miss/expiry/disabled. */
export function getCached(prompt) {
  if (MAX() <= 0) return undefined;
  const hit = store.get(prompt);
  if (!hit) return undefined;
  if (now() - hit.at > TTL()) {
    store.delete(prompt);
    return undefined;
  }
  // Refresh recency (move to tail).
  store.delete(prompt);
  store.set(prompt, hit);
  return hit.value;
}

/** Cache a verdict for `prompt`. No-op when disabled. */
export function setCached(prompt, value) {
  const max = MAX();
  if (max <= 0) return;
  if (store.has(prompt)) store.delete(prompt);
  store.set(prompt, { value, at: now() });
  // Evict oldest entries past the bound.
  while (store.size > max) {
    const oldest = store.keys().next().value;
    store.delete(oldest);
  }
}

/** Test/ops helper — drop all cached verdicts. */
export function clearClfCache() {
  store.clear();
}

/** Observability: current cache size (surfaced on /metrics if desired). */
export function clfCacheSize() {
  return store.size;
}
