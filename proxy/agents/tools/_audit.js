/**
 * EPIC F — shared audit + rate-limit helpers for tool adapters.
 *
 * Every tool call passes through `recordCall` which:
 *   1. enforces the per-tool rate limit (sliding window, in-process)
 *   2. appends to the audit log (in-memory ring buffer; surfaced via auditTrail())
 *
 * The actual RBAC + schema validation happen BEFORE the adapter is invoked (in
 * actorAgent.js) — so a call reaching the adapter is already authorized.
 */
export const LOG = {
  warn: (...a) => console.warn("[tools]", ...a),
  info: (...a) => console.log("[tools]", ...a),
};

// tool name -> array of timestamps (sliding window)
const _calls = new Map();
// ring buffer of recent call records (for audit trail / dashboard)
const _audit = [];
const AUDIT_MAX = 200;

/** In-process rate limiter. Throws Error("rate_limited") if exceeded. */
export function recordCall(tool, detail = {}) {
  const now = Date.now();
  // rate check
  const cfg = _rateConfig(tool);
  if (cfg) {
    const arr = (_calls.get(tool) || []).filter((t) => now - t < cfg.windowMs);
    if (arr.length >= cfg.max) {
      throw new Error(`rate_limited: tool "${tool}" exceeded ${cfg.max}/${cfg.windowMs}ms`);
    }
    arr.push(now);
    _calls.set(tool, arr);
  }
  // audit ring buffer
  _audit.unshift({ tool, ts: new Date(), detail });
  if (_audit.length > AUDIT_MAX) _audit.length = AUDIT_MAX;
}

// Per-tool rate-limit config — populated lazily from each adapter's `config`.
const _rateTable = new Map();
export function registerRateLimit(tool, cfg) {
  if (cfg && cfg.windowMs && cfg.max) _rateTable.set(tool, cfg);
}
function _rateConfig(tool) {
  return _rateTable.get(tool);
}

/** Read-only copy of the audit trail (most-recent first). */
export function auditTrail(limit = 50) {
  return _audit.slice(0, limit);
}

/** Test hook: clear all rate-limit windows + audit. */
export function _resetForTests() {
  _calls.clear();
  _audit.length = 0;
}
