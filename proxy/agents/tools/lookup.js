/**
 * EPIC F — `lookup` tool adapter (real KB/vector search, feature-flagged).
 *
 * Queries a real knowledge base when LOOKUP_API_URL is set (any HTTP search/KB
 * endpoint that returns JSON). Otherwise falls back to a deterministic mock.
 *
 * Same enforcement envelope as `notify`: RBAC, schema validation, rate limit,
 * and every call is audited via the shared adapter registry.
 *
 * @param {{query:string}} args
 * @returns {Promise<{tool:string, ok:boolean, result:string, mode:string}>}
 */
import { LOG, recordCall } from "./_audit.js";

export async function lookup(args) {
  const query = String(args?.query || "").slice(0, 120);
  recordCall("lookup", { length: query.length });

  // Real KB mode.
  const apiUrl = process.env.LOOKUP_API_URL;
  const apiKey = process.env.LOOKUP_API_KEY;
  if (apiUrl) {
    try {
      const url = new URL(apiUrl);
      url.searchParams.set("q", query);
      const r = await fetch(url.toString(), {
        headers: { ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) },
        signal: AbortSignal.timeout(5000),
      });
      if (r.ok) {
        const data = await r.json().catch(() => ({}));
        // Be defensive: KB shapes vary. Pull the first plausible text field.
        const hit = data?.results?.[0]?.text || data?.answer || data?.text || JSON.stringify(data).slice(0, 120);
        return { tool: "lookup", ok: true, mode: "kb", result: `KB hit for "${query}": ${String(hit).slice(0, 100)}` };
      }
      return { tool: "lookup", ok: false, mode: "kb", result: `KB returned ${r.status}` };
    } catch (err) {
      LOG.warn("[tools.lookup] KB failed:", err.message);
    }
  }

  // Mock fallback.
  return {
    tool: "lookup",
    ok: true,
    mode: "mock",
    result: `Lookup for "${query}": 1 record found (mock KB).`,
  };
}

export const config = {
  name: "lookup",
  rateLimit: { windowMs: 60_000, max: 20 }, // 20 lookups/min/role
  requiresCreds: ["LOOKUP_API_URL"],
};
