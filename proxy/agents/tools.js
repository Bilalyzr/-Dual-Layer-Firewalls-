/**
 * EPIC F — tool registry. Delegates to the per-tool adapters in `tools/` and
 * enforces the shared enforcement envelope (RBAC + schema + rate-limit + audit).
 *
 * Replaces the old mock-only `tools.js`. Each adapter is feature-flagged: it
 * uses real integrations when creds are present, otherwise falls back to a mock
 * so the demo keeps working with no external accounts.
 *
 * Public contract with actorAgent.js is unchanged:
 *   callTool(name, args) -> { tool, ok, result|error }
 */
import { notify, config as notifyCfg } from "./tools/notify.js";
import { lookup, config as lookupCfg } from "./tools/lookup.js";
import { summarize, config as summarizeCfg } from "./tools/summarize.js";
import { registerRateLimit, recordCall, auditTrail } from "./tools/_audit.js";

const ADAPTERS = {
  notify,
  lookup,
  summarize,
};

// Register per-tool rate limits.
registerRateLimit("notify", notifyCfg.rateLimit);
registerRateLimit("lookup", lookupCfg.rateLimit);
registerRateLimit("summarize", summarizeCfg.rateLimit);

/**
 * Execute a tool by name. Rate-limited + audited.
 * RBAC + schema validation have ALREADY run in actorAgent.js before this.
 * @param {string} name
 * @param {object} args
 */
export async function callTool(name, args) {
  const fn = ADAPTERS[name];
  if (!fn) {
    return { tool: name, ok: false, error: `unknown tool: ${name}` };
  }
  try {
    const result = await fn(args || {});
    return { ...result, tool: result.tool || name, ok: result.ok !== false };
  } catch (err) {
    const message = String(err.message || err);
    // rate-limit violations surface distinctly so the actor can report them
    if (message.startsWith("rate_limited")) {
      return { tool: name, ok: false, error: message };
    }
    return { tool: name, ok: false, error: message };
  }
}

function toolNames() {
  return Object.keys(ADAPTERS);
}

export { auditTrail };
