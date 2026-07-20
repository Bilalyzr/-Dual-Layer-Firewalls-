/**
 * Mock tool registry (Req 2.4 — the Actor's permitted actions).
 *
 * These are deliberately mock implementations: they demonstrate the RBAC +
 * audit boundary without needing real external API credentials. Each tool logs
 * its call (for the audit trail) and returns a deterministic result.
 *
 * In production these would be real integrations (calendar, email, CRM lookup);
 * the security boundary (schema validation + RBAC) is what matters here, and
 * that is real.
 */

const TOOLS = {
  /**
   * lookup(query) — pretend knowledge-base lookup.
   * Returns a short canned fact so the demo flow has something concrete.
   */
  lookup: async ({ query }) => {
    return {
      tool: "lookup",
      ok: true,
      result: `Lookup for "${String(query).slice(0, 60)}": found 1 record (mock KB).`,
    };
  },

  /**
   * summarize(topic) — produce a short summary marker (mock; the real summary
   * came from the Reader — this tool just records the action).
   */
  summarize: async ({ topic }) => {
    return {
      tool: "summarize",
      ok: true,
      result: `Summary of "${String(topic).slice(0, 60)}" recorded.`,
    };
  },

  /**
   * notify({message, channel}) — mock notification dispatch.
   * Demonstrates a "side-effecting" action under RBAC.
   */
  notify: async ({ message, channel = "dashboard" }) => {
    return {
      tool: "notify",
      ok: true,
      result: `Notification sent on ${channel}: ${String(message).slice(0, 60)}`,
    };
  },
};

/**
 * Execute a tool by name. Throws if the tool doesn't exist (caught by Actor).
 * @param {string} name
 * @param {object} args
 */
async function callTool(name, args) {
  const fn = TOOLS[name];
  if (!fn) {
    return { tool: name, ok: false, error: `unknown tool: ${name}` };
  }
  try {
    return await fn(args || {});
  } catch (err) {
    return { tool: name, ok: false, error: String(err.message || err) };
  }
}

function toolNames() {
  return Object.keys(TOOLS);
}

export { TOOLS, callTool, toolNames };
