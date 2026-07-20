/**
 * RBAC permission matrix (Req 2.4).
 *
 * The Trifecta's whole point: roles are isolated by capability. A Reader can
 * NEVER call tools; an Actor can only call the tools its role is granted. This
 * table is the single source of truth — the Actor consults `canCall` before
 * every tool invocation and an unauthorized call → rbac_deny event + alert.
 *
 * Roles:
 *   reader  — processes untrusted content; NO tool access (the sandbox principle)
 *   actor   — executes validated actions under strict tool whitelist
 */

const ROLE_TOOLS = {
  reader: [], // readers never call tools — this is the core Trifecta guarantee
  actor: ["lookup", "summarize", "notify"], // whitelisted tools an Actor may use
};

/**
 * @param {"reader"|"actor"} role
 * @param {string} tool
 * @returns {boolean}
 */
function canCall(role, tool) {
  const allowed = ROLE_TOOLS[role] || [];
  return allowed.includes(tool);
}

/** Which tools a role may call (for the audit trail / dashboard). */
function toolsFor(role) {
  return [...(ROLE_TOOLS[role] || [])];
}

export { ROLE_TOOLS, canCall, toolsFor };
