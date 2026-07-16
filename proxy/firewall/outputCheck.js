/**
 * Outbound integrity check (Req 1.4).
 *
 * Inspects LLM *responses* before they return to the client, blocking:
 *   - apparent secrets/credentials the model leaked (LLM02)
 *   - unauthorized tool-calling / function-call parameters smuggled in output (LLM06)
 *
 * Returns a verdict the proxy can act on (and log).
 */

const SECRET_PATTERNS = [
  { re: /(?:sk-[a-zA-Z0-9]{20,})/, label: "OpenAI-style API key" },
  { re: /(?:AKIA[0-9A-Z]{16})/, label: "AWS access key id" },
  { re: /(?:gh[pousr]_[A-Za-z0-9]{36,})/, label: "GitHub token" },
  { re: /(?:-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----)/, label: "Private key block" },
  { re: /(?:mongodb(?:\+srv)?:\/\/[^\s'"<>]+:[^\s'"<>]+@)/, label: "Connection string with credentials" },
];

// Heuristic JSON tool-call envelopes the model is NOT allowed to emit directly.
const TOOL_CALL_PATTERNS = [
  { re: /"function"\s*:\s*"(?:exec|eval|shell|delete|drop|update|insert|fetch|request)"/i, label: "Unauthorized function call" },
  { re: /"action"\s*:\s*"(?:run_command|execute_sql|send_email|delete_file)"/i, label: "Unauthorized agent action" },
];

/**
 * @param {string} text - LLM response text
 * @returns {{ blocked: boolean, reasons: string[], snippets: string[], latencyMs: number }}
 */
export function checkOutput(text) {
  const t0 = performance.now();
  const reasons = [];
  const snippets = [];
  if (typeof text === "string" && text.length) {
    for (const { re, label } of [...SECRET_PATTERNS, ...TOOL_CALL_PATTERNS]) {
      const m = text.match(re);
      if (m) {
        reasons.push(label);
        const start = Math.max(0, (m.index || 0) - 15);
        const end = Math.min(text.length, (m.index || 0) + m[0].length + 15);
        snippets.push(text.slice(start, end).trim());
      }
    }
  }
  const latencyMs = +(performance.now() - t0).toFixed(3);
  return { blocked: reasons.length > 0, reasons, snippets, latencyMs };
}
