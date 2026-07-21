/**
 * Trifecta orchestrator (Req 2.1–2.5) — the Reader→Validator→Actor controller.
 *
 * Routes a prompt: agentic prompts (containing untrusted content + an implied
 * action) flow through the Trifecta; everything else bypasses to a normal LLM
 * call (zero overhead). Every stage emits an audit trace event so the Agent
 * Audit Trail can visualize the full reasoning chain.
 *
 * Returns the same shape chat.js expects from chatCompletion:
 *   { content, raw, simulated?, agentTrace? }
 * so the outbound integrity check + response handling need no changes.
 */
import { read } from "./readerAgent.js";
import { act } from "./actorAgent.js";
import { toolsFor } from "./rbac.js";

// Heuristic: a prompt is "agentic" if it embeds a chunk of untrusted content
// AND implies an action. This keeps normal Q&A on the fast path.
const CONTENT_HINTS = /(resume|cv|cover letter|ticket|support request|email says|message:|review this|summarize this|document:|pr description)/i;
const ACTION_HINTS = /(create|send|schedule|notify|look up|lookup|file|record|summarize|translate|classify)/i;

/**
 * Should this prompt go through the Trifecta?
 * @param {string} prompt
 */
export function isAgentic(prompt) {
  if (!prompt || typeof prompt !== "string") return false;
  return CONTENT_HINTS.test(prompt) && ACTION_HINTS.test(prompt);
}

/**
 * Run the full Trifecta on a prompt.
 *
 * @param {object} p
 * @param {string} p.prompt
 * @param {string} [p.userId]
 * @param {(event:object)=>void} [p.emit]  audit-trace callback (one event per stage)
 * @returns {Promise<{content:string, raw:any, simulated:boolean, agentTrace:object}>}
 */
export async function runTrifecta({ prompt, userId, emit }) {
  // EPIC G: in the distributed topology the firewall service delegates the
  // Trifecta to a dedicated agent-svc over HTTP (mirrors the reader-svc split in
  // EPIC E). Falls back to running in-process when AGENT_SVC_URL is unset — the
  // monolith and the test suite. The `SERVICE_ROLE === "agent"` guard prevents
  // agent-svc from recursively re-delegating to itself.
  const svcUrl = process.env.AGENT_SVC_URL;
  if (svcUrl && process.env.SERVICE_ROLE !== "agent") {
    try {
      const r = await fetch(svcUrl.replace(/\/$/, "") + "/internal/agent/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prompt, userId }),
      });
      if (r.ok) {
        emit?.({ stage: "delegated", via: "agent-svc" });
        return await r.json();
      }
      emit?.({ stage: "agent-svc:degraded", status: r.status });
      // Non-2xx → fall through to in-process so a flaky agent-svc never breaks chat.
    } catch (err) {
      emit?.({ stage: "agent-svc:error", error: String(err.message || err) });
      // Unreachable → fall through to in-process.
    }
  }

  const trace = {
    userId: userId || "anon",
    promptPreview: String(prompt).slice(0, 160),
    stages: [],
    blocked: false,
    blockReason: null,
    ts: new Date(),
  };

  // ----- 1. READER -------------------------------------------------------
  emit?.({ stage: "reader:start", userId });
  const reader = await read(prompt, (e) => trace.stages.push({ step: "reader", ...e }));
  emit?.({ stage: "reader:done", valid: reader.valid, simulated: reader.simulated });

  if (!reader.valid) {
    // Req 2.3: schema deviation → reject immediately. Injection can't propagate.
    trace.blocked = true;
    trace.blockReason = "reader_schema_reject";
    trace.stages.push({ step: "validator", rejected: true, errors: reader.errors });
    emit?.({ stage: "schema_reject", errors: reader.errors });
    return {
      content: "[Trifecta] Reader output rejected by schema validation — untrusted content cannot be processed.",
      raw: reader.raw,
      simulated: reader.simulated,
      agentTrace: trace,
    };
  }

  trace.reader = reader.json;
  emit?.({ stage: "reader:validated", summary: reader.json.summary, intent: reader.json.intent });

  // ----- 2. ACTOR (with embedded validation + RBAC) ----------------------
  emit?.({ stage: "actor:start", userId });
  const actor = await act(reader.json, (e) => trace.stages.push({ step: "actor", ...e }));
  trace.actor = { tool: actor.tool, rbac: actor.rbac, schemaValid: actor.schemaValid, result: actor.result };
  emit?.({ stage: "actor:done", tool: actor.tool, rbac: actor.rbac, result: actor.result });

  // ----- 3. Assemble response -------------------------------------------
  let content;
  if (!actor.schemaValid) {
    trace.blocked = true;
    trace.blockReason = "actor_schema_reject";
    content = `[Trifecta] Actor's tool call failed schema validation (${actor.tool}). No tool executed.`;
  } else if (!actor.rbac) {
    trace.blocked = true;
    trace.blockReason = "rbac_deny";
    content = `[Trifecta] RBAC denied tool "${actor.tool}" for the actor role. No tool executed.`;
  } else if (actor.tool) {
    content =
      `[Trifecta] Reader extracted: "${reader.json.summary}" (intent: ${reader.json.intent}).\n` +
      `Actor executed tool "${actor.tool}" → ${actor.result?.result || JSON.stringify(actor.result)}`;
  } else {
    content =
      `[Trifecta] Reader extracted: "${reader.json.summary}" (intent: ${reader.json.intent}).\n` +
      `Actor: no tool warranted. ${actor.reasoning ? "" : ""}`.trim();
  }

  trace.allowedTools = toolsFor("actor");
  trace.completed = true;
  return {
    content,
    raw: { reader: reader.raw, actor: actor.reasoning },
    simulated: reader.simulated || actor.simulated,
    agentTrace: trace,
  };
}
