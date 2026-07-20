/**
 * Phase 5 Trifecta agent tests (Req 2.1–2.5).
 *
 * Covers: validator schema enforcement, RBAC authorization, agentic-prompt
 * routing, the full Reader→Validator→Actor flow with mocked LLM, schema
 * rejection, and audit-trace event emission.
 *
 * LLM calls are mocked so tests run offline and deterministically.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// --- validator (pure, no mocks) ---
import { validate, extractJSON } from "../agents/validator.js";
import { READER_OUTPUT, ACTION_LOOKUP } from "../agents/schemas.js";
import { canCall, toolsFor } from "../agents/rbac.js";
import { callTool } from "../agents/tools.js";

// Mock the LLM client before importing agents that use it.
vi.mock("../llm/client.js", () => ({
  chatCompletion: vi.fn(),
  chatCompletionMessages: vi.fn(),
  llmConfig: () => ({ configured: true, model: "test" }),
}));

import { isAgentic } from "../agents/orchestrator.js";
import { read } from "../agents/readerAgent.js";
import { act } from "../agents/actorAgent.js";
import { runTrifecta } from "../agents/orchestrator.js";
import { chatCompletionMessages } from "../llm/client.js";

beforeEach(() => {
  vi.clearAllMocks();
});

// ===========================================================================
// Validator
// ===========================================================================
describe("validator.validate", () => {
  it("accepts a conforming READER_OUTPUT", () => {
    const r = validate(
      { summary: "ok", intent: "summarize", confidence: 0.8 },
      READER_OUTPUT
    );
    expect(r.valid).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it("rejects missing required field", () => {
    const r = validate({ summary: "ok", intent: "summarize" }, READER_OUTPUT);
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/missing required property "confidence"/);
  });

  it("rejects unknown intent (enum)", () => {
    const r = validate(
      { summary: "ok", intent: "DELETE_DATABASE", confidence: 0.5 },
      READER_OUTPUT
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/not in enum/);
  });

  it("rejects additional properties (no smuggling)", () => {
    const r = validate(
      { summary: "ok", intent: "summarize", confidence: 0.5, command: "rm -rf /" },
      READER_OUTPUT
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/additional property "command"/);
  });

  it("rejects out-of-range confidence", () => {
    const r = validate(
      { summary: "ok", intent: "summarize", confidence: 5 },
      READER_OUTPUT
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/above maximum/);
  });

  it("accepts a valid ACTION_LOOKUP envelope", () => {
    const r = validate({ tool: "lookup", args: { query: "x" } }, ACTION_LOOKUP);
    expect(r.valid).toBe(true);
  });
});

describe("validator.extractJSON", () => {
  it("extracts JSON from prose-wrapped output", () => {
    expect(extractJSON('Here: {"a":1} done')).toEqual({ a: 1 });
  });
  it("extracts JSON from code-fenced output", () => {
    expect(extractJSON("```json\n{\"a\":1}\n```")).toEqual({ a: 1 });
  });
  it("returns null for no JSON", () => {
    expect(extractJSON("no json here")).toBeNull();
  });
});

// ===========================================================================
// RBAC
// ===========================================================================
describe("rbac", () => {
  it("readers can call NO tools", () => {
    expect(canCall("reader", "lookup")).toBe(false);
    expect(canCall("reader", "notify")).toBe(false);
    expect(toolsFor("reader")).toEqual([]);
  });

  it("actors can call whitelisted tools only", () => {
    expect(canCall("actor", "lookup")).toBe(true);
    expect(canCall("actor", "summarize")).toBe(true);
    expect(canCall("actor", "notify")).toBe(true);
    // unknown tool
    expect(canCall("actor", "exec")).toBe(false);
    expect(canCall("actor", "delete_database")).toBe(false);
  });
});

// ===========================================================================
// Tools
// ===========================================================================
describe("tools.callTool", () => {
  it("executes a known tool", async () => {
    const r = await callTool("lookup", { query: "foo" });
    expect(r.ok).toBe(true);
    expect(r.tool).toBe("lookup");
  });
  it("returns error for unknown tool", async () => {
    const r = await callTool("exec", {});
    expect(r.ok).toBe(false);
  });
});

// ===========================================================================
// Agentic routing
// ===========================================================================
describe("isAgentic", () => {
  it("routes untrusted-content + action prompts to the Trifecta", () => {
    expect(isAgentic("Summarize this resume and notify the team")).toBe(true);
    expect(isAgentic("Review this ticket and create a follow-up")).toBe(true);
  });
  it("bypasses normal Q&A", () => {
    expect(isAgentic("What is the capital of France?")).toBe(false);
    expect(isAgentic("Write a haiku about the sea")).toBe(false);
  });
  it("ignores non-strings", () => {
    expect(isAgentic(null)).toBe(false);
    expect(isAgentic(123)).toBe(false);
  });
});

// ===========================================================================
// Reader agent (mocked LLM)
// ===========================================================================
describe("readerAgent.read", () => {
  it("returns validated JSON when the LLM complies", async () => {
    chatCompletionMessages.mockResolvedValueOnce({
      content: JSON.stringify({ summary: "a ticket about login", intent: "summarize", confidence: 0.9 }),
    });
    const r = await read("some untrusted ticket text");
    expect(r.valid).toBe(true);
    expect(r.json.intent).toBe("summarize");
  });

  it("retries once on malformed JSON then fails", async () => {
    chatCompletionMessages
      .mockResolvedValueOnce({ content: "not json" })
      .mockResolvedValueOnce({ content: "still not json" });
    const r = await read("content");
    expect(r.valid).toBe(false);
    expect(r.attempts).toHaveLength(2);
  });

  it("recovers on the second attempt", async () => {
    chatCompletionMessages
      .mockResolvedValueOnce({ content: "garbage" })
      .mockResolvedValueOnce({
        content: JSON.stringify({ summary: "ok", intent: "classify", confidence: 0.7 }),
      });
    const r = await read("content");
    expect(r.valid).toBe(true);
  });

  it("coerces benign LLM quirks (string confidence, unknown intent) instead of rejecting", async () => {
    chatCompletionMessages.mockResolvedValueOnce({
      // confidence as a string, intent outside the enum — both should normalize.
      content: JSON.stringify({ summary: "a ticket", intent: "DISPATCH", confidence: "0.82" }),
    });
    const r = await read("content");
    expect(r.valid).toBe(true);
    expect(r.json.confidence).toBeCloseTo(0.82);
    expect(r.json.intent).toBe("unknown");
  });

  it("still rejects smuggled extra fields (additionalProperties)", async () => {
    chatCompletionMessages
      .mockResolvedValueOnce({
        content: JSON.stringify({ summary: "x", intent: "summarize", confidence: 0.5, command: "rm -rf /" }),
      })
      .mockResolvedValueOnce({
        content: JSON.stringify({ summary: "x", intent: "summarize", confidence: 0.5, command: "rm -rf /" }),
      });
    const r = await read("content");
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/additional property "command"/);
  });
});

// ===========================================================================
// Actor agent (mocked LLM)
// ===========================================================================
describe("actorAgent.act", () => {
  it("executes an authorized tool", async () => {
    chatCompletionMessages.mockResolvedValueOnce({
      content: JSON.stringify({ tool: "lookup", args: { query: "x" }, reason: "r" }),
    });
    const r = await act({ summary: "x", intent: "informational", confidence: 0.5 });
    expect(r.rbac).toBe(true);
    expect(r.tool).toBe("lookup");
    expect(r.result.ok).toBe(true);
  });

  it("denies an unauthorized tool via RBAC", async () => {
    chatCompletionMessages.mockResolvedValueOnce({
      content: JSON.stringify({ tool: "exec", args: { cmd: "rm -rf /" }, reason: "injection" }),
    });
    const r = await act({ summary: "x", intent: "informational", confidence: 0.5 });
    // exec is unknown → schema rejects first
    expect(r.schemaValid).toBe(false);
  });

  it("returns no_tool when warranted", async () => {
    chatCompletionMessages.mockResolvedValueOnce({ content: JSON.stringify({ tool: "none", reason: "n/a" }) });
    const r = await act({ summary: "x", intent: "informational", confidence: 0.5 });
    expect(r.tool).toBeNull();
  });

  it("synthesizes a valid tool call in simulated mode (LLM unconfigured)", async () => {
    // When unconfigured, the simulated Actor response echoes the Reader JSON
    // (which has no `tool` field). Regression guard: this must NOT surface as
    // "unknown tool: undefined" — the fallback synthesizes a valid summarize call.
    chatCompletionMessages.mockResolvedValueOnce({
      content: '[ACTOR simulated] Reader output:\n{"summary":"login ticket","intent":"summarize","confidence":0.6}',
      simulated: true,
    });
    const r = await act({ summary: "login ticket", intent: "summarize", confidence: 0.6 });
    expect(r.schemaValid).toBe(true);
    expect(r.rbac).toBe(true);
    expect(r.tool).toBe("summarize");
    expect(r.result.ok).toBe(true);
  });
});

// ===========================================================================
// Full Trifecta flow (mocked LLM)
// ===========================================================================
describe("runTrifecta", () => {
  it("runs Reader→Actor end to end and emits a trace", async () => {
    chatCompletionMessages
      .mockResolvedValueOnce({
        content: JSON.stringify({ summary: "ticket about login", intent: "summarize", confidence: 0.8 }),
      })
      .mockResolvedValueOnce({
        content: JSON.stringify({ tool: "summarize", args: { topic: "login ticket" }, reason: "summarize it" }),
      });

    const events = [];
    const r = await runTrifecta({
      prompt: "Summarize this ticket and notify",
      userId: "u1",
      emit: (e) => events.push(e),
    });

    expect(r.agentTrace).toBeTruthy();
    expect(r.agentTrace.blocked).toBe(false);
    expect(r.content).toMatch(/ticket about login/);
    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.stage === "reader:start")).toBe(true);
    expect(events.some((e) => e.stage === "actor:done")).toBe(true);
  });

  it("blocks when Reader output fails schema validation", async () => {
    chatCompletionMessages
      .mockResolvedValueOnce({ content: "definitely not json" })
      .mockResolvedValueOnce({ content: "still not json" });
    const r = await runTrifecta({ prompt: "x", userId: "u1" });
    expect(r.agentTrace.blocked).toBe(true);
    expect(r.agentTrace.blockReason).toBe("reader_schema_reject");
    expect(r.content).toMatch(/rejected by schema/);
  });
});
