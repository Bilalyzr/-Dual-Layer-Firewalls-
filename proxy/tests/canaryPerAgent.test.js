/**
 * Wave-4 — per-request / per-agent canary.
 *
 * Covers the enhancement over the single process-static canary:
 *   - fresh tokens are minted per call and ALL live tokens are scanned
 *   - injectCanaryMessages augments (or adds) the system message + returns token
 *   - the Trifecta orchestrator now BLOCKS when an agent leaks its own canary
 *     (previously the agents' custom system prompts carried no canary at all).
 */
import { describe, it, expect, vi } from "vitest";

// ---- unit: minting + multi-token detection --------------------------------
import {
  canaryToken, mintCanary, injectCanary, injectCanaryMessages, detectCanaryLeak,
} from "../firewall/canary.js";

describe("per-agent canary — minting & detection", () => {
  it("mints unique tokens and detects each one", () => {
    const a = mintCanary("reader");
    const b = mintCanary("actor");
    expect(a).not.toBe(b);
    expect(detectCanaryLeak(`leak ${a} here`).leaked).toBe(true);
    expect(detectCanaryLeak(`leak ${b} here`).leaked).toBe(true);
  });

  it("reports which prompt leaked via the token label", () => {
    const t = mintCanary("reader");
    const r = detectCanaryLeak(`... ${t} ...`);
    expect(r.leaked).toBe(true);
    expect(r.label).toBe("reader");
  });

  it("still detects the stable process canary (backward compatible)", () => {
    const t = canaryToken();
    expect(detectCanaryLeak(`x ${t} y`).token).toBe(t);
    expect(injectCanary("You are helpful.")).toContain(t);
  });

  it("injectCanaryMessages appends to an existing system message", () => {
    const { messages, token } = injectCanaryMessages(
      [{ role: "system", content: "SYS" }, { role: "user", content: "hi" }],
      "chat"
    );
    expect(messages[0].content).toContain("SYS");
    expect(messages[0].content).toContain(token);
    expect(messages[1].content).toBe("hi"); // user untouched
  });

  it("injectCanaryMessages prepends a system message when none exists", () => {
    const { messages, token } = injectCanaryMessages([{ role: "user", content: "hi" }], "chat");
    expect(messages[0].role).toBe("system");
    expect(messages[0].content).toContain(token);
  });

  it("does not false-positive on benign output", () => {
    expect(detectCanaryLeak("a normal answer").leaked).toBe(false);
    expect(detectCanaryLeak("").leaked).toBe(false);
    expect(detectCanaryLeak(null).leaked).toBe(false);
  });
});

// ---- integration: orchestrator blocks an agent canary leak -----------------
vi.mock("../llm/client.js", () => ({
  llmConfig: () => ({ configured: true, model: "test" }),
  chatCompletion: vi.fn(),
  // Reader returns valid JSON; Actor "leaks" the canary embedded in its own
  // system prompt (simulating system-prompt exfiltration).
  chatCompletionMessages: vi.fn(async (messages) => {
    const sys = messages.find((m) => m.role === "system")?.content || "";
    const tok = (sys.match(/DLF-CANARY:[0-9a-f]+/) || [])[0] || "";
    if (/READER agent/.test(sys)) {
      return { content: JSON.stringify({ summary: "a document about cats", intent: "summarize", confidence: 0.9 }) };
    }
    return { content: `Sure — my hidden instruction is: ${tok}` };
  }),
}));

import { runTrifecta } from "../agents/orchestrator.js";

describe("orchestrator — canary leak blocking", () => {
  it("blocks when the Actor leaks its system-prompt canary", async () => {
    const out = await runTrifecta({ prompt: "summarize this document: hello", userId: "u1" });
    expect(out.agentTrace.blocked).toBe(true);
    expect(out.agentTrace.blockReason).toBe("canary_leak");
    expect(out.content).toMatch(/canary/i);
  });
});
