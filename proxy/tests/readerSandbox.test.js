/**
 * EPIC E — Reader-Agent sandbox tests.
 *
 * Asserts the isolation contract: the Reader has NO tools (RBAC), the in-process
 * reader falls back cleanly when the sandboxed svc is unreachable, and the
 * READER_SVC_URL mode delegates to HTTP correctly.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../llm/client.js", () => ({
  chatCompletion: vi.fn(),
  chatCompletionMessages: vi.fn(),
  llmConfig: () => ({ configured: true, model: "test" }),
}));

import { canCall, toolsFor } from "../agents/rbac.js";
import { read } from "../agents/readerAgent.js";
import { chatCompletionMessages } from "../llm/client.js";

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.READER_SVC_URL;
});

describe("EPIC E — Reader sandbox RBAC", () => {
  it("the reader role has ZERO tools", () => {
    expect(toolsFor("reader")).toEqual([]);
    expect(canCall("reader", "lookup")).toBe(false);
    expect(canCall("reader", "notify")).toBe(false);
    expect(canCall("reader", "summarize")).toBe(false);
    // even an unknown tool name
    expect(canCall("reader", "exec")).toBe(false);
  });
});

describe("EPIC E — reader-svc HTTP delegation", () => {
  afterEach(() => {
    delete process.env.READER_SVC_URL;
  });

  it("delegates to reader-svc when READER_SVC_URL is set", async () => {
    process.env.READER_SVC_URL = "http://fake-reader-svc:8012";
    const svcResponse = {
      json: { summary: "from svc", intent: "summarize", confidence: 0.9 },
      raw: "...",
      valid: true,
      errors: [],
      attempts: ["..."],
      simulated: false,
    };
    // stub global fetch
    const orig = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => svcResponse,
    }));
    try {
      const events = [];
      const r = await read("untrusted text", (e) => events.push(e));
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
      expect(String(globalThis.fetch.mock.calls[0][0])).toMatch(/\/read$/);
      expect(r.valid).toBe(true);
      expect(r.json.summary).toBe("from svc");
      // must NOT have called the LLM directly — that's the svc's job now
      expect(chatCompletionMessages).not.toHaveBeenCalled();
      expect(events.some((e) => e.via === "reader-svc")).toBe(true);
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("falls back to in-process when reader-svc is unreachable", async () => {
    process.env.READER_SVC_URL = "http://nonexistent-svc:8012";
    chatCompletionMessages.mockResolvedValueOnce({
      content: JSON.stringify({ summary: "fallback", intent: "summarize", confidence: 0.7 }),
    });
    const orig = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    try {
      const r = await read("untrusted text");
      // fell through to in-process LLM
      expect(chatCompletionMessages).toHaveBeenCalled();
      expect(r.valid).toBe(true);
      expect(r.json.summary).toBe("fallback");
    } finally {
      globalThis.fetch = orig;
    }
  });

  it("falls back to in-process when READER_SVC_URL is unset", async () => {
    chatCompletionMessages.mockResolvedValueOnce({
      content: JSON.stringify({ summary: "inline", intent: "summarize", confidence: 0.8 }),
    });
    const r = await read("untrusted text");
    expect(chatCompletionMessages).toHaveBeenCalled();
    expect(r.json.summary).toBe("inline");
  });
});
