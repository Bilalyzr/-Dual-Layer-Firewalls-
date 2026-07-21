/**
 * EPIC F — tool adapter tests.
 *
 * Covers: mock fallback when creds absent, real mode when creds set, RBAC still
 * enforced (a reader can never call tools), per-tool rate limiting, and that
 * every call lands in the audit trail.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { callTool, auditTrail } from "../agents/tools.js";
import { canCall } from "../agents/rbac.js";
import { _resetForTests } from "../agents/tools/_audit.js";

beforeEach(() => {
  _resetForTests();
  // Clear all credential env vars — mock fallback by default
  for (const k of ["NOTIFY_WEBHOOK_URL", "NOTIFY_SMTP_URL", "LOOKUP_API_URL", "LOOKUP_API_KEY", "SUMMARY_INDEX_URL"]) {
    delete process.env[k];
  }
});
afterEach(() => {
  _resetForTests();
  vi.unstubAllGlobals();
});

describe("EPIC F — mock fallback when creds absent", () => {
  it("notify falls back to mock with no creds", async () => {
    const r = await callTool("notify", { message: "hello", channel: "email" });
    expect(r.ok).toBe(true);
    expect(r.mode).toBe("mock");
    expect(r.result).toMatch(/mock.*hello/);
  });

  it("lookup falls back to mock with no creds", async () => {
    const r = await callTool("lookup", { query: "status" });
    expect(r.ok).toBe(true);
    expect(r.mode).toBe("mock");
    expect(r.result).toMatch(/status/);
  });

  it("summarize falls back to mock with no creds", async () => {
    const r = await callTool("summarize", { topic: "report" });
    expect(r.ok).toBe(true);
    expect(r.mode).toBe("mock");
  });
});

describe("EPIC F — real mode when creds set", () => {
  it("notify uses webhook when NOTIFY_WEBHOOK_URL set", async () => {
    process.env.NOTIFY_WEBHOOK_URL = "https://hooks.example.test/incoming";
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await callTool("notify", { message: "real send" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(r.mode).toBe("webhook");
    expect(r.ok).toBe(true);
  });

  it("lookup queries the KB when LOOKUP_API_URL set", async () => {
    process.env.LOOKUP_API_URL = "https://kb.example.test/search";
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ results: [{ text: "answer from KB" }] }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await callTool("lookup", { query: "what" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(r.mode).toBe("kb");
    expect(r.result).toMatch(/answer from KB/);
  });

  it("unknown tool returns an error (not a crash)", async () => {
    const r = await callTool("exec", {});
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/unknown tool/);
  });
});

describe("EPIC F — RBAC still enforced (defense in depth)", () => {
  // Note: actorAgent.js enforces canCall BEFORE invoking callTool; we assert the
  // permission matrix here too so the contract is independently verified.
  it("readers can NEVER call notify / lookup / summarize", () => {
    expect(canCall("reader", "notify")).toBe(false);
    expect(canCall("reader", "lookup")).toBe(false);
    expect(canCall("reader", "summarize")).toBe(false);
  });
  it("actors CAN call all three tools", () => {
    expect(canCall("actor", "notify")).toBe(true);
    expect(canCall("actor", "lookup")).toBe(true);
    expect(canCall("actor", "summarize")).toBe(true);
  });
});

describe("EPIC F — rate limiting", () => {
  it("rate-limits notify after the configured cap", async () => {
    // notify rate limit = 5/min (per tools/notify.js config)
    const results = [];
    for (let i = 0; i < 7; i++) {
      results.push(await callTool("notify", { message: `msg ${i}` }));
    }
    const ok = results.filter((r) => r.ok);
    const limited = results.filter((r) => !r.ok && r.error?.includes("rate_limited"));
    expect(ok.length).toBe(5);
    expect(limited.length).toBe(2);
  });

  it("lookup has a higher rate limit (20/min)", async () => {
    // sanity: 3 calls should all succeed
    for (let i = 0; i < 3; i++) {
      const r = await callTool("lookup", { query: `q${i}` });
      expect(r.ok).toBe(true);
    }
  });
});

describe("EPIC F — audit trail", () => {
  it("every successful call is recorded", async () => {
    await callTool("notify", { message: "a" });
    await callTool("lookup", { query: "b" });
    const trail = auditTrail(10);
    expect(trail.length).toBeGreaterThanOrEqual(2);
    expect(trail.some((t) => t.tool === "notify")).toBe(true);
    expect(trail.some((t) => t.tool === "lookup")).toBe(true);
  });
});
