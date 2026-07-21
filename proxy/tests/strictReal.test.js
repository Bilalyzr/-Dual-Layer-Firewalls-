/**
 * Strict real-only mode tests.
 *
 * When STRICT_REAL is on (default), unconfigured backends must FAIL LOUDLY
 * instead of returning simulated/mock output. When off, the demo fallbacks
 * return as before.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { strictReal } from "../lib/strict.js";
import { chatCompletion, llmConfig } from "../llm/client.js";
import { callTool } from "../agents/tools.js";
import { _resetForTests } from "../agents/tools/_audit.js";

const LLM_ENV = ["LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"];
const CRED_ENV = ["NOTIFY_WEBHOOK_URL", "NOTIFY_SMTP_URL", "LOOKUP_API_URL", "SUMMARY_INDEX_URL"];

beforeEach(() => {
  _resetForTests();
  for (const k of [...LLM_ENV, ...CRED_ENV, "STRICT_REAL"]) delete process.env[k];
});
afterEach(() => _resetForTests());

describe("strictReal() flag", () => {
  it("defaults to on", () => {
    expect(strictReal()).toBe(true);
  });
  it("can be turned off", () => {
    process.env.STRICT_REAL = "false";
    expect(strictReal()).toBe(false);
  });
  it("is reported in llmConfig()", () => {
    expect(llmConfig().strictReal).toBe(true);
  });
});

describe("LLM refuses to simulate in strict mode", () => {
  it("throws when unconfigured + strict (no fabricated text)", async () => {
    // no LLM_API_KEY, strict default on
    await expect(chatCompletion("hello")).rejects.toThrow(/LLM_NOT_CONFIGURED/);
  });
  it("returns the demo simulation only when strict is off", async () => {
    process.env.STRICT_REAL = "false";
    const r = await chatCompletion("hello there");
    expect(r.simulated).toBe(true);
    expect(r.content).toContain("hello there");
  });
});

describe("tools refuse to mock in strict mode", () => {
  it("notify returns unconfigured (not a fake send) with no creds", async () => {
    const r = await callTool("notify", { message: "hi", channel: "email" });
    expect(r.ok).toBe(false);
    expect(r.mode).toBe("unconfigured");
  });
  it("lookup returns unconfigured (not a fake hit) with no KB", async () => {
    const r = await callTool("lookup", { query: "status" });
    expect(r.ok).toBe(false);
    expect(r.mode).toBe("unconfigured");
  });
  it("notify still uses the real webhook when configured (strict on)", async () => {
    process.env.NOTIFY_WEBHOOK_URL = "https://hooks.example.test/incoming";
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await callTool("notify", { message: "real" });
    expect(r.ok).toBe(true);
    expect(r.mode).toBe("webhook");
    vi.unstubAllGlobals();
  });
});
