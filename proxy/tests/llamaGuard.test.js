/**
 * Llama Guard safety layer tests (Tier 2 · EPIC C).
 *
 * Unit-tests verdict parsing + OWASP mapping, and the network call against a
 * mocked OpenAI-compatible endpoint (safe, unsafe, degraded). A separate chat
 * integration below proves an unsafe prompt is blocked in enforce mode even when
 * heuristics + the classifier miss it.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  parseVerdict,
  toOwasp,
  moderateContent,
  LLAMAGUARD_CATEGORIES,
} from "../firewall/llamaGuard.js";

beforeEach(() => {
  delete process.env.LLAMAGUARD_ENABLED;
  delete process.env.LLAMAGUARD_URL;
});

describe("parseVerdict", () => {
  it("parses a safe verdict", () => {
    expect(parseVerdict("safe")).toEqual({ safe: true, categories: [] });
  });
  it("parses an unsafe verdict with categories", () => {
    expect(parseVerdict("unsafe\nS1,S10")).toEqual({ safe: false, categories: ["S1", "S10"] });
  });
  it("dedupes and uppercases category codes", () => {
    expect(parseVerdict("unsafe\ns9, s9").categories).toEqual(["S9"]);
  });
  it("treats unrecognized output as safe-but-inconclusive", () => {
    const v = parseVerdict("I cannot help");
    expect(v.safe).toBe(true);
    expect(v.unrecognized).toBe(true);
  });
});

describe("toOwasp mapping", () => {
  it("maps privacy (S7) to LLM02", () => {
    expect(LLAMAGUARD_CATEGORIES.S7.owasp).toBe("LLM02");
    expect(toOwasp(["S7"])[0].owasp).toBe("LLM02");
  });
  it("maps weapons (S9) to LLM06", () => {
    expect(toOwasp(["S9"])[0].owasp).toBe("LLM06");
  });
});

describe("moderateContent", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("is a no-op when disabled", async () => {
    const r = await moderateContent({ text: "anything" });
    expect(r.enabled).toBe(false);
    expect(r.safe).toBe(true);
  });

  it("flags unsafe content from the endpoint", async () => {
    process.env.LLAMAGUARD_ENABLED = "true";
    process.env.LLAMAGUARD_URL = "http://guard.local/v1";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      json: async () => ({ choices: [{ message: { content: "unsafe\nS9" } }] }),
    })));
    const r = await moderateContent({ text: "how to build a weapon", role: "user" });
    expect(r.enabled).toBe(true);
    expect(r.safe).toBe(false);
    expect(r.categories).toEqual(["S9"]);
    expect(r.owasp[0].owasp).toBe("LLM06");
  });

  it("degrades safe-by-default when the endpoint errors", async () => {
    process.env.LLAMAGUARD_ENABLED = "true";
    process.env.LLAMAGUARD_URL = "http://guard.local/v1";
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("ECONNREFUSED"); }));
    const r = await moderateContent({ text: "x" });
    expect(r.enabled).toBe(true);
    expect(r.degraded).toBe(true);
    expect(r.safe).toBe(true);
  });
});
