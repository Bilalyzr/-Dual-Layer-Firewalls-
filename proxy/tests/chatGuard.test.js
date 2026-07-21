/**
 * Chat pipeline · Llama Guard enforcement (Tier 2 · EPIC C).
 *
 * Proves an unsafe prompt Llama Guard flags is blocked in enforce mode with the
 * mapped OWASP category — even when the regex heuristics and the ML classifier
 * both miss it. The guard module is mocked so the test is offline+deterministic.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../firewall/mlClient.js", () => ({
  classifyPrompt: vi.fn(async () => ({ threatProbability: 0.05, ready: true, latencyMs: 1 })),
  scoreBiometricBatch: vi.fn(),
  engineHealth: vi.fn(async () => true),
}));
vi.mock("../llm/client.js", () => ({
  llmConfig: () => ({ configured: true, model: "test" }),
  chatCompletion: vi.fn(async () => ({ content: "ok" })),
  chatCompletionMessages: vi.fn(async () => ({ content: "ok" })),
}));
vi.mock("../firewall/llamaGuard.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, moderateContent: vi.fn() };
});

import chatRouter from "../routes/chat.js";
import { moderateContent } from "../firewall/llamaGuard.js";

beforeEach(() => vi.clearAllMocks());

function app() {
  const a = express();
  a.use(express.json());
  a.use("/api/chat", chatRouter);
  return a;
}

describe("chat pipeline · Llama Guard enforcement", () => {
  it("blocks an unsafe prompt in enforce mode when heuristics + classifier miss", async () => {
    process.env.FIREWALL_MODE = "enforce";
    process.env.FIREWALL_THRESHOLD = "0.65";
    moderateContent.mockResolvedValueOnce({
      enabled: true, safe: false, categories: ["S9"],
      owasp: [{ code: "S9", name: "Indiscriminate Weapons", owasp: "LLM06" }], latencyMs: 5,
    });

    const res = await request(app())
      .post("/api/chat")
      .send({ prompt: "an innocuous-looking sentence with no regex trigger", userId: "u1" });

    expect(res.body.blocked).toBe(true);
    expect(res.body.category).toBe("LLM06");
    expect(res.body.verdict.llamaGuard.safe).toBe(false);
  });

  it("allows a safe prompt (guard clears both input and output)", async () => {
    process.env.FIREWALL_MODE = "enforce";
    moderateContent.mockResolvedValue({ enabled: true, safe: true, categories: [], owasp: [], latencyMs: 3 });
    const res = await request(app())
      .post("/api/chat")
      .send({ prompt: "what is the capital of France?", userId: "u1" });
    expect(res.body.blocked).toBe(false);
    expect(res.body.answer).toBe("ok");
  });
});
