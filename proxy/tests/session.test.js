/**
 * Session & step-up tests (Tier 2 · EPIC A + B).
 *
 * Uses the in-memory Mongo fallback (no real DB). Covers:
 *   - signed session token round-trip + tamper rejection
 *   - the pure shouldStepUp enforcement decision
 *   - biometric enforce mode marking a session stepUpRequired
 *   - /api/chat gating a stepUpRequired session with 401 step_up_required
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

vi.mock("../firewall/mlClient.js", () => ({
  classifyPrompt: vi.fn(async () => ({ threatProbability: 0.1, ready: true, latencyMs: 1 })),
  scoreBiometricBatch: vi.fn(),
  engineHealth: vi.fn(async () => true),
}));
vi.mock("../llm/client.js", () => ({
  llmConfig: () => ({ configured: true, model: "test" }),
  chatCompletion: vi.fn(async () => ({ content: "ok" })),
  chatCompletionMessages: vi.fn(async () => ({ content: "ok" })),
}));

import {
  signSession,
  verifyToken,
  createSession,
  shouldStepUp,
  sessionMiddleware,
  requireStepUp,
} from "../auth/session.js";
import sessionRouter from "../routes/session.js";
import chatRouter from "../routes/chat.js";

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(sessionMiddleware);
  app.use("/api/session", sessionRouter);
  app.use("/api/chat", chatRouter);
  return app;
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.SESSION_SECRET = "test-secret-abcdefghijklmnop";
});

describe("session token", () => {
  it("round-trips a signed token", () => {
    const t = signSession("abc123");
    expect(verifyToken(t)).toBe("abc123");
  });

  it("rejects a tampered token", () => {
    const t = signSession("abc123");
    expect(verifyToken(t.replace(/.$/, "X"))).toBeNull();
    expect(verifyToken("abc123.deadbeef")).toBeNull();
    expect(verifyToken("garbage")).toBeNull();
  });
});

describe("shouldStepUp decision", () => {
  const base = { mode: "enforce", trustScore: 40, threshold: 50, coldStart: false };
  it("requires step-up when trust collapses in enforce mode", () => {
    expect(shouldStepUp(base)).toBe(true);
  });
  it("never steps up in shadow mode", () => {
    expect(shouldStepUp({ ...base, mode: "shadow" })).toBe(false);
  });
  it("never steps up during cold-start", () => {
    expect(shouldStepUp({ ...base, coldStart: true })).toBe(false);
  });
  it("allows trust above threshold", () => {
    expect(shouldStepUp({ ...base, trustScore: 80 })).toBe(false);
  });
});

describe("POST /api/session", () => {
  it("issues a usable token that GET /api/session reads back", async () => {
    const app = buildApp();
    const create = await request(app).post("/api/session").send({ userId: "u-epicA" });
    expect(create.body.token).toBeTruthy();
    expect(create.body.trustState.stepUpRequired).toBe(false);
    const me = await request(app)
      .get("/api/session")
      .set("Authorization", `Bearer ${create.body.token}`);
    expect(me.status).toBe(200);
    expect(me.body.userId).toBe("u-epicA");
  });

  it("GET /api/session 401s without a token", async () => {
    const res = await request(buildApp()).get("/api/session");
    expect(res.status).toBe(401);
  });
});

describe("step-up → chat gate", () => {
  it("marks the session for step-up and then blocks chat", async () => {
    process.env.FIREWALL_MODE = "shadow";
    const app = buildApp();

    // Bootstrap a real, signed session.
    const { body } = await request(app).post("/api/session").send({ userId: "u-collapse" });
    const auth = { Authorization: `Bearer ${body.token}` };

    await requireStepUp(body.sessionId, "anomalous session risk");

    // Chat must now be frozen until a WebAuthn assertion clears step-up.
    const chat = await request(app).post("/api/chat").set(auth).send({ prompt: "hello" });
    expect(chat.status).toBe(401);
    expect(chat.body.reason).toBe("step_up_required");

    // Re-minting a session for the same locked userId must NOT bypass step-up MFA.
    const reminted = await request(app).post("/api/session").send({ userId: "u-collapse" });
    expect(reminted.body.trustState.stepUpRequired).toBe(true);
  });
});
