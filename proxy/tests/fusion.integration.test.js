/**
 * Trust-fusion integration (Epic G).
 *
 * Proves the mouse/touch channels are actually folded into the step-up decision:
 * a keystroke trust that ALONE sits above the threshold gets pulled below it once
 * a persisted, disagreeing mouse baseline is fused in — so step-up fires. Also
 * confirms the no-fusion baseline (no aux channel) leaves the decision unchanged.
 *
 * Uses the in-memory Mongo fallback (no real DB) via the shared repository.
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

import { sessionMiddleware } from "../auth/session.js";
import sessionRouter from "../routes/session.js";
import biometricRouter from "../routes/biometric.js";
import { scoreBiometricBatch } from "../firewall/mlClient.js";
import { upsertBehaviorBaseline } from "../db/mongo.js";

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(sessionMiddleware);
  app.use("/api/session", sessionRouter);
  app.use("/api/biometric", biometricRouter);
  return app;
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.SESSION_SECRET = "test-secret-abcdefghijklmnop";
  process.env.BIOMETRIC_MODE = "enforce";
  process.env.BIOMETRIC_STEPUP_THRESHOLD = "50";
  delete process.env.BIOMETRIC_FUSION;
});

async function newSession(app, userId) {
  const { body } = await request(app).post("/api/session").send({ userId });
  return { Authorization: `Bearer ${body.token}` };
}

describe("fusion → step-up", () => {
  it("keystroke trust of 55 alone does NOT trip step-up", async () => {
    const app = buildApp();
    const auth = await newSession(app, "u-nofuse");
    scoreBiometricBatch.mockResolvedValue({ trust_score: 55, risk_score: 45, z: 1.2, cold_start: false, reason: "borderline" });
    const bio = await request(app).post("/api/biometric/batch").set(auth)
      .send({ events: [{ d: 100, f: 50 }] });
    expect(bio.body.stepUpRequired).toBe(false);
    expect(bio.body.fused).toBe(false); // no aux channel
    expect(bio.body.fused_trust_score).toBe(55);
  });

  it("a persisted disagreeing mouse baseline pulls fused trust below threshold → step-up", async () => {
    const app = buildApp();
    const auth = await newSession(app, "u-fuse");
    // Seed an established mouse baseline that strongly disagrees (score 0).
    await upsertBehaviorBaseline("u-fuse", "mouse", {
      meanSpeed: 1, turnRate: 0.3, cadence: 20, n: 60,
      lastScore: 0.0, lastColdStart: false, lastTs: new Date(),
    });
    scoreBiometricBatch.mockResolvedValue({ trust_score: 55, risk_score: 45, z: 1.2, cold_start: false, reason: "borderline" });
    const bio = await request(app).post("/api/biometric/batch").set(auth)
      .send({ events: [{ d: 100, f: 50 }] });
    expect(bio.body.fused).toBe(true);
    expect(bio.body.fused_trust_score).toBeLessThan(50);
    expect(bio.body.stepUpRequired).toBe(true);
  });

  it("a cold-start mouse baseline is ignored (no fusion)", async () => {
    const app = buildApp();
    const auth = await newSession(app, "u-coldaux");
    await upsertBehaviorBaseline("u-coldaux", "mouse", {
      meanSpeed: 1, turnRate: 0.3, cadence: 20, n: 3,
      lastScore: 0.5, lastColdStart: true, lastTs: new Date(),
    });
    scoreBiometricBatch.mockResolvedValue({ trust_score: 55, risk_score: 45, z: 1.2, cold_start: false, reason: "borderline" });
    const bio = await request(app).post("/api/biometric/batch").set(auth)
      .send({ events: [{ d: 100, f: 50 }] });
    expect(bio.body.fused).toBe(false);
    expect(bio.body.stepUpRequired).toBe(false);
  });
});
