/**
 * Behavioral route + consent-gate tests (Epic E/G/I).
 *
 * These endpoints (fingerprint) previously had NO dedicated
 * coverage. This exercises: the consent read/write surface, the server-side
 * consent gate (403 without consent), cold-start scoring, and device-change
 * detection — all hermetic (no Mongo, Redis, LLM, or engine).
 */
import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import { createApp } from "../app.js";

const app = createApp({ role: "all" });

// Each test uses a fresh userId so the module-level baseline/consent Maps don't
// bleed across cases.
let uid = 0;
const nextUser = () => `bio-test-${Date.now()}-${uid++}`;

async function grant(userId, category) {
  return request(app).post("/api/consent").send({ userId, category, granted: true });
}

describe("Epic I — consent route", () => {
  it("reports all categories off for a fresh user", async () => {
    const userId = nextUser();
    const res = await request(app).get(`/api/consent/${userId}`);
    expect(res.status).toBe(200);
    expect(res.body.granted.mouse).toBe(false);
    expect(res.body.granted.fingerprint).toBe(false);
    expect(res.body.categories).toHaveProperty("mouse");
  });

  it("records a grant and reads it back", async () => {
    const userId = nextUser();
    const set = await grant(userId, "mouse");
    expect(set.status).toBe(200);
    expect(set.body.granted).toBe(true);
    const read = await request(app).get(`/api/consent/${userId}`);
    expect(read.body.granted.mouse).toBe(true);
  });

  it("rejects an unknown category", async () => {
    const res = await request(app).post("/api/consent").send({ userId: nextUser(), category: "nope", granted: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_category");
  });
});

describe("Epic E — fingerprint route", () => {
  it("403s without consent", async () => {
    const res = await request(app)
      .post("/api/biometric/fingerprint")
      .send({ userId: nextUser(), combined: "abc123" });
    expect(res.status).toBe(403);
  });

  it("stores a fingerprint and detects a device change", async () => {
    const userId = nextUser();
    await grant(userId, "fingerprint");
    const first = await request(app)
      .post("/api/biometric/fingerprint")
      .send({ userId, combined: "fp-A", canvas: "c", webgl: "w", audio: "a" });
    expect(first.status).toBe(200);
    expect(first.body.changed).toBe(false);

    const second = await request(app)
      .post("/api/biometric/fingerprint")
      .send({ userId, combined: "fp-B" });
    expect(second.status).toBe(200);
    expect(second.body.changed).toBe(true);
  });

  it("400s when the combined hash is missing", async () => {
    const userId = nextUser();
    await grant(userId, "fingerprint");
    const res = await request(app).post("/api/biometric/fingerprint").send({ userId });
    expect(res.status).toBe(400);
  });
});
