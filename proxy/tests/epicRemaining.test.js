/**
 * Tests for the remaining sub-epics: SLA tracking, system-metric anomaly
 * detection, SOC 2 evidence, fingerprint route, touch route.
 */
import { describe, it, expect, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

import { recordRequest, slaSnapshot, sampleSystemMetrics, metricHistory } from "../observability/sla.js";
import { requestLogger } from "../lib/logger.js";
import { collectEvidence, evidenceSummary } from "../compliance/soc2.js";
import { verifyChain, _resetChain } from "../compliance/auditChain.js";

beforeEach(() => _resetChain());

// ---- SLA tracking --------------------------------------------------------
describe("SLA tracking", () => {
  it("records requests and computes percentiles", () => {
    for (let i = 1; i <= 100; i++) recordRequest(i, 200);
    const s = slaSnapshot();
    expect(s.requestCount).toBe(100);
    expect(s.availability).toBe(100); // all 2xx
    expect(s.latencyMs.p50).toBeLessThanOrEqual(s.latencyMs.p99);
    expect(s.latencyMs.mean).toBeGreaterThan(0);
  });

  it("tracks error rate", () => {
    recordRequest(10, 200);
    recordRequest(10, 500);
    recordRequest(10, 200);
    const s = slaSnapshot();
    expect(s.errorRate).toBeGreaterThan(0);
    expect(s.availability).toBeLessThan(100);
  });

  it("is fed by live traffic through requestLogger (wiring, not just the pure fn)", async () => {
    const before = slaSnapshot().requestCount;
    const app = express();
    app.use(requestLogger);
    app.get("/ping", (_req, res) => res.json({ ok: true }));
    const res = await request(app).get("/ping");
    expect(res.status).toBe(200);
    const s = slaSnapshot();
    expect(s.requestCount).toBeGreaterThan(before); // driving a request populated the window
    expect(s.latencyMs.p50).toBeGreaterThanOrEqual(0);
  });
});

// ---- System-metric anomaly detection -------------------------------------
describe("system-metric anomaly detection", () => {
  it("samples CPU + memory + request-rate", () => {
    const r = sampleSystemMetrics();
    expect(r.metric).toBeDefined();
    expect(r.metric.cpuLoad).toBeGreaterThanOrEqual(0);
    expect(r.metric.memPct).toBeGreaterThan(0);
    expect(Array.isArray(r.anomalies)).toBe(true);
  });

  it("metricHistory returns recent samples", () => {
    sampleSystemMetrics();
    const h = metricHistory(10);
    expect(h.length).toBeGreaterThanOrEqual(1);
  });
});

// ---- SOC 2 evidence ------------------------------------------------------
describe("SOC 2 evidence collection", () => {
  it("collects a structured evidence report", () => {
    const r = collectEvidence();
    expect(r.controls).toBeDefined();
    expect(r.auditTrail.tamperEvident).toBe(true);
    expect(r.trustServiceCategories.security).toBe(true);
  });

  it("generates a human-readable summary", () => {
    const s = evidenceSummary();
    expect(s).toMatch(/controls operating/);
    expect(s).toMatch(/chain/);
  });
});

// ---- Fingerprint route (consent-gated) -----------------------------------
describe("fingerprint route", () => {
  it("rejects without consent", async () => {
    const app = express();
    app.use(express.json());
    const { default: router } = await import("../routes/fingerprint.js");
    app.use("/api/biometric/fingerprint", router);
    const res = await request(app).post("/api/biometric/fingerprint").send({ userId: "fp-test", combined: "abc123" });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("consent_required");
  });
});

// ---- Touch route (now consent-gated, symmetric with fingerprint) ---------
describe("touch route", () => {
  it("rejects without consent", async () => {
    const app = express();
    app.use(express.json());
    const { default: router } = await import("../routes/touch.js");
    app.use("/api/biometric/touch", router);
    const res = await request(app)
      .post("/api/biometric/touch")
      .send({ userId: "touch-nocons", meanForce: 0.5, meanArea: 20, meanVelocity: 0.3 });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("consent_required");
  });

  it("returns cold-start for a consenting new user", async () => {
    const app = express();
    app.use(express.json());
    const { setConsent } = await import("../compliance/consent.js");
    setConsent("touch-test", "touch", true);
    const { default: router } = await import("../routes/touch.js");
    app.use("/api/biometric/touch", router);
    const res = await request(app)
      .post("/api/biometric/touch")
      .send({ userId: "touch-test", meanForce: 0.5, meanArea: 20, meanVelocity: 0.3 });
    expect(res.status).toBe(200);
    expect(res.body.cold_start).toBe(true);
  });
});
