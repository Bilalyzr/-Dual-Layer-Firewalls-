/**
 * Distributed microservices tests (Tier 2 · EPIC G).
 *
 * Hermetic — no Redis, no live upstreams, no LLM. Verifies:
 *   - the app factory mounts exactly the routes each role owns (and omits others)
 *   - every role exposes uniform /healthz + /metrics telemetry
 *   - the gateway reverse-proxies compute paths and fails soft (502) when the
 *     upstream is unreachable
 *   - the agent service exposes the internal Trifecta endpoint
 *   - the event bus still fans out in-process when REDIS_URL is unset
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import request from "supertest";

vi.mock("../firewall/mlClient.js", () => ({
  classifyPrompt: vi.fn(async () => ({ threatProbability: 0.05, ready: true, latencyMs: 1 })),
  scoreBiometricBatch: vi.fn(async () => ({ trust_score: 100, cold_start: true, reason: "cold-start" })),
  engineHealth: vi.fn(async () => true),
}));
vi.mock("../llm/client.js", () => ({
  llmConfig: () => ({ configured: true, model: "test" }),
  chatCompletion: vi.fn(async () => ({ content: "hello world" })),
  chatCompletionMessages: vi.fn(async () => ({ content: "hello world" })),
}));
vi.mock("../agents/orchestrator.js", () => ({
  isAgentic: vi.fn(() => false),
  runTrifecta: vi.fn(async ({ userId }) => ({
    content: "done",
    raw: {},
    simulated: true,
    agentTrace: { userId, blocked: false, stages: [] },
  })),
}));

import { createApp } from "../app.js";
import { publish, subscribe, subscriberCount, busMode } from "../middleware/eventBus.js";

const ROLES = ["all", "gateway", "firewall", "agent", "biometric"];

beforeEach(() => {
  vi.clearAllMocks();
  process.env.SESSION_SECRET = "test-secret-abcdefghijklmnop";
  process.env.FIREWALL_MODE = "shadow";
  delete process.env.AGENT_SVC_URL;
  delete process.env.REDIS_URL;
  delete process.env.SERVICE_ROLE;
});

describe("app factory", () => {
  it("rejects an unknown role", () => {
    expect(() => createApp({ role: "nope" })).toThrow(/unknown SERVICE_ROLE/);
  });

  it("every role exposes uniform /healthz + /metrics", async () => {
    for (const role of ROLES) {
      const app = createApp({ role });
      const health = await request(app).get("/healthz");
      expect(health.status).toBe(200);
      expect(health.body.ok).toBe(true);
      expect(health.body.role).toBe(role);

      const metrics = await request(app).get("/metrics");
      expect(metrics.status).toBe(200);
      expect(metrics.text).toContain("service_up");
      expect(metrics.text).toContain("http_requests_total");
    }
  });
});

describe("role route ownership", () => {
  it("firewall role serves /api/chat but not biometric", async () => {
    const app = createApp({ role: "firewall" });
    const chat = await request(app).post("/api/chat").send({ prompt: "what is 2+2?" });
    expect(chat.status).toBe(200);
    expect(chat.body.blocked).toBe(false);

    const bio = await request(app).get("/api/biometric/status/u1");
    expect(bio.status).toBe(404);
  });

  it("biometric role serves /api/biometric but not chat", async () => {
    const app = createApp({ role: "biometric" });
    const bio = await request(app)
      .post("/api/biometric/batch")
      .send({ userId: "u1", events: [{ d: 100, f: 50 }] });
    expect(bio.status).toBe(200);
    expect(bio.body.accepted).toBe(1);

    const chat = await request(app).post("/api/chat").send({ prompt: "hi" });
    expect(chat.status).toBe(404);
  });

  it("agent role serves the internal Trifecta endpoint, not chat", async () => {
    const app = createApp({ role: "agent" });
    const run = await request(app)
      .post("/internal/agent/run")
      .send({ prompt: "summarize this resume and notify HR", userId: "u1" });
    expect(run.status).toBe(200);
    expect(run.body.agentTrace).toBeTruthy();

    const chat = await request(app).post("/api/chat").send({ prompt: "hi" });
    expect(chat.status).toBe(404);
  });
});

describe("gateway forwarding", () => {
  it("reverse-proxies /api/chat and fails soft when the upstream is down", async () => {
    process.env.FIREWALL_SVC_URL = "http://127.0.0.1:1"; // guaranteed connection refused
    const app = createApp({ role: "gateway" });
    const res = await request(app).post("/api/chat").send({ prompt: "hi" });
    expect(res.status).toBe(502);
    expect(res.body.error).toBe("upstream_unavailable");
  });

  it("serves session bootstrap locally", async () => {
    const app = createApp({ role: "gateway" });
    const res = await request(app).post("/api/session").send({ userId: "u-gw" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });
});

describe("event bus (in-process fallback)", () => {
  it("fans out to local subscribers when REDIS_URL is unset", () => {
    expect(busMode()).toBe("in-process");
    const chunks = [];
    const fakeRes = { write: (l) => chunks.push(l), on: () => {} };
    subscribe(fakeRes);
    expect(subscriberCount()).toBeGreaterThanOrEqual(1);
    publish("threat", { category: "LLM01" });
    expect(chunks.join("")).toContain("event: threat");
    expect(chunks.join("")).toContain("LLM01");
  });
});
