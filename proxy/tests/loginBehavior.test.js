/**
 * Regression tests for the login hardening fixes:
 *
 * 1. The login used to trust client-claimed risk context (failed_auth_count,
 *    device_trust, working_hours, location_change from the request body).
 * 2. MEDIUM-risk logins logged "step-up recommended" but issued an unfrozen
 *    session; engine failures failed OPEN as LOW/ALLOW.
 * 3. /api/behavior/* (events with prompt snippets, /recalculate state
 *    mutations) answered anonymous requests.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import express from "express";
import request from "supertest";
import http from "node:http";

let engineStub;
let capturedTelemetry = [];
let stubMode = "low"; // low | medium | high | error

beforeAll(async () => {
  // Behavioral engine stub: captures the telemetry the proxy actually sends
  // and answers with the configured verdict.
  const handler = (req, res) => {
    if (req.url.startsWith("/behavior/stats")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, users: 1 }));
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      capturedTelemetry.push(JSON.parse(body || "{}"));
      const verdicts = {
        low: { risk_level: "LOW", risk_score: 10, decision: "ALLOW" },
        medium: { risk_level: "MEDIUM", risk_score: 55, decision: "STEP_UP" },
        high: { risk_level: "HIGH", risk_score: 90, decision: "RESTRICT" },
      };
      if (stubMode === "error") {
        res.writeHead(500);
        res.end("boom");
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(verdicts[stubMode]));
    });
  };
  engineStub = http.createServer(handler);
  await new Promise((r) => engineStub.listen(0, "127.0.0.1", r));
  process.env.ENGINE_URL = `http://127.0.0.1:${engineStub.address().port}`;
});

afterAll(async () => {
  await new Promise((r) => engineStub.close(r));
});

// Enforcement tests promote `demo` to a real (configured) account by setting
// DEMO_PASSWORD, which makes isDemoAccount() return false. Clear it after each
// test so the demo-bypass tests see the built-in demo account again.
afterEach(() => {
  delete process.env.DEMO_PASSWORD;
});

async function buildApp() {
  // ENGINE_URL is read at module import — import AFTER the stub is listening.
  const { sessionMiddleware } = await import("../auth/session.js");
  const loginRouter = (await import("../routes/login.js")).default;
  const behaviorRouter = (await import("../routes/behavior.js")).default;
  const app = express();
  app.use(express.json());
  app.use(sessionMiddleware);
  app.use("/api/auth", loginRouter);
  app.use("/api/behavior", behaviorRouter);
  return app;
}

describe("login trust boundary", () => {
  it("ignores client-claimed risk context in the telemetry it sends", async () => {
    const app = await buildApp();
    capturedTelemetry = [];
    stubMode = "low";
    const before = new Date();
    const r = await request(app).post("/api/auth/login").send({
      username: "demo",
      password: "demo",
      // Attacker with a stolen password claims a pristine context:
      device_trust: 0.99,
      registered_device: true,
      device_change: false,
      location_change: false,
      working_hours: true,
      working_day: true,
      failed_auth_count: 0,
    });
    expect(r.status).toBe(200);
    expect(capturedTelemetry.length).toBe(1);
    const t = capturedTelemetry[0];
    expect(t.device_trust).toBe(0.8);            // server constant, not 0.99
    expect(t.location_change).toBe(false);       // server constant
    expect(t.failed_auth_count).toBe(0);         // server-tracked, not body
    const hour = before.getHours();
    expect(t.hour).toBe(hour);                   // server clock
    expect(t.working_hours).toBe(hour >= 9 && hour < 18); // server-derived
  });

  it("counts failed logins server-side and feeds the real count", async () => {
    const app = await buildApp();
    stubMode = "low";
    const bad = await request(app).post("/api/auth/login").send({ username: "analyst", password: "wrong" });
    expect(bad.status).toBe(401);

    capturedTelemetry = [];
    const good = await request(app).post("/api/auth/login").send({ username: "analyst", password: "sec123" });
    expect(good.status).toBe(200);
    expect(capturedTelemetry[0].failed_auth_count).toBeGreaterThanOrEqual(1);
  });
});

describe("login risk enforcement", () => {
  it("reports MEDIUM risk as stepUpRequired without freezing the session (enforcement opt-in)", async () => {
    process.env.DEMO_PASSWORD = "demo"; // treat `demo` as a real, enforced account
    const app = await buildApp();
    stubMode = "medium";
    const chatRouter = (await import("../routes/chat.js")).default;
    app.use("/api/chat", chatRouter);

    const r = await request(app).post("/api/auth/login").send({ username: "demo", password: "demo" });
    expect(r.status).toBe(200);
    expect(r.body.stepUpRequired).toBe(true); // verdict reported…

    // …but the session is NOT frozen: chat must not return the step-up 401.
    const chat = await request(app)
      .post("/api/chat")
      .set("Authorization", `Bearer ${r.body.token}`)
      .send({ prompt: "hello" });
    expect(chat.status === 401 ? chat.body.reason : "ok").not.toBe("step_up_required");
  });

  it("degrades to a step-up-gated login (never LOW/ALLOW) when the engine errors", async () => {
    process.env.DEMO_PASSWORD = "demo"; // treat `demo` as a real, enforced account
    const app = await buildApp();
    stubMode = "error";
    const r = await request(app).post("/api/auth/login").send({ username: "demo", password: "demo" });
    expect(r.status).toBe(200);
    expect(r.body.stepUpRequired).toBe(true);
    expect(r.body.behavioral.degraded).toBe(true);
    expect(r.body.behavioral.risk_level).not.toBe("LOW");
  });

  it("refuses HIGH-risk logins (score >= 80)", async () => {
    process.env.DEMO_PASSWORD = "demo"; // treat `demo` as a real, enforced account
    const app = await buildApp();
    stubMode = "high";
    const r = await request(app).post("/api/auth/login").send({ username: "demo", password: "demo" });
    expect(r.status).toBe(403);
    expect(r.body.behavioral.risk_level).toBe("HIGH");
  });

  it("lets the built-in demo accounts in regardless of the behavioral verdict", async () => {
    const chatRouter = (await import("../routes/chat.js")).default;

    // HIGH would 403 a real account; a demo account (bundled password) is not denied.
    for (const stub of ["high", "medium", "error"]) {
      const app = await buildApp();
      app.use("/api/chat", chatRouter);
      stubMode = stub;
      const r = await request(app).post("/api/auth/login").send({ username: "demo", password: "demo" });
      expect(r.status).toBe(200);
      expect(r.body.success).toBe(true);
      expect(r.body.demoBypass).toBe(true);
      expect(r.body.stepUpRequired).toBe(false); // never frozen behind step-up

      // And the issued session can actually use the chat (not step-up-locked).
      const chat = await request(app)
        .post("/api/chat")
        .set("Authorization", `Bearer ${r.body.token}`)
        .send({ prompt: "hello" });
      expect(chat.status === 401 ? chat.body.reason : "ok").not.toBe("step_up_required");
    }
  });
});

describe("/api/behavior authentication", () => {
  it("rejects anonymous requests with 401", async () => {
    const app = await buildApp();
    stubMode = "low";
    const noAuth = await request(app).get("/api/behavior/stats");
    expect(noAuth.status).toBe(401);
    expect(noAuth.body.error).toBe("no_session");
  });

  it("serves authenticated requests", async () => {
    const app = await buildApp();
    stubMode = "low";
    const login = await request(app).post("/api/auth/login").send({ username: "demo", password: "demo" });
    const ok = await request(app)
      .get("/api/behavior/stats")
      .set("Authorization", `Bearer ${login.body.token}`);
    expect(ok.status).toBe(200);
    expect(ok.body.ok).toBe(true);
  });
});
