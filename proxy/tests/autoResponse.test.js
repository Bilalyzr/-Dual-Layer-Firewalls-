/**
 * Tier 3 · Wave 1 · Epic C — automated response engine.
 *
 * Covers the acceptance criteria:
 *   - N strikes from one IP within the window → auto-ban
 *   - a banned IP is refused on its NEXT request (edge guard), before the pipeline
 *   - bans expire on their own (TTL)
 *   - a whole /24 is banned once enough distinct offenders share it
 *   - honeypot mode returns a delayed fake response instead of a hard block
 *   - a false-positive unban lifts the ban; kill switch disables enforcement
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import express from "express";
import request from "supertest";
import { ipContextMiddleware } from "../middleware/ipContext.js";
import { ipGuardMiddleware } from "../middleware/ipGuard.js";
import responseRouter from "../routes/response.js";
import {
  recordOffense,
  isBanned,
  banIp,
  unbanIp,
  setKillSwitch,
  __resetBanStoreForTests,
} from "../response/banStore.js";
import { __clearMemoryStore, kvExists } from "../lib/store.js";

function guardApp() {
  const app = express();
  app.use(express.json());
  app.use(ipContextMiddleware);
  app.use(ipGuardMiddleware);
  app.post("/api/chat", (_req, res) => res.json({ reached: true }));
  return app;
}

function opsApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/response", responseRouter);
  return app;
}

// Send a request whose resolved client IP is `ip` (loopback peer is trusted, so
// the XFF is honored — same path a real edge proxy takes).
const asClient = (app, ip) =>
  request(app).post("/api/chat").set("X-Forwarded-For", ip).send({ prompt: "hi" });

beforeEach(() => {
  __clearMemoryStore();
  __resetBanStoreForTests();
  process.env.RESPONSE_MODE = "block";
  process.env.AUTO_BAN_THRESHOLD = "3";
  process.env.AUTO_BAN_WINDOW = "600";
  process.env.AUTO_BAN_TTL = "3600";
  process.env.AUTO_BAN_CIDR_THRESHOLD = "3";
  delete process.env.RESPONSE_KILL_SWITCH;
  delete process.env.OPS_TOKEN;
  delete process.env.HONEYPOT_DELAY_MS;
});

afterEach(() => {
  delete process.env.RESPONSE_MODE;
});

describe("recordOffense — N strikes → auto-ban", () => {
  it("bans an IP on the Nth offence within the window", async () => {
    const ip = "203.0.113.5";
    let r = await recordOffense(ip);
    expect(r.banned).toBe(false);
    r = await recordOffense(ip);
    expect(r.banned).toBe(false);
    r = await recordOffense(ip); // 3rd = threshold
    expect(r.banned).toBe(true);
    expect(r.ban.ttl).toBeGreaterThan(0);
    expect((await isBanned(ip)).banned).toBe(true);
  });

  it("does not ban while the engine is off (shadow observes only)", async () => {
    process.env.RESPONSE_MODE = "off";
    const ip = "203.0.113.6";
    for (let i = 0; i < 6; i++) await recordOffense(ip);
    expect((await isBanned(ip)).banned).toBe(false);
  });
});

describe("edge guard — blocks banned IPs before the pipeline", () => {
  it("passes a clean IP through to the route", async () => {
    const res = await asClient(guardApp(), "198.51.100.10");
    expect(res.status).toBe(200);
    expect(res.body.reached).toBe(true);
  });

  it("refuses a banned IP with a terse 403 in block mode", async () => {
    await banIp("198.51.100.11", 3600, "test");
    const res = await asClient(guardApp(), "198.51.100.11");
    expect(res.status).toBe(403);
    expect(res.body.blocked).toBe(true);
    expect(res.body.reason).toBe("forbidden");
  });

  it("serves a delayed fake response in honeypot mode", async () => {
    process.env.RESPONSE_MODE = "honeypot";
    process.env.HONEYPOT_DELAY_MS = "0";
    await banIp("198.51.100.12", 3600, "test");
    const res = await asClient(guardApp(), "198.51.100.12");
    expect(res.status).toBe(200);
    expect(res.body.simulated).toBe(true);
    expect(res.body.verdict.mode).toBe("honeypot");
  });

  it("lets everything through when the kill switch is engaged", async () => {
    await banIp("198.51.100.13", 3600, "test");
    setKillSwitch(true);
    const res = await asClient(guardApp(), "198.51.100.13");
    expect(res.body.reached).toBe(true); // enforcement disabled
    setKillSwitch(false);
  });
});

describe("ban expiry", () => {
  it("auto-expires a short-TTL ban", async () => {
    await banIp("198.51.100.20", 1, "test"); // 1-second TTL
    expect((await isBanned("198.51.100.20")).banned).toBe(true);
    await new Promise((r) => setTimeout(r, 1100));
    expect(await kvExists("fx:ban:198.51.100.20")).toBe(false);
    expect((await isBanned("198.51.100.20")).banned).toBe(false);
  });
});

describe("CIDR range ban", () => {
  it("bans a whole /24 once enough distinct offenders appear", async () => {
    process.env.AUTO_BAN_THRESHOLD = "100"; // keep single-IP bans out of the way
    process.env.AUTO_BAN_CIDR_THRESHOLD = "3";
    await recordOffense("203.0.113.10");
    await recordOffense("203.0.113.20");
    const r = await recordOffense("203.0.113.30"); // 3rd distinct offender in /24
    expect(r.cidrBan).toBeTruthy();
    expect(r.cidrBan.cidr).toBe("203.0.113.0/24");
    // A brand-new IP in that /24 is now banned by the range.
    const v = await isBanned("203.0.113.200");
    expect(v.banned).toBe(true);
    expect(v.scope).toBe("cidr");
  });
});

describe("ops endpoints", () => {
  it("manually bans, lists, and unbans an IP (false-positive recovery)", async () => {
    const app = opsApp();
    await request(app).post("/api/response/ban").send({ ip: "203.0.113.77", ttl: 3600 }).expect(200);
    expect((await isBanned("203.0.113.77")).banned).toBe(true);

    const bans = await request(app).get("/api/response/bans").expect(200);
    expect(bans.body.ips.some((b) => b.ip === "203.0.113.77")).toBe(true);

    await request(app).post("/api/response/unban").send({ ip: "203.0.113.77" }).expect(200);
    expect((await isBanned("203.0.113.77")).banned).toBe(false);
  });

  it("engages the kill switch via the ops endpoint", async () => {
    const app = opsApp();
    const res = await request(app).post("/api/response/killswitch").send({ enabled: true }).expect(200);
    expect(res.body.killSwitch).toBe(true);
    setKillSwitch(false); // reset for other tests
  });

  it("enforces OPS_TOKEN when configured", async () => {
    process.env.OPS_TOKEN = "s3cret";
    const app = opsApp();
    await request(app).post("/api/response/unban").send({ ip: "1.2.3.4" }).expect(403);
    await request(app)
      .post("/api/response/unban")
      .set("x-ops-token", "s3cret")
      .send({ ip: "1.2.3.4" })
      .expect(200);
  });
});
