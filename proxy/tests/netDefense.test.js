/**
 * Tier 3 · Wave 2 · Epic E — network-level defenses.
 *
 * Covers the acceptance criteria:
 *   - geo/ASN fencing denies a listed country and allow-lists correctly (fails open
 *     when there is no geo signal)
 *   - a DNSBL-listed IP is detected (cached, fail-open on resolver error)
 *   - request cadence + a blocklisted JA3 produce a bot score over threshold
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("../forensics/geoip.js", () => ({ lookupGeo: vi.fn(async () => null) }));
vi.mock("../forensics/asn.js", () => ({ lookupAsn: vi.fn(async () => null) }));
vi.mock("node:dns", () => ({
  default: { promises: { resolve4: vi.fn() } },
}));

import { evaluateGeofence } from "../middleware/geoFence.js";
import { lookupGeo } from "../forensics/geoip.js";
import { lookupAsn } from "../forensics/asn.js";
import { checkDnsbl } from "../forensics/dnsbl.js";
import dns from "node:dns";
import { recordCadence, evaluateBot, __resetJa3Cache } from "../middleware/botScore.js";
import { __clearMemoryStore } from "../lib/store.js";

beforeEach(() => {
  __clearMemoryStore();
  __resetJa3Cache();
  vi.clearAllMocks();
});

describe("geo/ASN fencing", () => {
  it("denies a listed country in deny mode", async () => {
    process.env.GEOFENCE_MODE = "deny";
    process.env.GEOFENCE_LIST = "RU,KP";
    lookupGeo.mockResolvedValue({ country: "RU" });
    const v = await evaluateGeofence("203.0.113.7");
    expect(v.blocked).toBe(true);
    expect(v.country).toBe("RU");
  });

  it("blocks a non-allow-listed country in allow mode", async () => {
    process.env.GEOFENCE_MODE = "allow";
    process.env.GEOFENCE_LIST = "US,CA";
    lookupGeo.mockResolvedValue({ country: "RU" });
    expect((await evaluateGeofence("203.0.113.8")).blocked).toBe(true);
  });

  it("permits an allow-listed country", async () => {
    process.env.GEOFENCE_MODE = "allow";
    process.env.GEOFENCE_LIST = "US,CA";
    lookupGeo.mockResolvedValue({ country: "US" });
    expect((await evaluateGeofence("203.0.113.9")).blocked).toBe(false);
  });

  it("denies a listed ASN", async () => {
    process.env.GEOFENCE_MODE = "deny";
    process.env.GEOFENCE_LIST = "AS64500";
    lookupGeo.mockResolvedValue(null);
    lookupAsn.mockResolvedValue({ asn: 64500 });
    const v = await evaluateGeofence("203.0.113.10");
    expect(v.blocked).toBe(true);
    expect(v.asn).toBe(64500);
  });

  it("fails open when there is no geo signal", async () => {
    process.env.GEOFENCE_MODE = "deny";
    process.env.GEOFENCE_LIST = "RU";
    lookupGeo.mockResolvedValue(null);
    lookupAsn.mockResolvedValue(null);
    expect((await evaluateGeofence("203.0.113.11")).blocked).toBe(false);
  });

  it("is a no-op when disabled", async () => {
    process.env.GEOFENCE_MODE = "off";
    expect((await evaluateGeofence("203.0.113.12")).blocked).toBe(false);
  });
});

describe("DNSBL check", () => {
  beforeEach(() => {
    process.env.DNSBL_ENABLED = "true";
    process.env.DNSBL_ZONES = "zen.spamhaus.org";
  });

  it("flags a listed IP (reverse-octet A record answer)", async () => {
    dns.promises.resolve4.mockResolvedValue(["127.0.0.2"]);
    const v = await checkDnsbl("203.0.113.50");
    expect(v.listed).toBe(true);
    expect(v.zones).toContain("zen.spamhaus.org");
    // query name is reversed
    expect(dns.promises.resolve4).toHaveBeenCalledWith("50.113.0.203.zen.spamhaus.org");
  });

  it("treats NXDOMAIN as not-listed", async () => {
    dns.promises.resolve4.mockRejectedValue(Object.assign(new Error("nx"), { code: "ENOTFOUND" }));
    expect((await checkDnsbl("203.0.113.51")).listed).toBe(false);
  });

  it("fails open on a resolver error and skips private IPs", async () => {
    dns.promises.resolve4.mockRejectedValue(new Error("SERVFAIL"));
    expect((await checkDnsbl("203.0.113.52")).listed).toBe(false);
    // private IP is never queried
    dns.promises.resolve4.mockClear();
    expect((await checkDnsbl("10.0.0.1")).listed).toBe(false);
    expect(dns.promises.resolve4).not.toHaveBeenCalled();
  });
});

describe("bot scoring", () => {
  it("computes cadence stats over the window", async () => {
    const ip = "198.51.100.60";
    const base = Date.now() - 100;
    for (let i = 0; i < 4; i++) await recordCadence(ip, base + i * 10);
    const stats = await recordCadence(ip, base + 40);
    expect(stats.count).toBe(5);
    expect(stats.meanIntervalMs).toBeLessThan(300); // too fast
    expect(stats.cv).toBeLessThan(0.12); // too regular
  });

  it("scores a blocklisted JA3 as a bot", async () => {
    process.env.JA3_BLOCKLIST = "deadbeefcafe1234";
    __resetJa3Cache();
    const r = await evaluateBot("198.51.100.61", { "x-ja3": "DEADBEEFCAFE1234" });
    expect(r.signals).toContain("ja3-blocklist");
    expect(r.score).toBeGreaterThanOrEqual(70);
    expect(r.bot).toBe(true);
  });

  it("does not flag a slow, human-paced client", async () => {
    const ip = "198.51.100.62";
    const now = Date.now();
    // 5 requests spread ~5s apart → slow + irregular.
    await recordCadence(ip, now - 20000);
    await recordCadence(ip, now - 14000);
    await recordCadence(ip, now - 9000);
    await recordCadence(ip, now - 3000);
    const r = await evaluateBot(ip, {});
    expect(r.bot).toBe(false);
  });
});
