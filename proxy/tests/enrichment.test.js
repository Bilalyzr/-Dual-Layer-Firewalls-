/**
 * Tier 3 · Wave 1 · Epic B — threat enrichment pipeline.
 *
 * Covers the acceptance criteria:
 *   - enrichment output matches the §12.1 schema shape
 *   - a degraded / unconfigured API leaves the alert stored WITHOUT enrichment
 *     (fail-open) and never throws
 *   - the cache-hit path (a second lookup does not re-hit the external API)
 *   - out-of-band patching of the stored alert
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { enrichIp, requestEnrichment } from "../forensics/enrich.js";
import { lookupReputation, __resetTorCache } from "../forensics/reputation.js";
import { __clearMemoryStore } from "../lib/store.js";
import { insertAlert, recentAlerts } from "../db/mongo.js";

const SCHEMA_KEYS = ["geoip", "asn", "vpnDetected", "abuseScore", "previousOffenses"];

beforeEach(() => {
  __clearMemoryStore();
  __resetTorCache();
  // Start each test with NO external sources configured.
  for (const k of ["ABUSEIPDB_KEY", "PROXYCHECK_KEY", "MAXMIND_DB_PATH", "MAXMIND_ASN_DB_PATH", "TOR_EXIT_LIST_PATH"]) {
    delete process.env[k];
  }
  delete process.env.ENRICHMENT_ENABLED;
  vi.restoreAllMocks();
});

describe("enrichIp — schema + fail-open", () => {
  it("returns the §12.1 shape even with no sources configured", async () => {
    const out = await enrichIp("203.0.113.9");
    for (const key of SCHEMA_KEYS) expect(key in out).toBe(true);
    expect(out.geoip).toBe(null);
    expect(out.asn).toBe(null);
    expect(out.vpnDetected).toBe(false);
    expect(out.abuseScore).toBe(null);
    expect(out.previousOffenses).toBe(null);
    expect(typeof out.enrichedAt).toBe("string");
  });

  it("populates reputation from AbuseIPDB and serves the second call from cache", async () => {
    process.env.ABUSEIPDB_KEY = "test-key";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
      if (String(url).includes("abuseipdb")) {
        return {
          ok: true,
          json: async () => ({
            data: { abuseConfidenceScore: 88, totalReports: 12, isTor: false, usageType: "Data Center" },
          }),
        };
      }
      return { ok: false, json: async () => ({}) };
    });

    const first = await enrichIp("198.51.100.7");
    expect(first.abuseScore).toBe(88);
    expect(first.previousOffenses).toBe(12);
    expect(first.cached).toBe(false);
    const callsAfterFirst = fetchMock.mock.calls.length;
    expect(callsAfterFirst).toBeGreaterThan(0);

    const second = await enrichIp("198.51.100.7");
    expect(second.cached).toBe(true);
    expect(second.abuseScore).toBe(88);
    // No new external calls — served from the enrichment cache.
    expect(fetchMock.mock.calls.length).toBe(callsAfterFirst);
  });

  it("fails open when the reputation API errors (no throw, neutral result)", async () => {
    process.env.ABUSEIPDB_KEY = "test-key";
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"));
    const rep = await lookupReputation("198.51.100.8");
    expect(rep.abuseScore).toBe(null);
    expect(rep.vpnDetected).toBe(false);
  });

  it("flags a Tor exit node from the local list with no network call", async () => {
    const file = path.join(os.tmpdir(), `tor-exit-${process.pid}.txt`);
    writeFileSync(file, "# comment line\n185.220.101.1\n198.51.100.9\n");
    process.env.TOR_EXIT_LIST_PATH = file;
    try {
      const rep = await lookupReputation("198.51.100.9");
      expect(rep.torExit).toBe(true);
      expect(rep.vpnDetected).toBe(true);
      expect(rep.sources).toContain("tor-list");
    } finally {
      rmSync(file, { force: true });
    }
  });
});

describe("requestEnrichment — out-of-band alert patching", () => {
  it("patches the stored alert's forensics.enrichment after the response", async () => {
    const stored = await insertAlert({
      userId: "u1",
      category: "LLM01",
      blocked: true,
      forensics: { clientIp: "203.0.113.42", realIp: "127.0.0.1", proxyChain: [], enrichment: null },
      ts: new Date(),
    });
    expect(stored.forensics.enrichment).toBe(null); // not enriched at store time

    requestEnrichment({ alertId: stored.alertId, ip: "203.0.113.42" });

    // Enrichment is async/detached — poll until the patch lands.
    await vi.waitFor(async () => {
      const [alert] = await recentAlerts(1);
      expect(alert.forensics.enrichment).not.toBe(null);
      expect(alert.forensics.enrichment.enrichedAt).toBeTruthy();
    });
  });

  it("is a no-op when enrichment is disabled", async () => {
    process.env.ENRICHMENT_ENABLED = "false";
    const stored = await insertAlert({
      userId: "u2",
      category: "LLM01",
      forensics: { clientIp: "203.0.113.43", enrichment: null },
      ts: new Date(),
    });
    requestEnrichment({ alertId: stored.alertId, ip: "203.0.113.43" });
    await new Promise((r) => setTimeout(r, 30));
    const alert = (await recentAlerts(5)).find((a) => a.alertId === stored.alertId);
    expect(alert.forensics.enrichment).toBe(null);
  });
});
