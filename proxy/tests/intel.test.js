/**
 * Tier 3 · Wave 2 · Epic D — STIX export + threat correlation.
 *
 * Covers:
 *   - the STIX 2.1 bundle validates structurally (bundle + typed SDOs, indicators
 *     for observed IPs and attack signatures, indicates-relationships)
 *   - indicator ids are deterministic (a TAXII puller can de-dup across pulls)
 *   - correlation flags a distributed campaign (one signature across many IPs) and
 *     account spraying (one IP across many users)
 */
import { describe, it, expect, beforeEach } from "vitest";
import { insertAlert } from "../db/mongo.js";
import { buildStixBundle } from "../integrations/stix.js";
import { correlateThreats } from "../integrations/correlate.js";

const blocked = (over) => ({
  kind: "ml",
  category: "LLM01",
  categoryTitle: "Prompt Injection",
  label: "prompt injection",
  blocked: true,
  mode: "enforce",
  ts: new Date(),
  ...over,
});

beforeEach(() => {
  process.env.CORRELATE_IP_THRESHOLD = "3";
  process.env.CORRELATE_USER_THRESHOLD = "3";
});

describe("STIX 2.1 export", () => {
  it("builds a valid bundle with IP + signature indicators", async () => {
    await insertAlert(blocked({ forensics: { clientIp: "203.0.113.201" }, signature: "sigAAA111" }));

    const bundle = await buildStixBundle({ limit: 100 });
    expect(bundle.type).toBe("bundle");
    expect(Array.isArray(bundle.objects)).toBe(true);

    const indicators = bundle.objects.filter((o) => o.type === "indicator");
    const ipInd = indicators.find((i) => i.pattern.includes("203.0.113.201"));
    const sigInd = indicators.find((i) => i.pattern.includes("sigAAA111"));
    expect(ipInd).toBeTruthy();
    expect(ipInd.pattern).toBe("[ipv4-addr:value = '203.0.113.201']");
    expect(ipInd.spec_version).toBe("2.1");
    expect(sigInd).toBeTruthy();

    // an attack-pattern SDO + an indicates relationship exist
    expect(bundle.objects.some((o) => o.type === "attack-pattern")).toBe(true);
    expect(
      bundle.objects.some((o) => o.type === "relationship" && o.relationship_type === "indicates")
    ).toBe(true);
  });

  it("gives an indicator a deterministic id across exports", async () => {
    await insertAlert(blocked({ forensics: { clientIp: "203.0.113.202" }, signature: "sigBBB222" }));
    const b1 = await buildStixBundle({ limit: 100 });
    const b2 = await buildStixBundle({ limit: 100 });
    const id1 = b1.objects.find((o) => o.type === "indicator" && o.pattern.includes("203.0.113.202")).id;
    const id2 = b2.objects.find((o) => o.type === "indicator" && o.pattern.includes("203.0.113.202")).id;
    expect(id1).toBe(id2);
    // bundle ids themselves differ (fresh envelope each pull)
    expect(b1.id).not.toBe(b2.id);
  });
});

describe("threat correlation", () => {
  it("flags a distributed campaign: one signature across many IPs", async () => {
    const sig = "campaignSIG_" + Math.floor(performance.now());
    await insertAlert(blocked({ signature: sig, forensics: { clientIp: "198.51.100.31" } }));
    await insertAlert(blocked({ signature: sig, forensics: { clientIp: "198.51.100.32" } }));
    await insertAlert(blocked({ signature: sig, forensics: { clientIp: "198.51.100.33" } }));

    const out = await correlateThreats({ limit: 200 });
    expect(out.coordinated).toBe(true);
    const camp = out.campaigns.find((c) => c.type === "distributed-signature" && c.signature === sig);
    expect(camp).toBeTruthy();
    expect(camp.distinctIps).toBeGreaterThanOrEqual(3);
  });

  it("flags account spraying: one IP across many users", async () => {
    const ip = "198.51.100.99";
    await insertAlert(blocked({ userId: "victimA", forensics: { clientIp: ip } }));
    await insertAlert(blocked({ userId: "victimB", forensics: { clientIp: ip } }));
    await insertAlert(blocked({ userId: "victimC", forensics: { clientIp: ip } }));

    const out = await correlateThreats({ limit: 200 });
    const camp = out.campaigns.find((c) => c.type === "account-spray" && c.ip === ip);
    expect(camp).toBeTruthy();
    expect(camp.distinctUsers).toBeGreaterThanOrEqual(3);
  });
});
