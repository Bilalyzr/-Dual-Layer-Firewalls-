/**
 * Tier 3 · Wave 1 · Epic A — IP context resolution + forensics encryption.
 *
 * Covers the acceptance criteria:
 *   - X-Forwarded-For chain parsing through trusted proxies
 *   - a forged XFF from an UNTRUSTED hop is ignored (spoof rejection)
 *   - the forensics IP sub-document is persisted AND encrypted at rest
 */
import { describe, it, expect, beforeEach } from "vitest";
import {
  ipToBytes,
  ipInCidr,
  ipInAnyCidr,
  normalizeIp,
  enclosingNetwork,
  parseCidr,
} from "../lib/cidr.js";
import {
  resolveIpContext,
  forensicsFromReq,
  __resetTrustedCache,
} from "../middleware/ipContext.js";
import {
  encryptFields,
  decryptFields,
  encryptionEnabled,
  SENSITIVE_ALERT_FIELDS,
  __resetKeyCacheForTests,
} from "../db/encryption.js";

function fakeReq({ peer, headers = {} } = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return { socket: { remoteAddress: peer }, headers: lower };
}

beforeEach(() => {
  delete process.env.TRUSTED_PROXIES;
  delete process.env.IP_FORENSICS_ENABLED;
  __resetTrustedCache();
});

describe("cidr utilities", () => {
  it("parses IPv4 and matches host + subnet CIDRs", () => {
    expect([...ipToBytes("192.168.1.5")]).toEqual([192, 168, 1, 5]);
    expect(ipInCidr("192.168.1.5", "192.168.1.0/24")).toBe(true);
    expect(ipInCidr("192.168.2.5", "192.168.1.0/24")).toBe(false);
    expect(ipInCidr("10.1.2.3", "10.1.2.3")).toBe(true); // bare IP = /32
  });

  it("folds IPv4-mapped IPv6 to plain IPv4", () => {
    expect(normalizeIp("::ffff:127.0.0.1")).toBe("127.0.0.1");
    expect(ipInCidr("::ffff:10.0.0.9", "10.0.0.0/8")).toBe(true);
  });

  it("parses and matches IPv6 CIDRs without crossing v4/v6", () => {
    expect(ipInCidr("2001:db8::1", "2001:db8::/32")).toBe(true);
    expect(ipInCidr("2001:db9::1", "2001:db8::/32")).toBe(false);
    expect(ipInCidr("2001:db8::1", "10.0.0.0/8")).toBe(false);
  });

  it("matches against a list and derives enclosing networks", () => {
    expect(ipInAnyCidr("8.8.8.8", "10.0.0.0/8,8.8.8.0/24")).toBe(true);
    expect(enclosingNetwork("203.0.113.77")).toBe("203.0.113.0/24");
    expect(parseCidr("bogus/33")).toBe(null);
    expect(parseCidr("10.0.0.0/8")).toEqual({ bytes: expect.anything(), prefix: 8 });
  });
});

describe("resolveIpContext — trusted proxy chain", () => {
  it("walks XFF through trusted hops to the real client", () => {
    // peer is loopback (trusted by default), 10.0.0.5 is a trusted private hop,
    // 203.0.113.9 is the untrusted origin → the client.
    const ctx = resolveIpContext(
      fakeReq({
        peer: "127.0.0.1",
        headers: { "X-Forwarded-For": "203.0.113.9, 10.0.0.5" },
      })
    );
    expect(ctx.clientIp).toBe("203.0.113.9");
    expect(ctx.realIp).toBe("127.0.0.1");
    expect(ctx.spoofed).toBe(false);
    expect(ctx.proxyChain).toContain("203.0.113.9");
    expect(ctx.proxyChain).toContain("127.0.0.1");
  });

  it("honors an operator-added TRUSTED_PROXIES edge CIDR", () => {
    process.env.TRUSTED_PROXIES = "203.0.113.0/24";
    __resetTrustedCache();
    const ctx = resolveIpContext(
      fakeReq({
        peer: "203.0.113.7", // now trusted
        headers: { "X-Forwarded-For": "198.51.100.23, 203.0.113.9" },
      })
    );
    expect(ctx.clientIp).toBe("198.51.100.23");
  });

  it("uses CF-Connecting-IP / X-Real-IP from a trusted peer", () => {
    const cf = resolveIpContext(
      fakeReq({ peer: "127.0.0.1", headers: { "CF-Connecting-IP": "198.51.100.5" } })
    );
    expect(cf.clientIp).toBe("198.51.100.5");
    const xr = resolveIpContext(
      fakeReq({ peer: "127.0.0.1", headers: { "X-Real-IP": "198.51.100.6" } })
    );
    expect(xr.clientIp).toBe("198.51.100.6");
  });

  it("trusts the internal x-client-ip propagation header from a trusted hop", () => {
    const ctx = resolveIpContext(
      fakeReq({ peer: "10.0.0.2", headers: { "x-client-ip": "198.51.100.99" } })
    );
    expect(ctx.clientIp).toBe("198.51.100.99");
  });
});

describe("resolveIpContext — spoof rejection", () => {
  it("ignores a forged X-Forwarded-For from an UNTRUSTED peer", () => {
    const ctx = resolveIpContext(
      fakeReq({
        peer: "203.0.113.50", // public, not in any trusted range
        headers: { "X-Forwarded-For": "10.0.0.1, 1.1.1.1" }, // attacker-supplied
      })
    );
    expect(ctx.clientIp).toBe("203.0.113.50"); // pinned to the real socket peer
    expect(ctx.spoofed).toBe(true);
    expect(ctx.peerTrusted).toBe(false);
  });

  it("ignores a forged internal x-client-ip from an untrusted peer", () => {
    const ctx = resolveIpContext(
      fakeReq({ peer: "198.51.100.7", headers: { "x-client-ip": "10.0.0.1" } })
    );
    expect(ctx.clientIp).toBe("198.51.100.7");
    expect(ctx.spoofed).toBe(true);
  });
});

describe("forensicsFromReq", () => {
  it("builds a forensics sub-document with an enrichment placeholder", () => {
    const req = fakeReq({ peer: "127.0.0.1", headers: { "X-Forwarded-For": "203.0.113.9" } });
    req.ipContext = resolveIpContext(req);
    const f = forensicsFromReq(req);
    expect(f.clientIp).toBe("203.0.113.9");
    expect(f.enrichment).toBe(null);
    expect(f.spoofedForwardedFor).toBe(false);
  });

  it("returns null when IP_FORENSICS_ENABLED=false", () => {
    process.env.IP_FORENSICS_ENABLED = "false";
    const req = fakeReq({ peer: "127.0.0.1" });
    req.ipContext = resolveIpContext(req);
    expect(forensicsFromReq(req)).toBe(null);
  });
});

describe("forensics encryption at rest", () => {
  beforeEach(() => {
    process.env.APP_ENCRYPTION_KEY = "unit-test-forensics-passphrase";
    __resetKeyCacheForTests();
  });

  it("encrypts nested forensics IP fields and round-trips on read", () => {
    expect(encryptionEnabled()).toBe(true);
    const alert = {
      userId: "u1",
      category: "LLM01",
      forensics: {
        clientIp: "203.0.113.9",
        realIp: "127.0.0.1",
        proxyChain: ["203.0.113.9", "127.0.0.1"],
        enrichment: null,
      },
    };
    const enc = encryptFields(alert, SENSITIVE_ALERT_FIELDS);
    // Stored ciphertext must NOT contain the raw IP, and metadata stays plaintext.
    expect(enc.forensics.clientIp).toMatch(/^enc:v1:/);
    expect(enc.forensics.clientIp).not.toContain("203.0.113.9");
    expect(enc.forensics.proxyChain[0]).toMatch(/^enc:v1:/);
    expect(enc.userId).toBe("u1");
    expect(enc.category).toBe("LLM01");

    const dec = decryptFields(enc, SENSITIVE_ALERT_FIELDS);
    expect(dec.forensics.clientIp).toBe("203.0.113.9");
    expect(dec.forensics.proxyChain).toEqual(["203.0.113.9", "127.0.0.1"]);
  });
});
