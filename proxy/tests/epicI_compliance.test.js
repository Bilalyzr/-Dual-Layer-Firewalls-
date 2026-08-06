/**
 * EPIC I + K tests — compliance (consent, audit chain) + agent security
 * (kill switch, capability attestation, consensus).
 */
import { describe, it, expect, beforeEach } from "vitest";
import { hasConsent, setConsent, requireConsent } from "../compliance/consent.js";
import { appendAudit, verifyChain, auditChain, _resetChain } from "../compliance/auditChain.js";
import { engage, disengage, killSwitchEngaged, assertAgentsAllowed } from "../agents/killSwitch.js";
import { issueCapability, verifyCapability, authorize } from "../agents/attestation.js";
import { consensus, isHighRisk } from "../agents/consensus.js";

beforeEach(() => {
  _resetChain();
  if (killSwitchEngaged()) disengage("test");
});

// ---- EPIC I: consent -----------------------------------------------------
describe("EPIC I — consent management", () => {
  it("defaults to no consent", () => {
    expect(hasConsent("u", "keystroke")).toBe(false);
  });
  it("records opt-in", () => {
    setConsent("u", "keystroke", true);
    expect(hasConsent("u", "keystroke")).toBe(true);
  });
  it("requireConsent blocks without consent", () => {
    const mw = requireConsent("keystroke");
    const req = { body: { userId: "noconsent" } };
    const res = { status: (c) => ({ json: (d) => ({ status: c, body: d }) }) };
    const r = mw(req, res, () => "next");
    expect(r.status).toBe(403);
  });
});

// ---- EPIC I: tamper-evident audit chain ----------------------------------
describe("EPIC I — hash-chained audit log", () => {
  it("appends and chains entries", () => {
    const e1 = appendAudit("block", { prompt: "x" });
    const e2 = appendAudit("stepup", { user: "u" });
    expect(e1.index).toBe(0);
    expect(e2.prev).toBe(e1.hash);
    expect(e2.hash).not.toBe(e1.hash);
  });
  it("verifies an intact chain", () => {
    appendAudit("a", {});
    appendAudit("b", {});
    expect(verifyChain().valid).toBe(true);
  });
  it("detects tampering", () => {
    appendAudit("a", { x: 1 });
    appendAudit("b", { y: 2 });
    // tamper: mutate the first entry's payload
    const chain = auditChain(100);
    const first = chain[chain.length - 1]; // oldest
    first.payload.tampered = true;
    expect(verifyChain().valid).toBe(false);
  });
});

// ---- EPIC K: kill switch -------------------------------------------------
describe("EPIC K — agent kill switch", () => {
  it("engages and blocks agents", () => {
    expect(killSwitchEngaged()).toBe(false);
    engage("test");
    expect(killSwitchEngaged()).toBe(true);
    expect(() => assertAgentsAllowed()).toThrow(/kill_switch/);
  });
  it("disengages and allows agents", () => {
    engage();
    disengage("test");
    expect(killSwitchEngaged()).toBe(false);
    expect(() => assertAgentsAllowed()).not.toThrow();
  });
});

// ---- EPIC K: capability attestation --------------------------------------
describe("EPIC K — capability attestation", () => {
  it("issues and verifies a valid capability", () => {
    const cap = issueCapability("actor");
    const v = verifyCapability(cap);
    expect(v.valid).toBe(true);
    expect(v.role).toBe("actor");
    expect(v.tools).toContain("notify");
  });
  it("rejects a forged capability (bad signature)", () => {
    const cap = issueCapability("actor");
    cap.tools.push("exec"); // tamper
    const v = verifyCapability(cap);
    expect(v.valid).toBe(false);
  });
  it("authorizes only permitted tools", () => {
    const cap = issueCapability("actor");
    expect(authorize(cap, "notify").allowed).toBe(true);
    expect(authorize(cap, "exec").allowed).toBe(false);
  });
  it("readers get an empty tool capability", () => {
    const cap = issueCapability("reader");
    expect(cap.tools).toEqual([]);
    expect(authorize(cap, "lookup").allowed).toBe(false);
  });
});

// ---- EPIC K: consensus ---------------------------------------------------
describe("EPIC K — multi-agent consensus", () => {
  it("approves when quorum met", async () => {
    const r = await consensus(async () => true, { required: 2, evaluators: 3 });
    expect(r.approved).toBe(true);
  });
  it("rejects when quorum not met", async () => {
    const r = await consensus(async (i) => i === 0, { required: 2, evaluators: 3 });
    expect(r.approved).toBe(false);
  });
  it("flags high-risk tools", () => {
    expect(isHighRisk("delete")).toBe(true);
    expect(isHighRisk("notify")).toBe(false);
  });
});
