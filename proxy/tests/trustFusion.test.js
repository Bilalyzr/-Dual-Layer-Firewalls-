/**
 * Trust fusion unit tests (Epic G) — the pure fuseTrust() function.
 *
 * Critical invariant: with no usable auxiliary channel, fusion is a no-op and
 * fusedTrust === keystrokeTrust (this is what keeps the existing step-up/enforce
 * behavior byte-identical).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { fuseTrust } from "../firewall/trustFusion.js";

describe("fuseTrust — no-op invariants", () => {
  beforeEach(() => { delete process.env.BIOMETRIC_FUSION; });

  it("returns keystroke trust unchanged when no aux channels", () => {
    const r = fuseTrust({ keystrokeTrust: 20, keystrokeColdStart: false });
    expect(r.fusedTrust).toBe(20);
    expect(r.fused).toBe(false);
  });

  it("ignores cold-start aux channels", () => {
    const r = fuseTrust({
      keystrokeTrust: 80,
      mouse: { score: 0.1, coldStart: true },
    });
    expect(r.fusedTrust).toBe(80);
    expect(r.fused).toBe(false);
  });

  it("ignores stale aux samples", () => {
    const r = fuseTrust({
      keystrokeTrust: 80,
      mouse: { score: 0.1, coldStart: false, ageMs: 120_000 },
      freshnessMs: 60_000,
    });
    expect(r.fusedTrust).toBe(80);
    expect(r.fused).toBe(false);
  });

  it("reverts to keystroke-only when BIOMETRIC_FUSION=off", () => {
    process.env.BIOMETRIC_FUSION = "off";
    const r = fuseTrust({ keystrokeTrust: 90, mouse: { score: 0.0, coldStart: false } });
    expect(r.fusedTrust).toBe(90);
    expect(r.fused).toBe(false);
  });
});

describe("fuseTrust — multi-channel blending", () => {
  beforeEach(() => { delete process.env.BIOMETRIC_FUSION; });

  it("a corroborating channel raises trust", () => {
    const r = fuseTrust({ keystrokeTrust: 60, mouse: { score: 1.0, coldStart: false } });
    expect(r.fused).toBe(true);
    expect(r.fusedTrust).toBeGreaterThan(60);
    expect(r.channels.mouse).toBe(100);
  });

  it("a disagreeing channel lowers trust", () => {
    const r = fuseTrust({ keystrokeTrust: 80, mouse: { score: 0.0, coldStart: false } });
    expect(r.fused).toBe(true);
    expect(r.fusedTrust).toBeLessThan(80);
  });

  it("blends keystroke + mouse + touch with normalized weights", () => {
    const r = fuseTrust({
      keystrokeTrust: 100,
      mouse: { score: 0.5, coldStart: false },
      touch: { score: 0.0, coldStart: false },
    });
    expect(r.fused).toBe(true);
    // weights renormalize to sum 1 across all three present channels.
    const sum = r.weights.keystroke + r.weights.mouse + r.weights.touch;
    expect(sum).toBeCloseTo(1, 2);
    expect(r.fusedTrust).toBeLessThan(100);
    expect(r.fusedTrust).toBeGreaterThan(0);
  });
});
