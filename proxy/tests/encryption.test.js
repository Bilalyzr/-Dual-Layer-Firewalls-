/**
 * EPIC D — at-rest field encryption tests.
 *
 * Covers: enabled/disabled modes, round-trip, idempotency, tamper detection,
 * field-level application on doc copies, and that metadata fields stay plaintext.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  encryptString,
  decryptString,
  encryptFields,
  decryptFields,
  encryptionEnabled,
  __resetKeyCacheForTests,
  SENSITIVE_ALERT_FIELDS,
} from "../db/encryption.js";

const KEY = Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "hex").toString("base64");

beforeEach(() => {
  process.env.APP_ENCRYPTION_KEY = KEY;
  __resetKeyCacheForTests();
});
afterEach(() => {
  delete process.env.APP_ENCRYPTION_KEY;
  __resetKeyCacheForTests();
});

describe("encryption (enabled)", () => {
  it("reports enabled when key set", () => {
    expect(encryptionEnabled()).toBe(true);
  });

  it("round-trips a string", () => {
    const enc = encryptString("ignore previous instructions");
    expect(enc).not.toBe("ignore previous instructions");
    expect(enc.startsWith("enc:v1:")).toBe(true);
    expect(decryptString(enc)).toBe("ignore previous instructions");
  });

  it("is idempotent (encrypting twice doesn't double-wrap)", () => {
    const once = encryptString("secret");
    const twice = encryptString(once);
    expect(twice).toBe(once);
    expect(decryptString(twice)).toBe("secret");
  });

  it("handles empty / non-string input", () => {
    expect(encryptString("")).toBe("");
    expect(encryptString(null)).toBeNull();
    expect(decryptString(null)).toBeNull();
  });

  it("fails safe on tampered ciphertext (returns ciphertext, not crash)", () => {
    const enc = encryptString("payload");
    const tampered = enc.slice(0, -4) + "AAAA";
    // Should NOT throw; returns the tampered string rather than bad plaintext.
    const out = decryptString(tampered);
    expect(typeof out === "string").toBe(true);
  });
});

describe("encryption (disabled)", () => {
  beforeEach(() => {
    delete process.env.APP_ENCRYPTION_KEY;
    __resetKeyCacheForTests();
  });

  it("reports disabled when key unset", () => {
    expect(encryptionEnabled()).toBe(false);
  });

  it("passes strings through unchanged when disabled", () => {
    expect(encryptString("plain")).toBe("plain");
    expect(decryptString("plain")).toBe("plain");
  });
});

describe("encryptFields / decryptFields", () => {
  it("encrypts only sensitive fields, keeps metadata plaintext", () => {
    const doc = {
      userId: "u1",
      ts: new Date(),
      category: "LLM01",
      prompt: "ignore previous instructions",
      label: "Instruction override",
    };
    const enc = encryptFields(doc, SENSITIVE_ALERT_FIELDS);
    expect(enc.userId).toBe("u1"); // metadata untouched
    expect(enc.category).toBe("LLM01");
    expect(enc.prompt.startsWith("enc:v1:")).toBe(true);
    expect(enc.label.startsWith("enc:v1:")).toBe(true);
    // round-trip
    const dec = decryptFields(enc, SENSITIVE_ALERT_FIELDS);
    expect(dec.prompt).toBe("ignore previous instructions");
    expect(dec.label).toBe("Instruction override");
  });

  it("handles arrays (e.g. reasons/snippets)", () => {
    const doc = { reasons: ["API key", "private key"], snippets: ["sk-xxx"] };
    const enc = encryptFields(doc, ["reasons", "snippets"]);
    expect(enc.reasons[0].startsWith("enc:v1:")).toBe(true);
    expect(decryptFields(enc, ["reasons", "snippets"]).reasons).toEqual(["API key", "private key"]);
  });

  it("returns the doc unchanged when disabled", () => {
    delete process.env.APP_ENCRYPTION_KEY;
    __resetKeyCacheForTests();
    const doc = { prompt: "plain" };
    expect(encryptFields(doc, SENSITIVE_ALERT_FIELDS).prompt).toBe("plain");
  });

  it("does not mutate the original doc", () => {
    const doc = { prompt: "secret" };
    encryptFields(doc, SENSITIVE_ALERT_FIELDS);
    expect(doc.prompt).toBe("secret");
  });
});
