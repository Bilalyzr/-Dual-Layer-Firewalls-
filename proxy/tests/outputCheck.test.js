/**
 * Outbound integrity check tests (Req 1.4).
 *
 * Verifies the proxy detects leaked secrets/credentials and unauthorized
 * tool-calling parameters in LLM responses, and passes clean output.
 */
import { describe, it, expect } from "vitest";
import { checkOutput } from "../firewall/outputCheck.js";

describe("checkOutput", () => {
  it("passes clean output through", () => {
    const r = checkOutput("The capital of France is Paris.");
    expect(r.blocked).toBe(false);
    expect(r.reasons).toHaveLength(0);
  });

  it("handles empty / non-string input", () => {
    expect(checkOutput("").blocked).toBe(false);
    expect(checkOutput(null).blocked).toBe(false);
  });

  it.each([
    ["my key is sk-abcdefghijklmnopqrstuvwxyz1234567890", "OpenAI-style API key"],
    ["AWS key: AKIAIOSFODNN7EXAMPLE", "AWS access key id"],
    ["token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", "GitHub token"],
    ["-----BEGIN RSA PRIVATE KEY-----", "Private key block"],
    ["mongodb://user:secretpass@host/db", "Connection string"],
  ])("blocks leaked secret: %s", (text, label) => {
    const r = checkOutput(text);
    expect(r.blocked).toBe(true);
    expect(r.reasons.some((x) => x.toLowerCase().includes(label.toLowerCase().split(" ")[0]))).toBe(true);
  });

  it("blocks unauthorized function-call envelopes", () => {
    const r = checkOutput('{"function":"exec","args":["rm -rf /"]}');
    expect(r.blocked).toBe(true);
  });

  it("blocks unauthorized agent action envelopes", () => {
    const r = checkOutput('{"action":"delete_file","path":"/etc/passwd"}');
    expect(r.blocked).toBe(true);
  });

  it("includes snippets of the offending content", () => {
    const r = checkOutput("here is the key sk-abcdefghijklmnopqrstuvwxyz1234567890 ok");
    expect(r.blocked).toBe(true);
    expect(r.snippets.length).toBeGreaterThan(0);
    expect(typeof r.snippets[0]).toBe("string");
  });
});
