/**
 * EPIC K — Cryptographic capability attestation.
 *
 * Each agent role carries a SIGNED capability set (which tools it may call +
 * expiry). The Actor verifies the capability's signature before executing any
 * tool — so a prompt-injection can't escalate the Actor's permissions by simply
 * asking for more tools. The capability is issued at session boot and signed
 * with the session secret.
 *
 * This is the crypto analog of RBAC: RBAC says "actor can call notify";
 * attestation PROVES the capability wasn't forged, because it's signed.
 */
import crypto from "node:crypto";
import { ROLE_TOOLS } from "./rbac.js";

function _secret() {
  return process.env.SESSION_SECRET || "dev-insecure-attestation-secret";
}

function _sign(obj) {
  const material = JSON.stringify(obj);
  return crypto.createHmac("sha256", _secret()).update(material).digest("hex");
}

/**
 * Issue a signed capability for a role. Includes the permitted tools + expiry.
 */
export function issueCapability(role, ttlSeconds = 3600) {
  const tools = [...(ROLE_TOOLS[role] || [])]; // copy — callers must not mutate the shared RBAC table
  const payload = {
    role,
    tools,
    issuedAt: Date.now(),
    expiresAt: Date.now() + ttlSeconds * 1000,
  };
  const sig = _sign(payload);
  return { ...payload, sig };
}

/**
 * Verify a capability. Returns { valid, role, tools } or { valid: false, reason }.
 * Checks: signature matches, not expired, role is known.
 */
export function verifyCapability(cap) {
  if (!cap || !cap.sig) return { valid: false, reason: "missing signature" };
  const { sig, ...rest } = cap;
  const expected = _sign(rest);
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return { valid: false, reason: "bad signature" };
  }
  if (Date.now() > cap.expiresAt) {
    return { valid: false, reason: "expired" };
  }
  if (!ROLE_TOOLS[cap.role]) {
    return { valid: false, reason: "unknown role" };
  }
  return { valid: true, role: cap.role, tools: cap.tools };
}

/**
 * Authorize a specific tool call against a verified capability.
 * injection can't call a tool the capability didn't list, even if it forges a
 * request envelope.
 */
export function authorize(cap, tool) {
  const v = verifyCapability(cap);
  if (!v.valid) return { allowed: false, reason: v.reason };
  if (!v.tools.includes(tool)) return { allowed: false, reason: "tool not in capability" };
  return { allowed: true, role: v.role, tool };
}
