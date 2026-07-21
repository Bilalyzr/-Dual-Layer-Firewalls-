/**
 * Session & identity foundation (Tier 2 · EPIC A).
 *
 * The stack previously keyed everything off a client-generated `userId` with no
 * real, server-verifiable session. FIDO2 step-up (EPIC B) needs an authenticated
 * session to protect, so this module issues a **signed, tamper-evident** session
 * token on first load and stores the session server-side.
 *
 * Token format:  `<sessionId>.<sig>`
 *   sessionId — 128-bit random hex, the server-side lookup key
 *   sig       — base64url( HMAC-SHA256(sessionId, SESSION_SECRET) )
 *
 * The signature makes the token unforgeable without the secret; the server still
 * loads the authoritative session record (trustState, boundUserId) from the
 * `sessions` store, so revocation and step-up state live server-side, not in the
 * token. This is the opaque-token half of the "JWT or opaque + Mongo" choice in
 * the plan — no extra dependency, and it degrades to the in-memory store like
 * every other collection.
 */
import crypto from "crypto";
import {
  createSessionDoc,
  getSessionDoc,
  updateSessionDoc,
} from "../db/mongo.js";

// Read lazily so import ordering vs. dotenv never leaves us with an empty secret
// (mirrors llm/client.js). A missing secret in a non-local deploy is a hard
// error surfaced once at first use.
function secret() {
  const s = process.env.SESSION_SECRET;
  if (s && s.length >= 16) return s;
  // Dev fallback: deterministic but clearly-marked insecure default so the demo
  // works out of the box. Warn once.
  if (!secret._warned) {
    console.warn(
      "[auth] SESSION_SECRET unset/short — using an insecure dev default. " +
        "Set SESSION_SECRET (>=16 chars) before any non-local deploy."
    );
    secret._warned = true;
  }
  return "dev-insecure-session-secret-change-me";
}

const b64url = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** HMAC-sign a sessionId, returning `<sessionId>.<sig>`. */
export function signSession(sessionId) {
  const sig = b64url(crypto.createHmac("sha256", secret()).update(sessionId).digest());
  return `${sessionId}.${sig}`;
}

/**
 * Verify a token's signature (constant-time) and return its sessionId, or null
 * if the token is malformed or the signature doesn't match.
 */
export function verifyToken(token) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const idx = token.lastIndexOf(".");
  const sessionId = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  if (!sessionId || !sig) return null;
  const expected = b64url(
    crypto.createHmac("sha256", secret()).update(sessionId).digest()
  );
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  return crypto.timingSafeEqual(a, b) ? sessionId : null;
}

/**
 * Create a fresh session and persist it. Returns the token + the stored record.
 * @param {{ userId?: string }} [opts]
 */
export async function createSession({ userId } = {}) {
  const sessionId = crypto.randomBytes(16).toString("hex");
  const doc = {
    sessionId,
    userId: userId || `user-${sessionId.slice(0, 8)}`,
    trustState: { stepUpRequired: false, lastVerifiedAt: null, reason: null },
    createdAt: new Date(),
  };
  await createSessionDoc(doc);
  return { token: signSession(sessionId), ...doc };
}

/** Load a session record from a bearer token (verifying its signature first). */
export async function getSessionFromToken(token) {
  const sessionId = verifyToken(token);
  if (!sessionId) return null;
  return await getSessionDoc(sessionId);
}

/** Mark a session as requiring step-up re-auth (EPIC B enforcement hook). */
export async function requireStepUp(sessionId, reason) {
  return await updateSessionDoc(sessionId, {
    trustState: { stepUpRequired: true, lastVerifiedAt: null, reason: reason || "trust_collapse" },
  });
}

/** Clear step-up after a successful WebAuthn assertion. */
export async function clearStepUp(sessionId) {
  return await updateSessionDoc(sessionId, {
    trustState: { stepUpRequired: false, lastVerifiedAt: new Date(), reason: null },
  });
}

/** Persist a pending WebAuthn challenge on the session (register/authenticate). */
export async function setChallenge(sessionId, challenge) {
  return await updateSessionDoc(sessionId, { webauthnChallenge: challenge });
}

/**
 * Pure enforcement decision (EPIC B) — kept separate from I/O so it can be unit
 * tested. Step-up is required only in enforce mode, once the user has a real
 * baseline (not cold-start), when trust has collapsed at/below the threshold.
 *
 * @param {{ mode:string, trustScore:number, threshold:number, coldStart:boolean }} p
 * @returns {boolean}
 */
export function shouldStepUp({ mode, trustScore, threshold, coldStart }) {
  if (String(mode).toLowerCase() !== "enforce") return false;
  if (coldStart) return false;
  if (typeof trustScore !== "number" || !isFinite(trustScore)) return false;
  return trustScore <= threshold;
}

/**
 * Read a token from the request (`Authorization: Bearer …` or `x-session-token`).
 */
export function tokenFromRequest(req) {
  const auth = req.headers?.authorization || "";
  if (auth.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  const hdr = req.headers?.["x-session-token"];
  return typeof hdr === "string" && hdr ? hdr : null;
}

/**
 * Express middleware: if the request carries a valid session token, attach the
 * live session record as `req.session` (and `req.sessionId`). Never rejects —
 * routes decide whether a session is required. Keeps unauthenticated demo flows
 * working while giving authenticated requests a verifiable identity.
 */
export async function sessionMiddleware(req, _res, next) {
  try {
    const token = tokenFromRequest(req);
    if (token) {
      const session = await getSessionFromToken(token);
      if (session) {
        req.session = session;
        req.sessionId = session.sessionId;
      }
    }
  } catch (err) {
    console.warn(`[auth] sessionMiddleware: ${err.message}`);
  }
  next();
}
