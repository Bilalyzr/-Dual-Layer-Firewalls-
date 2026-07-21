/**
 * /api/auth/webauthn — FIDO2 / WebAuthn step-up MFA (Tier 2 · EPIC B).
 *
 * Turns Layer 2 from shadow into enforce: when keystroke trust collapses, the
 * session is marked `stepUpRequired` (see routes/biometric.js) and /api/chat is
 * gated until the user completes a hardware/passkey assertion here.
 *
 * Flow (all endpoints require a valid session from EPIC A):
 *   register/options   → generateRegistrationOptions, stash challenge on session
 *   register/verify    → verifyRegistrationResponse, persist the credential
 *   authenticate/options → generateAuthenticationOptions for the user's passkeys
 *   authenticate/verify  → verifyAuthenticationResponse; on success clear step-up
 *
 * Challenges are stored server-side on the session record (never trusted from
 * the client). Public keys are stored base64url-encoded.
 */
import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  insertCredential,
  getCredentialsByUser,
  getCredentialById,
  updateCredentialCounter,
} from "../db/mongo.js";
import { setChallenge, clearStepUp } from "../auth/session.js";
import { publish } from "../middleware/eventBus.js";

const router = Router();

const rpID = () => process.env.WEBAUTHN_RP_ID || "localhost";
const rpName = () => process.env.WEBAUTHN_RP_NAME || "Dual-Layer AI Firewall";
const origin = () => process.env.WEBAUTHN_ORIGIN || "http://localhost:5174";

const toB64url = (u8) => Buffer.from(u8).toString("base64url");
const fromB64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));

/** Guard: every WebAuthn endpoint needs an authenticated session. */
function requireSession(req, res) {
  if (!req.session) {
    res.status(401).json({ error: "no_session", reason: "bootstrap a session via POST /api/session first" });
    return null;
  }
  return req.session;
}

// ---- Registration -------------------------------------------------------- //
router.post("/webauthn/register/options", async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const existing = await getCredentialsByUser(session.userId);
  const options = await generateRegistrationOptions({
    rpName: rpName(),
    rpID: rpID(),
    userName: session.userId,
    userID: new TextEncoder().encode(session.userId),
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.credentialID, transports: c.transports })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
  await setChallenge(session.sessionId, options.challenge);
  res.json(options);
});

router.post("/webauthn/register/verify", async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const expectedChallenge = session.webauthnChallenge;
  if (!expectedChallenge) return res.status(400).json({ error: "no_pending_challenge" });
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body?.response || req.body,
      expectedChallenge,
      expectedOrigin: origin(),
      expectedRPID: rpID(),
    });
  } catch (err) {
    return res.status(400).json({ verified: false, error: String(err.message || err) });
  }
  await setChallenge(session.sessionId, null);
  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ verified: false });
  }
  const { credential } = verification.registrationInfo;
  await insertCredential({
    userId: session.userId,
    credentialID: credential.id,
    publicKey: toB64url(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports || [],
  });
  publish("stepup", { userId: session.userId, sessionId: session.sessionId, event: "credential_registered", ts: new Date() });
  res.json({ verified: true, credentialID: credential.id });
});

// ---- Authentication (step-up assertion) ---------------------------------- //
router.post("/webauthn/authenticate/options", async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const creds = await getCredentialsByUser(session.userId);
  if (creds.length === 0) {
    return res.status(409).json({ error: "no_credentials", reason: "register a passkey first" });
  }
  const options = await generateAuthenticationOptions({
    rpID: rpID(),
    allowCredentials: creds.map((c) => ({ id: c.credentialID, transports: c.transports })),
    userVerification: "preferred",
  });
  await setChallenge(session.sessionId, options.challenge);
  res.json(options);
});

router.post("/webauthn/authenticate/verify", async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const expectedChallenge = session.webauthnChallenge;
  if (!expectedChallenge) return res.status(400).json({ error: "no_pending_challenge" });
  const response = req.body?.response || req.body;
  const cred = await getCredentialById(response?.id);
  if (!cred || cred.userId !== session.userId) {
    return res.status(404).json({ verified: false, error: "unknown_credential" });
  }
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin(),
      expectedRPID: rpID(),
      credential: {
        id: cred.credentialID,
        publicKey: fromB64url(cred.publicKey),
        counter: cred.counter,
        transports: cred.transports,
      },
    });
  } catch (err) {
    return res.status(400).json({ verified: false, error: String(err.message || err) });
  }
  await setChallenge(session.sessionId, null);
  if (!verification.verified) {
    publish("stepup", { userId: session.userId, sessionId: session.sessionId, event: "assertion_failed", ts: new Date() });
    return res.status(401).json({ verified: false });
  }
  await updateCredentialCounter(cred.credentialID, verification.authenticationInfo.newCounter);
  const updated = await clearStepUp(session.sessionId);
  publish("stepup", { userId: session.userId, sessionId: session.sessionId, event: "assertion_verified", ts: new Date() });
  res.json({ verified: true, trustState: updated?.trustState });
});

export default router;
