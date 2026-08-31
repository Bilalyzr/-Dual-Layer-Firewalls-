/**
 * EPIC E — /api/biometric/fingerprint endpoint.
 *
 * Receives the hashed client fingerprint (canvas/WebGL/audio). Server-side
 * consent-gated: refuses if the user hasn't consented to the "fingerprint"
 * category (Epic I). Stores per-user so the trust model can detect device
 * changes (a sudden fingerprint switch ⇒ possible session takeover).
 */
import { Router } from "express";
import { hasConsent } from "../compliance/consent.js";
import { appendAudit } from "../compliance/auditChain.js";

const router = Router();
const _fingerprints = new Map(); // userId -> { combined, prev, ts }

router.post("/", async (req, res) => {
  const userId = req.body?.userId || "anon";
  // Server-side consent gate (defense in depth — the client checks too).
  if (process.env.CONSENT_ENFORCEMENT !== "off" && !hasConsent(userId, "fingerprint")) {
    return res.status(403).json({ error: "consent_required", category: "fingerprint" });
  }
  const fp = {
    canvas: req.body?.canvas,
    webgl: req.body?.webgl,
    audio: req.body?.audio,
    combined: req.body?.combined,
    screen: req.body?.screen,
  };
  if (!fp.combined) {
    return res.status(400).json({ error: "missing 'combined' fingerprint" });
  }

  // Detect device change — a different fingerprint for a known user.
  const prev = _fingerprints.get(userId);
  const changed = prev && prev.combined !== fp.combined;
  _fingerprints.set(userId, { ...fp, prev: prev?.combined, ts: new Date() });
  appendAudit("fingerprint", { userId, changed, ts: new Date() });

  res.json({
    userId,
    stored: true,
    changed: Boolean(changed),
    message: changed ? "device fingerprint changed — session may need re-verification" : "fingerprint recorded",
  });
});

router.get("/:userId", (req, res) => {
  const fp = _fingerprints.get(req.params.userId);
  res.json(fp || { stored: false });
});

/** Real device-trust state for behavioral context (trial-update: real-time).
 * known  — we have a stored fingerprint for this user
 * changed — the fingerprint CHANGED since the previous request (real signal,
 *           not a hardcoded hostile context) */
export function getFingerprintState(userId) {
  const fp = _fingerprints.get(userId);
  return {
    known: Boolean(fp?.combined),
    changed: Boolean(fp?.prev && fp.prev !== fp.combined),
  };
}

export default router;
