/**
 * EPIC I — Consent management (legal prerequisite for biometric enforcement).
 *
 * Tracks per-user opt-in/opt-out for each data category. Biometric capture
 * (keystroke, mouse) MUST NOT run until the user has explicitly consented —
 * this is the gate the PRD §9 calls out as a hard requirement.
 *
 * Consent records are themselves auditable (when/what/version), so we can prove
 * the legal basis for any stored biometric data.
 */

// Category codes mirror the GDPR special-data tiers.
const CATEGORIES = {
  keystroke: "keystroke_dynamics", // Category-3 special data
  mouse: "mouse_dynamics",
  touch: "touch_dynamics", // touchscreen force/area/swipe — gated
  fingerprint: "client_fingerprint", // canvas/WebGL — gated
  security_logs: "security_logging",
};

// In-process store; would persist to Mongo `consents` collection in production.
const _store = new Map(); // userId -> { category -> {granted, ts, version} }

const CONSENT_VERSION = "1.0";

export function getConsent(userId) {
  return _store.get(userId) || {};
}

export function hasConsent(userId, category) {
  const c = _store.get(userId);
  return Boolean(c && c[category] && c[category].granted);
}

export function setConsent(userId, category, granted) {
  const cur = _store.get(userId) || {};
  cur[category] = { granted: Boolean(granted), ts: new Date(), version: CONSENT_VERSION };
  _store.set(userId, cur);
  return cur[category];
}

/** Middleware: block biometric endpoints unless the user has consented. */
export function requireConsent(category) {
  return (req, res, next) => {
    const userId = req.body?.userId || req.session?.userId || "anon";
    if (process.env.CONSENT_ENFORCEMENT === "off") return next();
    if (!hasConsent(userId, category)) {
      return res.status(403).json({
        error: "consent_required",
        category,
        message: `Biometric capture (${category}) requires explicit user consent.`,
      });
    }
    next();
  };
}

export { CATEGORIES, CONSENT_VERSION };
