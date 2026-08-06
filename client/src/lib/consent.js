/**
 * EPIC I — client consent helper.
 *
 * The privacy gate that must precede mouse/touch/fingerprint capture. Grants are
 * the source of truth on the server (`/api/consent`), but we mirror them in
 * localStorage so the UI can gate capture synchronously on first paint without
 * waiting for a round-trip (and re-sync in the background).
 *
 * Behavioral categories default to OFF — nothing captures until the user opts in.
 */
const LS_KEY = "dlf.consent";

/** Categories the dashboard lets the user toggle, with human labels. */
export const CONSENT_CATEGORIES = [
  { key: "mouse", label: "Mouse dynamics", desc: "Movement cadence, speed & curvature — behavioral biometric." },
  { key: "touch", label: "Touch dynamics", desc: "Pressure, contact area & swipe velocity on touch devices." },
  { key: "fingerprint", label: "Device fingerprint", desc: "Hashed canvas / WebGL / audio signature (GDPR personal data)." },
];

function readCache() {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) || "{}") || {};
  } catch {
    return {};
  }
}

function writeCache(map) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(map));
  } catch {
    /* storage disabled — server remains source of truth */
  }
}

/** Synchronous read from the local mirror (safe for render-time gating). */
export function hasConsent(category) {
  return Boolean(readCache()[category]);
}

/** Fetch authoritative grants from the server and refresh the local mirror. */
export async function loadConsent(userId) {
  try {
    const r = await fetch(`/api/consent/${encodeURIComponent(userId)}`);
    if (!r.ok) return readCache();
    const data = await r.json();
    const granted = data?.granted || {};
    writeCache(granted);
    return granted;
  } catch {
    return readCache();
  }
}

/** Set a single category and persist both server-side and in the mirror. */
export async function setConsent(userId, category, granted) {
  const map = readCache();
  map[category] = Boolean(granted);
  writeCache(map); // optimistic — reflect immediately
  try {
    await fetch("/api/consent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId, category, granted: Boolean(granted) }),
    });
  } catch {
    /* keep optimistic value; will re-sync via loadConsent */
  }
  return map;
}

/** Has the user made any explicit choice yet? Drives the first-run banner. */
export function hasDecided() {
  return localStorage.getItem(LS_KEY) !== null;
}
