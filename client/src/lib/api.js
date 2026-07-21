/**
 * Client session + API helper (Tier 2 · EPIC A/B).
 *
 * On first use we bootstrap a signed session token from the proxy (POST
 * /api/session) and cache it in localStorage. Every API call goes through
 * apiFetch, which attaches `Authorization: Bearer <token>` so the server can
 * bind requests to a verifiable session and enforce WebAuthn step-up.
 */
const TOKEN_KEY = "dlf.token";
const SID_KEY = "dlf.sessionId";

let token = localStorage.getItem(TOKEN_KEY) || null;
let sessionId = localStorage.getItem(SID_KEY) || null;
let bootstrapping = null;

/** Ensure a session token exists, creating one bound to `userId` if needed. */
export async function ensureSession(userId) {
  if (token) return token;
  if (bootstrapping) return bootstrapping;
  bootstrapping = (async () => {
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId }),
    });
    const data = await res.json();
    token = data.token;
    sessionId = data.sessionId;
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(SID_KEY, sessionId);
    bootstrapping = null;
    return token;
  })();
  return bootstrapping;
}

export function getSessionId() {
  return sessionId;
}

/** fetch() wrapper that guarantees a session token on the Authorization header. */
export async function apiFetch(url, opts = {}, userId) {
  await ensureSession(userId);
  const headers = { ...(opts.headers || {}), Authorization: `Bearer ${token}` };
  return fetch(url, { ...opts, headers });
}
