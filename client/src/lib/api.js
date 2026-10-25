/**
 * Client session + API helper (Tier 2 · EPIC A/B).
 *
 * On first use we bootstrap a signed session token from the proxy (POST
 * /api/session) and cache it in localStorage. Every API call goes through
 * apiFetch, which attaches `Authorization: Bearer <token>` so the server can
 * bind requests to a verifiable session and enforce WebAuthn step-up.
 */
import { resolvePublicIp } from "./publicIp";

const TOKEN_KEY = "dlf.token";
const SID_KEY = "dlf.sessionId";
const TOKEN_USER_KEY = "dlf.tokenUser";

let token = localStorage.getItem(TOKEN_KEY) || null;
let sessionId = localStorage.getItem(SID_KEY) || null;
let tokenUser = localStorage.getItem(TOKEN_USER_KEY) || null;
let bootstrapping = null;

/** Store a signed session token issued by /api/auth/login or /api/session. */
export function setSessionToken(newToken, newSessionId, userId) {
  token = newToken || null;
  sessionId = newSessionId || null;
  tokenUser = userId || null;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
  if (sessionId) localStorage.setItem(SID_KEY, sessionId);
  else localStorage.removeItem(SID_KEY);
  if (tokenUser) localStorage.setItem(TOKEN_USER_KEY, tokenUser);
  else localStorage.removeItem(TOKEN_USER_KEY);
}

/** Clear cached session token on logout. */
export function clearSessionToken() {
  setSessionToken(null, null, null);
}

/** Ensure a session token exists, creating one bound to `userId` if needed. */
export async function ensureSession(userId, forceRefresh = false) {
  if (!forceRefresh && token && (!userId || !tokenUser || tokenUser === userId)) {
    return token;
  }
  if (bootstrapping) return bootstrapping;
  bootstrapping = (async () => {
    try {
      const res = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
      });
      if (res.ok) {
        const data = await res.json();
        setSessionToken(data.token, data.sessionId, data.userId || userId);
      }
      return token;
    } finally {
      bootstrapping = null;
    }
  })();
  return bootstrapping;
}

export function getSessionId() {
  return sessionId;
}

/** fetch() wrapper that guarantees a session token on the Authorization header. */
export async function apiFetch(url, opts = {}, userId) {
  await ensureSession(userId);
  const publicIp = await resolvePublicIp();
  const buildHeaders = () => {
    const h = { ...(opts.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) };
    if (publicIp) h["x-demo-client-ip"] = publicIp;
    return h;
  };
  let res = await fetch(url, { ...opts, headers: buildHeaders() });
  // If the proxy restarted and invalidated an old token (non-step-up 401),
  // re-bootstrap the session once automatically.
  if (res.status === 401) {
    const cloned = res.clone();
    const errBody = await cloned.json().catch(() => ({}));
    if (errBody?.reason !== "step_up_required") {
      await ensureSession(userId, true);
      res = await fetch(url, { ...opts, headers: buildHeaders() });
    }
  }
  return res;
}
