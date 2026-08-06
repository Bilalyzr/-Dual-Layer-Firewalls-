/**
 * Best-effort public-IP discovery for the LOCAL-DEV demo (pairs with the proxy's
 * DEMO_PUBLIC_IP flag — see proxy/middleware/ipContext.js).
 *
 * Why this exists: in local dev the whole browser → Vite → backend chain runs
 * over loopback, so the backend can only ever see 127.0.0.1 as the "client" and
 * the Real-Time Threat Feed has no real address to show. To fix that, the browser
 * asks a public echo service for its own egress IP once and hands it to the proxy
 * as `x-demo-client-ip`. The proxy honors that header ONLY from a loopback peer
 * and ONLY when DEMO_PUBLIC_IP=true, so it is completely inert in production.
 *
 * Fail-soft in every path: any error → no IP → the feed simply falls back to the
 * loopback address. Result is cached in sessionStorage so we hit the echo service
 * at most once per tab.
 */
const KEY = "dlf.publicIp";
const ECHO_URL = import.meta.env.VITE_PUBLIC_IP_URL || "https://api.ipify.org?format=json";
const TIMEOUT_MS = 3000;

let cached = null;
let inflight = null;

/** Synchronous read of an already-resolved IP (module memo → sessionStorage). */
export function cachedPublicIp() {
  if (cached) return cached;
  try {
    cached = sessionStorage.getItem(KEY) || null;
  } catch {
    /* storage blocked (private mode) — just skip the cache */
  }
  return cached;
}

/** Resolve the public IP once (cached). Never throws; resolves to null on failure. */
export async function resolvePublicIp() {
  const stored = cachedPublicIp();
  if (stored) return stored;
  if (inflight) return inflight;

  inflight = (async () => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(ECHO_URL, { cache: "no-store", signal: ctrl.signal });
      const data = await res.json();
      const ip = (data && (data.ip || data.address)) || null;
      if (ip) {
        cached = ip;
        try {
          sessionStorage.setItem(KEY, ip);
        } catch {
          /* ignore */
        }
      }
      return cached;
    } catch {
      return null; // offline / blocked / timed out — feed falls back to loopback
    } finally {
      clearTimeout(timer);
      inflight = null;
    }
  })();
  return inflight;
}
