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
// Provider chain: any single echo service can be blocked or down on a given
// network, so we try each in order until one answers. First two return JSON,
// the rest return plain text.
const PROVIDERS = [
  (import.meta.env.VITE_PUBLIC_IP_URL ? [import.meta.env.VITE_PUBLIC_IP_URL, "json"] : null),
  ["https://api.ipify.org?format=json", "json"],
  ["https://ipapi.co/json/", "json"],
  ["https://ifconfig.me/ip", "text"],
  ["https://icanhazip.com", "text"],
].filter(Boolean);
const TIMEOUT_MS = 5000;

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

  const attempt = (async () => {
    for (const [url, kind] of PROVIDERS) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
      try {
        const res = await fetch(url, { cache: "no-store", signal: ctrl.signal });
        if (!res.ok) continue;
        const body = kind === "json" ? await res.json() : (await res.text()).trim();
        const ip = (body && (body.ip || body.address)) || (/^\d{1,3}(\.\d{1,3}){3}$/.test(body) ? body : null);
        if (ip) {
          cached = ip;
          try {
            sessionStorage.setItem(KEY, ip);
          } catch {
            /* ignore */
          }
          return cached;
        }
      } catch {
        // provider blocked/down — next in the chain
      } finally {
        clearTimeout(timer);
      }
    }
    return null; // every provider failed — feed falls back to loopback
  })();
  // Allow a later retry when the whole chain failed (cache still empty).
  attempt.finally(() => { if (!cached) inflight = null; });
  inflight = attempt;
  return inflight;
}
