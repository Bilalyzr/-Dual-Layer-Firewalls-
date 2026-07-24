/**
 * Gateway reverse-proxy helper (Tier 2 · EPIC G).
 *
 * Forwards a JSON API request to an upstream service and relays the response.
 * Deliberately dependency-free (global fetch) — the gateway only fronts JSON
 * endpoints. The single streaming endpoint (/api/events, SSE) is served directly
 * by the gateway off the shared Redis event bus, so it never needs proxying.
 *
 * Identity + tracing headers (session token, request id) are passed through so
 * each downstream service verifies the same session and shares one trace id.
 */
import { log } from "./logger.js";

const PASS_THROUGH = ["authorization", "x-session-token", "content-type", "x-request-id"];

// Internal header carrying the client IP the gateway already resolved against
// TRUSTED_PROXIES (Epic A). Downstream services trust it because the gateway is
// (by deployment) a trusted proxy in their own allow-list, so they don't re-walk
// the forwarding chain per hop.
const CLIENT_IP_HEADER = "x-client-ip";

/**
 * @param {string} targetBase  e.g. "http://firewall-svc:4000"
 */
export function proxyTo(targetBase) {
  const base = String(targetBase || "").replace(/\/$/, "");
  return async (req, res) => {
    const target = base + (req.originalUrl || req.url);
    try {
      const headers = {};
      for (const h of PASS_THROUGH) if (req.headers[h]) headers[h] = req.headers[h];
      // Forward the resolved client IP so the downstream service records the true
      // origin instead of the gateway's own address.
      const clientIp = req.ipContext?.clientIp;
      if (clientIp) headers[CLIENT_IP_HEADER] = clientIp;
      const hasBody = !["GET", "HEAD"].includes(req.method);
      const body = hasBody ? JSON.stringify(req.body ?? {}) : undefined;
      if (hasBody && !headers["content-type"]) headers["content-type"] = "application/json";

      const upstream = await fetch(target, { method: req.method, headers, body });

      // Relay a downstream-issued session token + the shared request id.
      const tok = upstream.headers.get("x-session-token");
      if (tok) res.setHeader("x-session-token", tok);
      const rid = upstream.headers.get("x-request-id");
      if (rid) res.setHeader("x-request-id", rid);

      res.status(upstream.status);
      res.setHeader("content-type", upstream.headers.get("content-type") || "application/json");
      res.send(await upstream.text());
    } catch (err) {
      log.error("gateway upstream unreachable", { target, error: String(err.message || err) });
      res.status(502).json({
        error: "upstream_unavailable",
        target: base,
        detail: String(err.message || err),
      });
    }
  };
}
