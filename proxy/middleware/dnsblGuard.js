/**
 * Tier 3 · Wave 2 · Epic E — DNSBL edge guard.
 *
 * Checks the client IP against DNS blocklists (forensics/dnsbl.js) at the edge. The
 * lookup is DETACHED (fire-and-forget) so it never adds request latency: the first
 * request from an IP passes through while the async check populates the cache; a
 * listed result records an offense (Epic C), which bans the IP on repeat visits when
 * RESPONSE_MODE is on. Off by default (DNSBL_ENABLED=false); private IPs skipped.
 */
import { checkDnsbl, dnsblEnabled } from "../forensics/dnsbl.js";
import { recordOffense } from "../response/banStore.js";
import { publish } from "./eventBus.js";
import { normalizeIp } from "../lib/cidr.js";
import { log } from "../lib/logger.js";

const EXEMPT = new Set(["/", "/healthz", "/metrics"]);

export function dnsblGuardMiddleware(req, _res, next) {
  if (!dnsblEnabled()) return next();
  const path = req.path || req.url || "";
  if (EXEMPT.has(path)) return next();
  const ip = normalizeIp(req.ipContext?.clientIp || "");
  if (!ip) return next();

  // Detach — never wait on DNS on the request path.
  checkDnsbl(ip)
    .then((verdict) => {
      if (!verdict.listed) return;
      publish("dnsbl_hit", { ip, zones: verdict.zones, path, ts: new Date().toISOString() });
      log.warn("dnsbl guard: listed client", { ip, zones: verdict.zones });
      recordOffense(ip).catch(() => {});
    })
    .catch((err) => log.debug("dnsbl guard: check failed", { ip, error: String(err.message || err) }));

  next();
}
