/**
 * Tier 3 · Wave 1 · Epic C — edge IP guard.
 *
 * Runs BEFORE the firewall pipeline: a request from a banned IP/CIDR is refused
 * (or fed a honeypot) without paying for heuristics, ML, or the LLM. This is the
 * "act" half of the auto-response engine — the ban decisions come from banStore.
 *
 * Modes (RESPONSE_MODE):
 *   off       — pass everything through (default; shadow deployments only observe)
 *   block     — banned IPs get a terse 403; no hint about why, to avoid coaching
 *   honeypot  — banned IPs get a DELAYED, plausible fake response to waste their
 *               time and let us keep gathering signal instead of a hard block
 *
 * The kill switch (banStore.killSwitchEngaged) short-circuits to pass-through so
 * an operator can disable enforcement instantly if it ever misfires.
 */
import { isBanned, responseMode, honeypotDelayMs, killSwitchEngaged } from "../response/banStore.js";
import { publish } from "./eventBus.js";
import { log } from "../lib/logger.js";

// Never guard health/metrics/root probes — they come from trusted infra and must
// stay reachable even while enforcement is on.
const EXEMPT = new Set(["/", "/healthz", "/metrics"]);

function honeypotBody() {
  return {
    blocked: false,
    answer:
      "I can help with that. Could you share a little more detail about what you're trying to accomplish?",
    simulated: true,
    verdict: { mode: "honeypot", threat: false },
  };
}

export function ipGuardMiddleware(req, res, next) {
  // Fast path: engine off or killed → no store lookups at all.
  if (responseMode() === "off" || killSwitchEngaged()) return next();
  const path = req.path || req.url || "";
  if (EXEMPT.has(path)) return next();

  const ip = req.ipContext?.clientIp;
  if (!ip) return next();

  isBanned(ip)
    .then((verdict) => {
      if (!verdict.banned) return next();

      publish("ban_enforced", {
        ip,
        scope: verdict.scope,
        cidr: verdict.cidr,
        mode: responseMode(),
        path,
        ts: new Date().toISOString(),
      });
      log.warn("ip guard: refused banned client", { ip, scope: verdict.scope, mode: responseMode() });

      if (responseMode() === "honeypot") {
        const delay = Math.max(0, honeypotDelayMs());
        const timer = setTimeout(() => {
          if (!res.headersSent) res.status(200).json(honeypotBody());
        }, delay);
        timer.unref?.();
        // Don't leak the timer if the client bails first.
        res.on("close", () => clearTimeout(timer));
        return;
      }

      // block mode — deliberately generic.
      return res.status(403).json({ blocked: true, reason: "forbidden" });
    })
    .catch((err) => {
      // Fail-open: a store error must never take the whole gateway down.
      log.warn("ip guard: check failed, allowing", { ip, error: String(err.message || err) });
      next();
    });
}
