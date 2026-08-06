/**
 * Service bootstrap (Tier 2 · EPIC G).
 *
 * Shared start-up used by every role: load env, connect Mongo, wire the Redis
 * event-bus relay (no-op in monolith/test), and listen. The per-role entrypoints
 * in services/ are one-liners over this so `node services/gateway.js` etc. are
 * self-documenting.
 */
import "./config/env.js";
import { createApp } from "./app.js";
import { connect } from "./db/mongo.js";
import { startBusRelay, busMode } from "./middleware/eventBus.js";
import { connectStore, storeMode } from "./lib/store.js";
import { hydrateBans } from "./response/banStore.js";
import { startSiemRelay, siemEnabled } from "./integrations/siem.js";
import { log } from "./lib/logger.js";
import { llmConfig } from "./llm/client.js";
import { strictReal } from "./lib/strict.js";

// Last-resort safety net. The proxy is a security control with no supervisor in
// local dev (scripts/runner.js does not restart a dead child), so an off-path
// async error must never take the whole firewall down. We log loudly and keep
// serving rather than exit — the request path itself already fails safe per-route.
// Installed once, at module load, before any listener is wired.
let _guardsInstalled = false;
function installProcessGuards() {
  if (_guardsInstalled) return;
  _guardsInstalled = true;
  process.on("unhandledRejection", (reason) => {
    log.error("unhandledRejection (kept alive)", {
      error: String(reason?.message || reason),
      stack: reason?.stack,
    });
  });
  process.on("uncaughtException", (err) => {
    log.error("uncaughtException (kept alive)", {
      error: String(err?.message || err),
      stack: err?.stack,
    });
  });
}

export async function startService(role = "all") {
  installProcessGuards();
  // Set at runtime so the orchestrator's recursion guard + the logger/telemetry
  // service label resolve correctly (all read process.env lazily, per call).
  process.env.SERVICE_ROLE = role;
  if (!process.env.SERVICE_NAME) process.env.SERVICE_NAME = role === "all" ? "proxy" : role;

  const PORT = parseInt(process.env.PROXY_PORT || process.env.PORT || "4000", 10);
  const app = createApp({ role });

  await connect();
  await startBusRelay();
  await connectStore(); // Tier-3 Redis command client (reputation cache + ip guard)
  await hydrateBans(); // load persisted CIDR bans into the in-memory guard index
  startSiemRelay(); // Tier-3 Wave 2: forward BLOCK events to the SIEM (no-op if unset)

  // Real-only posture check: warn loudly if strict mode is on but the LLM is not
  // configured — chat/agent calls will hard-fail (by design) until a key is set.
  if (strictReal() && !llmConfig().configured) {
    log.warn(
      "STRICT_REAL is on but the LLM is not configured — chat/agent requests will return errors " +
        "until LLM_API_KEY is set (or set STRICT_REAL=false to allow the offline demo fallback)."
    );
  }

  return new Promise((resolve) => {
    const server = app.listen(PORT, () => {
      log.info("service listening", {
        role,
        port: PORT,
        bus: busMode(),
        store: storeMode(),
        firewall: (process.env.FIREWALL_MODE || "shadow").toLowerCase(),
        biometric: (process.env.BIOMETRIC_MODE || "shadow").toLowerCase(),
        llmConfigured: llmConfig().configured,
        siem: siemEnabled(),
      });
      resolve(server);
    });
  });
}
