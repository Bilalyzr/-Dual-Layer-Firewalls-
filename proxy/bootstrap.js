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
import { log } from "./lib/logger.js";
import { llmConfig } from "./llm/client.js";

export async function startService(role = "all") {
  // Set at runtime so the orchestrator's recursion guard + the logger/telemetry
  // service label resolve correctly (all read process.env lazily, per call).
  process.env.SERVICE_ROLE = role;
  if (!process.env.SERVICE_NAME) process.env.SERVICE_NAME = role === "all" ? "proxy" : role;

  const PORT = parseInt(process.env.PROXY_PORT || process.env.PORT || "4000", 10);
  const app = createApp({ role });

  await connect();
  await startBusRelay();

  return new Promise((resolve) => {
    const server = app.listen(PORT, () => {
      log.info("service listening", {
        role,
        port: PORT,
        bus: busMode(),
        firewall: (process.env.FIREWALL_MODE || "shadow").toLowerCase(),
        biometric: (process.env.BIOMETRIC_MODE || "shadow").toLowerCase(),
        llmConfigured: llmConfig().configured,
      });
      resolve(server);
    });
  });
}
