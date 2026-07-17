/**
 * Dual-Layer AI Firewall — Node.js Proxy (PRD §4 Proxy Layer).
 *
 * Single Express gateway that:
 *   • intercepts inbound prompts (/api/chat) and runs the firewall pipeline,
 *   • ingests keystroke telemetry (/api/biometric) for continuous auth,
 *   • streams live events to the dashboard (/api/events),
 *   • exposes alerts, status and benchmark metrics.
 */
// Load env: prefer .env.local (local dev) over .env (docker). Existing process
// env vars always win.
import dotenv from "dotenv";
import { existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
if (existsSync(path.join(__root, ".env.local"))) {
  dotenv.config({ path: path.join(__root, ".env.local") });
} else {
  dotenv.config({ path: path.join(__root, ".env") });
}
import express from "express";
import cors from "cors";

import { connect } from "./db/mongo.js";
import chatRouter from "./routes/chat.js";
import biometricRouter from "./routes/biometric.js";
import eventsRouter from "./routes/events.js";
import alertsRouter from "./routes/alerts.js";
import metricsRouter from "./routes/metrics.js";
import inspectRouter from "./routes/inspect.js";
import shapRouter from "./routes/shap.js";
import { llmConfig } from "./llm/client.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.get("/", (_req, res) => {
  res.json({
    service: "dual-layer-proxy",
    version: "1.0.0",
    firewallMode: (process.env.FIREWALL_MODE || "shadow").toLowerCase(),
    biometricMode: (process.env.BIOMETRIC_MODE || "shadow").toLowerCase(),
    llm: llmConfig(),
    endpoints: [
      "POST /api/chat",
      "POST /api/biometric/batch",
      "GET  /api/biometric/status/:userId",
      "GET  /api/events (SSE)",
      "GET  /api/alerts",
      "GET  /api/alerts/status",
      "GET  /api/metrics",
      "POST /api/inspect (firewall-only, no LLM)",
    ],
  });
});

app.use("/api/chat", chatRouter);
app.use("/api/biometric", biometricRouter);
app.use("/api/events", eventsRouter);
app.use("/api/alerts", alertsRouter);
app.use("/api/metrics", metricsRouter);
app.use("/api/inspect", inspectRouter);
app.use("/api/shap", shapRouter);

app.use((err, _req, res, _next) => {
  console.error("[proxy] unhandled:", err);
  res.status(500).json({ error: "internal", detail: String(err.message || err) });
});

const PORT = parseInt(process.env.PROXY_PORT || "4000", 10);

connect().then(() => {
  app.listen(PORT, () => {
    console.log(`[proxy] Dual-Layer AI Firewall listening on :${PORT}`);
    console.log(
      `[proxy] firewall=${(process.env.FIREWALL_MODE || "shadow").toUpperCase()} ` +
      `biometric=${(process.env.BIOMETRIC_MODE || "shadow").toUpperCase()} ` +
      `llm.configured=${llmConfig().configured}`
    );
  });
});
