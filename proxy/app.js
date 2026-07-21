/**
 * App factory (Tier 2 · EPIC G — distributed microservices).
 *
 * One image, four roles. `createApp({ role })` builds an Express app that mounts
 * only the routers that role owns:
 *
 *   all        — the monolith: every router in-process (backward compatible,
 *                the default and what the whole test suite exercises).
 *   gateway    — public edge: sessions/auth, SSE (served off the shared Redis
 *                bus), alerts + metrics read models; forwards compute-heavy paths
 *                to their services.
 *   firewall   — the Layer-1 pipeline: /api/chat + /api/inspect.
 *   agent      — the Trifecta: internal /internal/agent/run only.
 *   biometric  — Layer-2 scoring + SHAP: /api/biometric + /api/shap.
 *
 * Every role gets the shared middleware (CORS, JSON, request logging, metrics,
 * session verification) and the /healthz + /metrics probes, so a collector sees a
 * uniform surface across services. Because every service shares SESSION_SECRET
 * and Mongo, a session token minted at the gateway verifies everywhere.
 */
import "./config/env.js";
import express from "express";
import cors from "cors";

import { sessionMiddleware } from "./auth/session.js";
import { requestLogger } from "./lib/logger.js";
import { metricsMiddleware, mountTelemetry } from "./middleware/telemetry.js";
import { proxyTo } from "./lib/forward.js";
import { busMode } from "./middleware/eventBus.js";
import { llmConfig } from "./llm/client.js";

import chatRouter from "./routes/chat.js";
import biometricRouter from "./routes/biometric.js";
import eventsRouter from "./routes/events.js";
import alertsRouter from "./routes/alerts.js";
import metricsRouter from "./routes/metrics.js";
import inspectRouter from "./routes/inspect.js";
import shapRouter from "./routes/shap.js";
import sessionRouter from "./routes/session.js";
import authRouter from "./routes/auth.js";
import internalAgentRouter from "./routes/internalAgent.js";

const ROLES = new Set(["all", "gateway", "firewall", "agent", "biometric"]);

const firewallSvc = () => process.env.FIREWALL_SVC_URL || "http://firewall-svc:4000";
const biometricSvc = () => process.env.BIOMETRIC_SVC_URL || "http://biometric-svc:4000";

function mountMonolith(app) {
  app.use("/api/session", sessionRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/chat", chatRouter);
  app.use("/api/biometric", biometricRouter);
  app.use("/api/events", eventsRouter);
  app.use("/api/alerts", alertsRouter);
  app.use("/api/metrics", metricsRouter);
  app.use("/api/inspect", inspectRouter);
  app.use("/api/shap", shapRouter);
}

function mountGateway(app) {
  // Owns identity + read models + the SSE stream (fed by the Redis relay).
  app.use("/api/session", sessionRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/events", eventsRouter);
  app.use("/api/alerts", alertsRouter);
  app.use("/api/metrics", metricsRouter);
  // Forwards compute-heavy paths to their owning services.
  app.use("/api/chat", proxyTo(firewallSvc()));
  app.use("/api/inspect", proxyTo(firewallSvc()));
  app.use("/api/biometric", proxyTo(biometricSvc()));
  app.use("/api/shap", proxyTo(biometricSvc()));
}

export function createApp({ role = "all" } = {}) {
  if (!ROLES.has(role)) throw new Error(`unknown SERVICE_ROLE "${role}" (expected one of ${[...ROLES].join(", ")})`);

  const app = express();
  app.disable("x-powered-by");
  app.use(cors({ exposedHeaders: ["x-session-token", "x-request-id"] }));
  app.use(express.json({ limit: "2mb" }));
  app.use(requestLogger);
  app.use(metricsMiddleware);
  app.use(sessionMiddleware);
  mountTelemetry(app, { role });

  if (role === "all") mountMonolith(app);
  else if (role === "gateway") mountGateway(app);
  else if (role === "firewall") {
    app.use("/api/chat", chatRouter);
    app.use("/api/inspect", inspectRouter);
  } else if (role === "agent") {
    app.use("/internal/agent", internalAgentRouter);
  } else if (role === "biometric") {
    app.use("/api/biometric", biometricRouter);
    app.use("/api/shap", shapRouter);
  }

  app.get("/", (_req, res) => {
    res.json({
      service: "dual-layer-proxy",
      role,
      version: "1.0.0",
      bus: busMode(),
      firewallMode: (process.env.FIREWALL_MODE || "shadow").toLowerCase(),
      biometricMode: (process.env.BIOMETRIC_MODE || "shadow").toLowerCase(),
      llm: llmConfig(),
    });
  });

  app.use((err, _req, res, _next) => {
    console.error(`[${role}] unhandled:`, err);
    res.status(500).json({ error: "internal", detail: String(err.message || err) });
  });

  return app;
}
