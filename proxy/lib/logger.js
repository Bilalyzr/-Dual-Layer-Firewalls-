/**
 * Structured logging (Tier 2 · EPIC G — observability).
 *
 * In a distributed topology the plain console lines from four services interleave
 * into an unparseable stream. This emits one JSON object per line, tagged with the
 * service name and a per-request id, so a log aggregator (Loki/ELK/Cloud Logging)
 * — or a local `jq` — can filter by service / level / requestId. This is the
 * integration point where an OpenTelemetry/OTLP log exporter would attach.
 *
 * Zero dependencies. Set LOG_FORMAT=pretty for human-readable local dev, and
 * LOG_LEVEL=debug|info|warn|error to filter. The service name is read lazily
 * (per call) so a service entrypoint can set SERVICE_ROLE before the first log
 * without fighting ES-module import hoisting (see config/env.js for the pattern).
 */
import crypto from "crypto";

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

const serviceName = () =>
  process.env.SERVICE_NAME || process.env.SERVICE_ROLE || "proxy";
const minLevel = () => LEVELS[(process.env.LOG_LEVEL || "info").toLowerCase()] ?? LEVELS.info;
const pretty = () => (process.env.LOG_FORMAT || "").toLowerCase() === "pretty";

function emit(level, msg, fields) {
  if (LEVELS[level] < minLevel()) return;
  const service = serviceName();
  const sink = level === "debug" ? "log" : level; // console has no .debug in older runtimes
  if (pretty()) {
    const extra = fields && Object.keys(fields).length ? " " + JSON.stringify(fields) : "";
    console[sink](`[${service}] ${level.toUpperCase()} ${msg}${extra}`);
  } else {
    console[sink](JSON.stringify({ ts: new Date().toISOString(), level, service, msg, ...fields }));
  }
}

export const log = {
  debug: (msg, f) => emit("debug", msg, f),
  info: (msg, f) => emit("info", msg, f),
  warn: (msg, f) => emit("warn", msg, f),
  error: (msg, f) => emit("error", msg, f),
  get service() {
    return serviceName();
  },
};

/**
 * Express middleware: assign/propagate a request id and log each request's
 * outcome once. The id is echoed as `x-request-id` and forwarded by the gateway
 * so a single client call can be traced across every service it touches.
 */
export function requestLogger(req, res, next) {
  const rid = req.headers["x-request-id"] || crypto.randomBytes(8).toString("hex");
  req.requestId = rid;
  res.setHeader("x-request-id", rid);
  const t0 = performance.now();
  res.on("finish", () => {
    emit(res.statusCode >= 500 ? "error" : "info", "request", {
      requestId: rid,
      method: req.method,
      path: req.originalUrl || req.url,
      status: res.statusCode,
      latencyMs: +(performance.now() - t0).toFixed(1),
    });
  });
  next();
}
