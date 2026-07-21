/**
 * Lightweight metrics + health (Tier 2 · EPIC G — centralized observability).
 *
 * A full OpenTelemetry SDK is a heavy dependency tree for this PoC, so instead we
 * expose the same two things an OTel/Prometheus collector would scrape from every
 * service, uniformly:
 *   • GET /healthz  — liveness/readiness probe (used by the compose healthchecks)
 *   • GET /metrics  — Prometheus text-format counters, labelled with `service`
 * A production deploy swaps `inc()` for an OTLP metric exporter without touching
 * call sites — this module is that seam.
 */
const counters = new Map(); // "name|{labels}" -> integer
const startedAt = Date.now();

const serviceName = () =>
  process.env.SERVICE_NAME || process.env.SERVICE_ROLE || "proxy";

/** Increment a named counter with an optional label set. */
export function inc(name, labels = {}, by = 1) {
  const key = name + "|" + JSON.stringify(labels);
  counters.set(key, (counters.get(key) || 0) + by);
}

function renderProm() {
  const service = serviceName();
  const lines = [
    "# HELP service_up 1 while the service is running",
    "# TYPE service_up gauge",
    `service_up{service="${service}"} 1`,
    "# HELP service_uptime_seconds Seconds since process start",
    "# TYPE service_uptime_seconds gauge",
    `service_uptime_seconds{service="${service}"} ${Math.round((Date.now() - startedAt) / 1000)}`,
  ];
  const grouped = new Map();
  for (const [key, val] of counters) {
    const sep = key.indexOf("|");
    const name = key.slice(0, sep);
    const labels = JSON.parse(key.slice(sep + 1));
    const labelStr = Object.entries({ service, ...labels })
      .map(([k, v]) => `${k}="${String(v).replace(/"/g, "")}"`)
      .join(",");
    if (!grouped.has(name)) grouped.set(name, []);
    grouped.get(name).push(`${name}{${labelStr}} ${val}`);
  }
  for (const [name, rows] of grouped) {
    lines.push(`# TYPE ${name} counter`, ...rows);
  }
  return lines.join("\n") + "\n";
}

/** Middleware: count every HTTP response by method + status. */
export function metricsMiddleware(req, res, next) {
  res.on("finish", () => {
    inc("http_requests_total", { method: req.method, status: res.statusCode });
  });
  next();
}

/** Mount /healthz + /metrics on an app (every service calls this). */
export function mountTelemetry(app, { role } = {}) {
  app.get("/healthz", (_req, res) =>
    res.json({
      ok: true,
      service: serviceName(),
      role: role || serviceName(),
      uptimeSec: Math.round((Date.now() - startedAt) / 1000),
    })
  );
  app.get("/metrics", (_req, res) => {
    res.set("Content-Type", "text/plain; version=0.0.4");
    res.send(renderProm());
  });
}
