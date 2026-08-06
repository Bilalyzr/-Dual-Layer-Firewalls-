/**
 * EPIC H — OpenTelemetry export + distributed tracing.
 *
 * Wires the existing telemetry seam to an OTLP collector (Grafana/Datadog/
 * Honeycomb/Lightstep). The `x-request-id` propagation is already in place;
 * this adds real spans across gateway → firewall-svc → engine → LLM.
 *
 * Feature-flagged via OTEL_EXPORTER_OTLP_ENDPOINT. When unset → no-op (the
 * library degrades to a console/console-less meter). Zero external deps in the
 * no-op path; the real path lazy-loads @opentelemetry/* so the proxy stays
 * lightweight when observability isn't configured.
 */

let _tracer = null;
let _enabled = false;

export function otelEnabled() {
  return _enabled;
}

/** Initialize OTLP export. Safe to call multiple times. */
export async function initOtel(serviceName = "dlf-proxy") {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return false; // no-op when unconfigured
  try {
    // Lazy-load heavy OTel deps only when configured.
    const { NodeSDK } = await import("@opentelemetry/sdk-node");
    const { OTLPTraceExporter } = await import("@opentelemetry/exporter-trace-otlp-http");
    const { OTLPMetricExporter } = await import("@opentelemetry/exporter-metrics-otlp-http");
    const { getResourceAttributes } = await import("./resource.js");

    const sdk = new NodeSDK({
      serviceName,
      resource: getResourceAttributes(serviceName),
      traceExporter: new OTLPTraceExporter({ url: `${endpoint}/v1/traces` }),
      metricExporter: new OTLPMetricExporter({ url: `${endpoint}/v1/metrics` }),
      metricInterval: 10000,
    });
    sdk.start();
    _enabled = true;
    const { trace } = await import("@opentelemetry/api");
    _tracer = trace.getTracer(serviceName);
    console.log(`[otel] OTLP export enabled → ${endpoint}`);
    return true;
  } catch (err) {
    console.warn(`[otel] init failed (observability disabled): ${err.message}`);
    return false;
  }
}

/**
 * Wrap an async handler in a tracing span. No-op when OTel isn't configured.
 * @example const r = await withSpan("chat.classify", () => classifyPrompt(p));
 */
export async function withSpan(name, fn, attrs = {}) {
  if (!_tracer) return fn();
  return _tracer.startActiveSpan(name, async (span) => {
    try {
      for (const [k, v] of Object.entries(attrs)) span.setAttribute(k, v);
      return await fn();
    } catch (err) {
      span.recordException(err);
      span.setStatus({ code: 2, message: err.message });
      throw err;
    } finally {
      span.end();
    }
  });
}
