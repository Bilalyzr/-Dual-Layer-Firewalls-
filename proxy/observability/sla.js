/**
 * EPIC H — SLA tracking + system-metric anomaly detection.
 *
 * Two capabilities:
 *   1. SLA: records per-request latency + status; computes p50/p95/p99,
 *      availability, and error rate over a rolling window.
 *   2. System-metric anomaly detection: samples CPU + memory + request-rate
 *      via Node's `os` module; flags spikes that may indicate DDoS or a runaway
 *      process. Feeds the alerting pipeline.
 *
 * All in-process; for multi-instance deployments, export via the OTLP seam (H).
 */
import os from "node:os";

const WINDOW_MS = 60_000; // rolling 1-minute window
const _requests = []; // { ts, latencyMs, status }
const _metrics = []; // { ts, cpuLoad, memPct, reqRate }
let _reqCount = 0;

/** Record a completed request. Called from the response-timing middleware. */
export function recordRequest(latencyMs, status) {
  const now = Date.now();
  _requests.push({ ts: now, latencyMs, status });
  _reqCount++;
  // prune
  while (_requests.length && _requests[0].ts < now - WINDOW_MS) _requests.shift();
}

/** Percentile helper. */
function pct(sorted, p) {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * (p / 100)))];
}

/** Compute SLA over the rolling window. */
export function slaSnapshot() {
  const now = Date.now();
  const recent = _requests.filter((r) => r.ts > now - WINDOW_MS);
  const latencies = recent.map((r) => r.latencyMs).sort((a, b) => a - b);
  const errors = recent.filter((r) => r.status >= 500).length;
  return {
    windowMs: WINDOW_MS,
    requestCount: recent.length,
    availability: recent.length ? +(((recent.length - errors) / recent.length) * 100).toFixed(2) : 100,
    errorRate: recent.length ? +((errors / recent.length) * 100).toFixed(2) : 0,
    latencyMs: {
      p50: +pct(latencies, 50).toFixed(1),
      p95: +pct(latencies, 95).toFixed(1),
      p99: +pct(latencies, 99).toFixed(1),
      mean: latencies.length ? +(latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : 0,
    },
  };
}

// ---- System-metric anomaly detection --------------------------------------
const CPU_WARN = parseFloat(process.env.CPU_WARN_PCT || "80");
const MEM_WARN = parseFloat(process.env.MEM_WARN_PCT || "85");
const REQ_RATE_WARN = parseFloat(process.env.REQ_RATE_WARN_RPS || "100");

/** Sample system metrics + detect anomalies. Call periodically (e.g. every 5s). */
export function sampleSystemMetrics() {
  const cpus = os.cpus();
  const cpuLoad = os.loadavg()[0] / (cpus.length || 1); // 1-min load avg per core
  const memPct = (1 - os.freemem() / os.totalmem()) * 100;
  const now = Date.now();
  const recent = _requests.filter((r) => r.ts > now - 1000).length;
  const reqRate = recent; // req/sec

  const metric = { ts: now, cpuLoad: +cpuLoad.toFixed(2), memPct: +memPct.toFixed(1), reqRate };
  _metrics.push(metric);
  if (_metrics.length > 240) _metrics.shift(); // 20 min at 5s intervals

  // anomaly flags
  const anomalies = [];
  if (cpuLoad * 100 > CPU_WARN) anomalies.push({ metric: "cpu", value: cpuLoad, threshold: CPU_WARN / 100 });
  if (memPct > MEM_WARN) anomalies.push({ metric: "memory", value: memPct, threshold: MEM_WARN });
  if (reqRate > REQ_RATE_WARN) anomalies.push({ metric: "request_rate", value: reqRate, threshold: REQ_RATE_WARN, note: "possible DDoS" });

  return { metric, anomalies };
}

/** Recent system-metric history (for the SLA dashboard chart). */
export function metricHistory(limit = 60) {
  return _metrics.slice(-limit);
}
