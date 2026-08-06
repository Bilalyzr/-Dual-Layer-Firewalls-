/**
 * EPIC H — /api/sla endpoint: SLA dashboard data.
 *
 * Returns latency percentiles, availability, error rate, system-metric history,
 * and any active anomalies. Consumed by the dashboard's SLA panel.
 */
import { Router } from "express";
import { slaSnapshot, metricHistory, sampleSystemMetrics } from "../observability/sla.js";

const router = Router();

router.get("/", (_req, res) => {
  const sys = sampleSystemMetrics();
  res.json({
    sla: slaSnapshot(),
    systemMetrics: metricHistory(60),
    anomalies: sys.anomalies,
    ts: new Date().toISOString(),
  });
});

export default router;
