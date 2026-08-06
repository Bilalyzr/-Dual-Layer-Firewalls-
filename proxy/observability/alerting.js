/**
 * EPIC H — Alerting pipeline (PagerDuty / OpsGenie / generic webhook).
 *
 * Subscribes to the event bus for high-severity / coordinated-attack events and
 * pages on-call. One bus subscriber — reuses the existing publish() seam.
 *
 * Config:
 *   ALERT_WEBHOOK_URL   — generic webhook (PagerDuty/OpsGenie/Slack) [unset = no-op]
 *   ALERT_SEVERITY_MIN  — minimum severity to page (info|warning|error|critical)
 *
 * Failures are logged but never block the event path (alerting is best-effort).
 */
const SEVERITY_RANK = { info: 0, warning: 1, error: 2, critical: 3 };

/** Page on-call for an event. No-op when ALERT_WEBHOOK_URL is unset. */
export async function pageAlert(event) {
  const url = process.env.ALERT_WEBHOOK_URL;
  if (!url) return { paged: false, reason: "no webhook configured" };
  const minRank = SEVERITY_RANK[process.env.ALERT_SEVERITY_MIN || "error"] ?? 2;
  const sev = event.severity || "error";
  if ((SEVERITY_RANK[sev] ?? 2) < minRank) return { paged: false, reason: "below severity floor" };

  const payload = {
    severity: sev,
    title: event.title || event.label || "Dual-Layer Firewall alert",
    summary: event.summary || event.reason || "",
    source: "dlf-proxy",
    timestamp: new Date().toISOString(),
    event_type: event.type || "alert",
    raw: event,
  };
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    return { paged: r.ok, status: r.status };
  } catch (err) {
    console.warn(`[alerting] page failed: ${err.message}`);
    return { paged: false, error: err.message };
  }
}
