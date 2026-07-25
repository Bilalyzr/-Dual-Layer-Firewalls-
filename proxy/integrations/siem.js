/**
 * Tier 3 · Wave 2 · Epic D — SIEM & threat-intelligence forwarding.
 *
 * Every BLOCK/THREAT/auto-ban event is pushed to a configurable SIEM webhook so an
 * enterprise SOC (Splunk / Elastic / Microsoft Sentinel / Sumo Logic) gets the
 * firewall's decisions in its own console. Architecturally this is "just another
 * subscriber": we register an in-process listener on the event bus (onEvent) rather
 * than teeing every call-site — a threat detected in `firewall-svc` is forwarded by
 * the same process that published it, exactly once.
 *
 * Fail-soft + off the hot path:
 *   • Unset SIEM_WEBHOOK_URL → the relay never starts (demo-safe default).
 *   • Delivery is fire-and-forget with a timeout; a down SIEM never blocks or
 *     crashes the request that produced the event.
 *   • Only actionable security events are forwarded (blocked=true / bans), not the
 *     dashboard's live chatter, so we don't flood the SIEM with noise.
 *
 * SIEM_FORMAT selects the payload shape:
 *   splunk  — Splunk HEC envelope   { event, sourcetype, source, time }
 *   ecs     — Elastic Common Schema  { @timestamp, event.*, source.ip, ... }
 *   sentinel/generic — a flat JSON record (works for Sentinel DCR, Sumo, webhooks)
 */
import { onEvent } from "../middleware/eventBus.js";
import { log } from "../lib/logger.js";

// Events worth escalating to a SIEM. NOTE the dual-publish pattern elsewhere: a
// signature block and a ban are each published under their specific type AND under
// "threat" (so the dashboard's threat feed shows them). To forward each logical
// event to the SIEM EXACTLY ONCE we subscribe to "threat" (which covers chat
// threats, signature blocks and ban creations) plus "ban_enforced" (the only
// security event that is NOT also published as "threat"). Do not add "ban" or
// "signature" here or every one would be forwarded twice.
const FORWARDED_TYPES = new Set(["threat", "ban_enforced"]);

let _unsubscribe = null;
let _stats = { forwarded: 0, failed: 0, lastError: null, lastAt: null };

export const siemUrl = () => process.env.SIEM_WEBHOOK_URL || "";
export const siemFormat = () => (process.env.SIEM_FORMAT || "generic").toLowerCase();
const siemToken = () => process.env.SIEM_TOKEN || process.env.SIEM_HEC_TOKEN || "";
const timeoutMs = () => parseInt(process.env.SIEM_TIMEOUT_MS || "4000", 10);

/** True when a threat/ban event should be relayed to the SIEM. */
function shouldForward(event) {
  if (!FORWARDED_TYPES.has(event.type)) return false;
  const p = event.payload || {};
  // "threat" carries a full alert; forward only actual blocks unless the operator
  // opts into shadow detections too (SIEM_FORWARD_DETECTIONS=true).
  if (event.type === "threat") {
    const forwardDetections =
      String(process.env.SIEM_FORWARD_DETECTIONS || "false").toLowerCase() === "true";
    return p.blocked === true || forwardDetections;
  }
  return true;
}

/** Normalize an event into a flat, SIEM-friendly record (PII already masked upstream). */
export function toRecord(event) {
  const p = event.payload || {};
  const fx = p.forensics || {};
  return {
    vendor: "dual-layer-ai-firewall",
    product: "prompt-firewall",
    eventType: event.type,
    ts: event.ts,
    severity: p.blocked ? "high" : "medium",
    action: p.blocked ? "blocked" : "detected",
    category: p.category || null,
    categoryTitle: p.categoryTitle || null,
    label: p.label || null,
    kind: p.kind || null,
    mode: p.mode || null,
    userId: p.userId || null,
    sessionId: p.sessionId || null,
    clientIp: fx.clientIp || p.ip || p.target || null,
    country: fx.enrichment?.geoip?.country || null,
    asn: fx.enrichment?.asn?.asn || null,
    abuseScore: fx.enrichment?.abuseScore ?? null,
    signature: p.signature || null,
    scope: p.scope || null,
  };
}

/** Wrap a record in the envelope the configured SIEM expects. */
export function formatPayload(event) {
  const rec = toRecord(event);
  switch (siemFormat()) {
    case "splunk":
      return {
        time: Math.floor(new Date(event.ts).getTime() / 1000),
        source: "dual-layer-ai-firewall",
        sourcetype: "_json",
        event: rec,
      };
    case "ecs":
      return {
        "@timestamp": event.ts,
        "event.kind": "alert",
        "event.category": ["intrusion_detection"],
        "event.action": rec.action,
        "event.severity": rec.severity === "high" ? 73 : 47,
        "rule.name": rec.label,
        "source.ip": rec.clientIp,
        "source.geo.country_iso_code": rec.country,
        "source.as.number": rec.asn,
        "user.id": rec.userId,
        "threat.tactic.name": rec.categoryTitle,
        firewall: rec,
      };
    // sentinel / sumo / generic all accept a flat JSON record.
    default:
      return rec;
  }
}

async function deliver(event) {
  const url = siemUrl();
  if (!url) return;
  const body = JSON.stringify(formatPayload(event));
  const headers = { "content-type": "application/json" };
  const token = siemToken();
  if (token) {
    // Splunk HEC uses `Authorization: Splunk <token>`; everything else a Bearer.
    headers.authorization = siemFormat() === "splunk" ? `Splunk ${token}` : `Bearer ${token}`;
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs());
  try {
    const resp = await fetch(url, { method: "POST", headers, body, signal: ctrl.signal });
    if (!resp.ok) throw new Error(`SIEM responded ${resp.status}`);
    _stats.forwarded++;
    _stats.lastAt = new Date().toISOString();
  } catch (err) {
    _stats.failed++;
    _stats.lastError = String(err.message || err);
    log.warn("siem: forward failed", { error: _stats.lastError });
  } finally {
    clearTimeout(t);
  }
}

/**
 * Start the SIEM relay if SIEM_WEBHOOK_URL is set. Idempotent. Returns true when
 * active. Called once per process at bootstrap; no-op (returns false) when unset.
 */
export function startSiemRelay() {
  if (_unsubscribe) return true; // already running
  if (!siemUrl()) return false; // unconfigured — demo default
  _unsubscribe = onEvent((event) => {
    if (!shouldForward(event)) return;
    // Detach from the publisher's stack entirely — never awaited, never throws up.
    Promise.resolve().then(() => deliver(event));
  });
  log.info("siem: relay active", { format: siemFormat() });
  return true;
}

export function stopSiemRelay() {
  if (_unsubscribe) _unsubscribe();
  _unsubscribe = null;
}

export function siemEnabled() {
  return !!siemUrl();
}

export function siemStats() {
  return { enabled: siemEnabled(), format: siemFormat(), running: !!_unsubscribe, ..._stats };
}

/** Test hook: reset counters + detach. */
export function __resetSiemForTests() {
  stopSiemRelay();
  _stats = { forwarded: 0, failed: 0, lastError: null, lastAt: null };
}
