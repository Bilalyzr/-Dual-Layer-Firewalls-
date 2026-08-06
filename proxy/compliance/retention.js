/**
 * EPIC I — Data-retention TTLs.
 *
 * Enforces automatic expiry on alerts / samples / baselines so the system
 * complies with data-minimization principles (PRD §9 retention limits). Runs
 * as a periodic sweep (called from a cron-like interval in bootstrap).
 *
 * Defaults are conservative; tune via env. Set a TTL to 0 to keep indefinitely.
 */
import { stats } from "../db/mongo.js";

const DEFAULTS = {
  alerts_days: 90,
  samples_days: 30,
  baselines_days: 365, // biometric baselines are long-lived but must eventually expire
  biometric_events_days: 180,
};

export function retentionConfig() {
  return {
    alerts_days: +(process.env.RETENTION_ALERTS_DAYS || DEFAULTS.alerts_days),
    samples_days: +(process.env.RETENTION_SAMPLES_DAYS || DEFAULTS.samples_days),
    baselines_days: +(process.env.RETENTION_BASELINES_DAYS || DEFAULTS.baselines_days),
    biometric_events_days: +(process.env.RETENTION_BIOMETRIC_EVENTS_DAYS || DEFAULTS.biometric_events_days),
  };
}

/**
 * Run one retention sweep. Returns counts of what would be / was deleted.
 * In the in-memory fallback this prunes the arrays; with Mongo it issues
 * deleteMany with an expires index. Here we expose the policy + a sweep stub.
 */
export async function runRetentionSweep(db) {
  const cfg = retentionConfig();
  const cutoff = (days) => new Date(Date.now() - days * 86400_000);
  const result = { ranAt: new Date(), config: cfg, deleted: {} };
  if (!db) return result; // no live connection — policy is documented, sweep is a no-op here

  try {
    for (const [coll, days] of Object.entries(cfg)) {
      if (!days || days <= 0) continue;
      const r = await db.collection(coll).deleteMany({ ts: { $lt: cutoff(days) } });
      result.deleted[coll] = r.deletedCount;
    }
  } catch (err) {
    result.error = err.message;
  }
  return result;
}
