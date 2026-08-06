/**
 * EPIC G — /api/biometric/touch endpoint.
 *
 * Scores touch-dynamics batches (mean force/area/velocity) against a per-user
 * baseline. On non-touch devices this is never called — gracefully inert.
 *
 * Baseline persists to Mongo (`behavior_baselines`, channel="touch") with an
 * in-memory fallback, and each batch stashes its latest score for fusion into
 * the trust signal (firewall/trustFusion.js).
 */
import { Router } from "express";
import { requireConsent } from "../compliance/consent.js";
import { getBehaviorBaseline, upsertBehaviorBaseline } from "../db/mongo.js";

const router = Router();
const MIN_SAMPLES = 30;

router.post("/", requireConsent("touch"), async (req, res) => {
  const userId = req.body?.userId || "anon";
  const batch = {
    meanForce: +req.body?.meanForce || 0,
    meanArea: +req.body?.meanArea || 0,
    meanVelocity: +req.body?.meanVelocity || 0,
  };
  const prev = (await getBehaviorBaseline(userId, "touch")) || { meanForce: 0, meanArea: 0, meanVelocity: 0, n: 0 };
  const a = 0.1;
  const next = {
    meanForce: prev.n ? (1 - a) * prev.meanForce + a * batch.meanForce : batch.meanForce,
    meanArea: prev.n ? (1 - a) * prev.meanArea + a * batch.meanArea : batch.meanArea,
    meanVelocity: prev.n ? (1 - a) * prev.meanVelocity + a * batch.meanVelocity : batch.meanVelocity,
    n: (prev.n || 0) + 1,
  };

  if (next.n < MIN_SAMPLES) {
    await upsertBehaviorBaseline(userId, "touch", { ...next, lastScore: 0.5, lastColdStart: true, lastTs: new Date() });
    return res.json({ userId, touch_score: 0.5, cold_start: true, reason: "touch cold-start", baselineN: next.n });
  }
  const z = (Math.abs(batch.meanForce - next.meanForce) / (next.meanForce + 1e-6)
    + Math.abs(batch.meanArea - next.meanArea) / (next.meanArea + 1e-6)
    + Math.abs(batch.meanVelocity - next.meanVelocity) / (next.meanVelocity + 1e-6)) / 3;
  const score = Math.max(0, 1 - Math.min(1, z / 2));
  await upsertBehaviorBaseline(userId, "touch", { ...next, lastScore: +score.toFixed(3), lastColdStart: false, lastTs: new Date() });
  res.json({ userId, touch_score: +score.toFixed(3), cold_start: false, reason: `touch z=${z.toFixed(2)}`, baselineN: next.n });
});

export default router;
