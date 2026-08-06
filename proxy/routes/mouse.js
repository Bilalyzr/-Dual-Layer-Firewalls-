/**
 * EPIC G — /api/biometric/mouse endpoint.
 *
 * Receives mouse-dynamics batches from useMouseCapture, scores them against a
 * per-user baseline (z-score on mean speed / turn rate / cadence), and exposes
 * a mouse_score that the fusion model combines with the keystroke score.
 *
 * The baseline persists to Mongo (`behavior_baselines`, channel="mouse") with an
 * in-memory fallback — previously it lived in a per-process Map that reset on
 * restart and diverged across biometric-svc replicas. Each batch also stashes
 * the latest score + timestamp so the keystroke route can fuse it into the trust
 * signal that drives step-up (see firewall/trustFusion.js).
 */
import { Router } from "express";
import { requireConsent } from "../compliance/consent.js";
import { getBehaviorBaseline, upsertBehaviorBaseline } from "../db/mongo.js";

const router = Router();

const MIN_MOUSE_SAMPLES = 40;

function scoreBatch(baseline, batch) {
  if (!baseline || baseline.n < MIN_MOUSE_SAMPLES) {
    return { mouse_score: 0.5, cold_start: true, reason: "mouse cold-start" };
  }
  const zSpeed = baseline.meanSpeed > 0 ? Math.abs(batch.meanSpeed - baseline.meanSpeed) / baseline.meanSpeed : 0;
  const zTurn = Math.abs(batch.turnRate - baseline.turnRate) / (baseline.turnRate + 1e-6);
  const zCadence = Math.abs(batch.cadence - baseline.cadence) / (baseline.cadence + 1e-6);
  const z = (zSpeed + zTurn + zCadence) / 3;
  const score = Math.max(0, 1 - Math.min(1, z / 2));
  return { mouse_score: +score.toFixed(3), cold_start: false, reason: `mouse z=${z.toFixed(2)}` };
}

router.post("/", requireConsent("mouse"), async (req, res) => {
  const userId = req.body?.userId || "anon";
  const batch = {
    meanSpeed: +req.body?.meanSpeed || 0,
    turnRate: +req.body?.turnRate || 0,
    cadence: +req.body?.cadence || 0,
  };
  const prev = (await getBehaviorBaseline(userId, "mouse")) || { meanSpeed: 0, turnRate: 0, cadence: 0, n: 0 };
  // extend baseline with a gentle EWMA
  const a = 0.1;
  const next = {
    meanSpeed: prev.n ? (1 - a) * prev.meanSpeed + a * batch.meanSpeed : batch.meanSpeed,
    turnRate: prev.n ? (1 - a) * prev.turnRate + a * batch.turnRate : batch.turnRate,
    cadence: prev.n ? (1 - a) * prev.cadence + a * batch.cadence : batch.cadence,
    n: (prev.n || 0) + 1,
  };
  const result = scoreBatch(next, batch);
  // Persist the baseline + the latest score (for fusion into the trust signal).
  await upsertBehaviorBaseline(userId, "mouse", {
    ...next,
    lastScore: result.mouse_score,
    lastColdStart: result.cold_start,
    lastTs: new Date(),
  });
  res.json({ userId, ...result, baselineN: next.n, minSamples: MIN_MOUSE_SAMPLES });
});

router.get("/status/:userId", async (req, res) => {
  const b = (await getBehaviorBaseline(req.params.userId, "mouse")) || { n: 0 };
  res.json({ userId: req.params.userId, baselineN: b.n || 0, minSamples: MIN_MOUSE_SAMPLES, coldStart: (b.n || 0) < MIN_MOUSE_SAMPLES });
});

export default router;
