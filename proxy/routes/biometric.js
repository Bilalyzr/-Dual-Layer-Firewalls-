/**
 * /api/biometric — keystroke telemetry ingestion + scoring (Req 3.1, 3.6).
 *
 * Frontend batches compact [dwell, flight] arrays; we:
 *   1. append to the user's rolling baseline (Req 3.1)
 *   2. score the new batch against the baseline via the engine (Req 3.2* — Tier-1 z-score)
 *   3. honour cold-start: insufficient history => MFA flag, no score (Req 3.6)
 *   4. publish trust updates to the dashboard SSE feed (Req 4.2)
 *
 * * LSTM/ensemble is Tier 2 (Phase 4).
 */
import { Router } from "express";
import { scoreBiometricBatch } from "../firewall/mlClient.js";
import { getBaseline, upsertBaseline, insertBiometricEvent } from "../db/mongo.js";
import { publish } from "../middleware/eventBus.js";

const router = Router();

const MIN_SAMPLES = parseInt(process.env.BIOMETRIC_MIN_SAMPLES || "120", 10);
const Z_THRESHOLD = parseFloat(process.env.BIOMETRIC_Z_THRESHOLD || "2.5");
const MAX_HISTORY = 5000; // rolling window cap

router.post("/batch", async (req, res) => {
  const userId = req.body?.userId || "anon";
  // events: [{d, f}]  (dwell ms, flight ms; flight may be null/0 for first key)
  const events = Array.isArray(req.body?.events) ? req.body.events : [];
  const dwellTimes = events.map((e) => +e.d).filter((n) => Number.isFinite(n) && n > 0);
  const flightTimes = events.map((e) => +e.f).filter((n) => Number.isFinite(n) && n > 0);

  if (dwellTimes.length === 0) {
    return res.json({ accepted: 0, trust_score: 100, cold_start: true, reason: "no events" });
  }

  // Load & extend rolling baseline.
  const prev = (await getBaseline(userId)) || { dwellHistory: [], flightHistory: [], n: 0 };
  const dwellHistory = (prev.dwellHistory || []).concat(dwellTimes).slice(-MAX_HISTORY);
  const flightHistory = (prev.flightHistory || []).concat(flightTimes).slice(-MAX_HISTORY);
  const priorN = (prev.n || 0) + dwellTimes.length;

  // Score the incoming batch against the baseline-so-far (engine does z-score + cold-start).
  const engineResult = await scoreBiometricBatch({
    dwell_history: dwellHistory,
    flight_history: flightHistory,
    prior_n: priorN,
    dwell_times: dwellTimes,
    flight_times: flightTimes,
    min_samples: MIN_SAMPLES,
    z_threshold: Z_THRESHOLD,
  });

  // Persist updated baseline (store a downsampled summary + small raw sample for demo).
  await upsertBaseline(userId, {
    dwellHistory: dwellHistory.slice(-MIN_SAMPLES * 2),
    flightHistory: flightHistory.slice(-MIN_SAMPLES * 2),
    n: priorN,
    lastTrust: engineResult.trust_score,
    lastReason: engineResult.reason,
  });

  const event = {
    userId,
    trust_score: engineResult.trust_score,
    risk_score: engineResult.risk_score,
    z: engineResult.z,
    cold_start: engineResult.cold_start,
    reason: engineResult.reason,
    model_used: engineResult.model_used || "zscore",
    p_genuine: engineResult.p_genuine,
    shap_request_id: engineResult.shap_request_id,
    batchSize: dwellTimes.length,
    baselineN: priorN,
    minSamples: MIN_SAMPLES,
    ts: new Date(),
  };
  await insertBiometricEvent(event);
  publish("biometric", event);

  return res.json({ accepted: dwellTimes.length, ...engineResult, baselineN: priorN, minSamples: MIN_SAMPLES });
});

/** GET current baseline summary for a user (dashboard). */
router.get("/status/:userId", async (req, res) => {
  const userId = req.params.userId;
  const b = (await getBaseline(userId)) || { n: 0 };
  const coldStart = (b.n || 0) < MIN_SAMPLES;
  res.json({
    userId,
    baselineN: b.n || 0,
    minSamples: MIN_SAMPLES,
    coldStart,
    lastTrust: b.lastTrust ?? null,
    lastReason: b.lastReason ?? null,
    progress: Math.min(1, (b.n || 0) / MIN_SAMPLES),
  });
});

export default router;
