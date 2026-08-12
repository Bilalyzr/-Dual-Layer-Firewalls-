/**
 * /api/auth/face — Face authentication endpoints (PRD §25 factor 2).
 *
 *   POST /enroll  — store the user's 128-d face descriptor
 *   POST /verify  — compare a new descriptor against the stored one (Euclidean distance)
 *
 * Face descriptors are 128-d Float32 vectors from face-api.js.
 * Match threshold: 0.6 (standard for face recognition — lower = stricter).
 */
import { Router } from "express";
import { appendAudit } from "../compliance/auditChain.js";
import { publish } from "../middleware/eventBus.js";

const router = Router();
const FACE_THRESHOLD = 0.6;

// In-process store: userId -> { descriptor: number[128], enrolledAt: Date }
const _faces = new Map();

function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

router.post("/enroll", (req, res) => {
  const userId = req.body?.userId;
  const descriptor = req.body?.descriptor;
  if (!userId || !Array.isArray(descriptor) || descriptor.length !== 128) {
    return res.status(400).json({ success: false, error: "missing userId or valid 128-d descriptor" });
  }
  _faces.set(userId, { descriptor: descriptor.map(Number), enrolledAt: new Date() });
  appendAudit("face_enrolled", { userId, ts: new Date() });
  publish("behavior", { user_id: userId, event_type: "face_enrolled", decision: "ENROLLED", ts: new Date() });
  res.json({ success: true, message: "Face enrolled successfully" });
});

router.post("/verify", (req, res) => {
  const userId = req.body?.userId;
  const descriptor = req.body?.descriptor;
  if (!userId || !Array.isArray(descriptor) || descriptor.length !== 128) {
    return res.status(400).json({ success: false, error: "missing userId or valid 128-d descriptor" });
  }

  const stored = _faces.get(userId);
  if (!stored) {
    appendAudit("face_verify_no_enrollment", { userId, ts: new Date() });
    return res.json({ success: false, error: "No face enrolled for this user. Enroll first." });
  }

  const distance = euclideanDistance(descriptor.map(Number), stored.descriptor);
  const match = distance <= FACE_THRESHOLD;

  appendAudit("face_verify", { userId, match, distance: +distance.toFixed(4), ts: new Date() });
  publish("behavior", { user_id: userId, event_type: "face_verify", decision: match ? "ALLOW" : "DENY", ts: new Date() });

  res.json({
    success: true,
    match,
    distance: +distance.toFixed(4),
    threshold: FACE_THRESHOLD,
    message: match ? "Face verified" : `Face does not match (distance ${distance.toFixed(3)} > ${FACE_THRESHOLD})`,
  });
});

router.get("/status/:userId", (req, res) => {
  const stored = _faces.get(req.params.userId);
  res.json({ enrolled: Boolean(stored), enrolledAt: stored?.enrolledAt || null });
});

export default router;
