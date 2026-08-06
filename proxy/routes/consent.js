/**
 * EPIC I — /api/consent endpoint (the privacy gate for behavioral capture).
 *
 * The consent *store* already exists (`compliance/consent.js`) but nothing let
 * the client read or set it — so mouse/touch/fingerprint capture had no way to
 * be lawfully activated. This route is that missing surface:
 *
 *   GET  /api/consent/:userId         → current per-category grants + catalog
 *   POST /api/consent                 → { userId, category, granted }
 *
 * Each write is appended to the audit chain so we can prove when/what/version
 * the user consented to (PRD §9). Categories mirror `CATEGORIES` in
 * compliance/consent.js.
 */
import { Router } from "express";
import { getConsent, setConsent, CATEGORIES, CONSENT_VERSION } from "../compliance/consent.js";
import { appendAudit } from "../compliance/auditChain.js";

const router = Router();

// Categories a client may toggle. `security_logs` is operational, not behavioral,
// so it's exposed but grouped separately in the UI.
const TOGGLEABLE = Object.keys(CATEGORIES);

router.get("/:userId", (req, res) => {
  const userId = req.params.userId || "anon";
  const raw = getConsent(userId);
  // Normalize into a flat { category: boolean } map plus the full records.
  const granted = {};
  for (const cat of TOGGLEABLE) granted[cat] = Boolean(raw[cat]?.granted);
  res.json({
    userId,
    version: CONSENT_VERSION,
    categories: CATEGORIES,
    granted,
    records: raw,
  });
});

router.post("/", (req, res) => {
  const userId = req.body?.userId || "anon";
  const category = req.body?.category;
  const granted = Boolean(req.body?.granted);
  if (!category || !TOGGLEABLE.includes(category)) {
    return res.status(400).json({
      error: "invalid_category",
      message: `category must be one of: ${TOGGLEABLE.join(", ")}`,
    });
  }
  const record = setConsent(userId, category, granted);
  appendAudit("consent", { userId, category, granted, version: record.version, ts: record.ts });
  res.json({ userId, category, granted, version: record.version, ts: record.ts });
});

export default router;
