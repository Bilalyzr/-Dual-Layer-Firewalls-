/**
 * /api/intel — Tier 3 · Wave 2 · Epic D threat-intelligence surface.
 *
 *   GET /api/intel/status              — SIEM + STIX posture and forward counters
 *   GET /api/intel/stix                — export observed indicators as a STIX 2.1 bundle
 *   GET /api/intel/correlate           — coordinated-campaign detection over recent alerts
 *   GET /api/intel/signatures          — learned attack signatures + hit counts
 *   GET /api/intel/taxii/collections   — minimal TAXII 2.1 collection discovery
 *   GET /api/intel/taxii/collections/:id/objects — pull the indicators (STIX bundle)
 *
 * Read-only intelligence; reuses the same OPS_TOKEN convention as /api/response for
 * the (optional) authenticated pull. STIX/TAXII endpoints 404 when STIX_ENABLED=false.
 */
import { Router } from "express";
import { buildStixBundle, taxiiCollection, stixEnabled } from "../integrations/stix.js";
import { correlateThreats } from "../integrations/correlate.js";
import { siemStats } from "../integrations/siem.js";
import { getSignature } from "../firewall/fingerprint.js";
import { recentAlerts } from "../db/mongo.js";

const router = Router();

function opsGuard(req, res, next) {
  const required = process.env.OPS_TOKEN;
  if (!required) return next();
  if (req.headers["x-ops-token"] === required) return next();
  return res.status(403).json({ error: "forbidden", detail: "invalid or missing x-ops-token" });
}

router.get("/status", (_req, res) => {
  res.json({
    siem: siemStats(),
    stix: { enabled: stixEnabled() },
    correlation: {
      ipThreshold: parseInt(process.env.CORRELATE_IP_THRESHOLD || "3", 10),
      userThreshold: parseInt(process.env.CORRELATE_USER_THRESHOLD || "3", 10),
    },
    signatures: {
      blockEnabled: String(process.env.SIGNATURE_BLOCK_ENABLED ?? "true").toLowerCase() !== "false",
      minHits: parseInt(process.env.SIGNATURE_MIN_HITS || "3", 10),
    },
  });
});

router.get("/stix", opsGuard, async (req, res) => {
  if (!stixEnabled()) return res.status(404).json({ error: "STIX export disabled" });
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);
  const bundle = await buildStixBundle({ limit });
  res.type("application/stix+json;version=2.1").json(bundle);
});

router.get("/correlate", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "300", 10) || 300, 1000);
  res.json(await correlateThreats({ limit }));
});

router.get("/signatures", async (_req, res) => {
  // Derive the distinct signatures seen recently, then read each one's learned
  // record (hit count / category) from the store. No key-scan needed.
  const alerts = await recentAlerts(300);
  const seen = new Set();
  const out = [];
  for (const a of alerts) {
    if (!a.signature || seen.has(a.signature)) continue;
    seen.add(a.signature);
    const rec = await getSignature(a.signature);
    if (rec) out.push(rec);
  }
  out.sort((x, y) => (y.hits || 0) - (x.hits || 0));
  res.json({ count: out.length, signatures: out });
});

// ---- Minimal TAXII 2.1 pull surface -------------------------------------- //
router.get("/taxii/collections", opsGuard, (_req, res) => {
  if (!stixEnabled()) return res.status(404).json({ error: "STIX export disabled" });
  res.type("application/taxii+json;version=2.1").json({ collections: [taxiiCollection()] });
});

router.get("/taxii/collections/:id/objects", opsGuard, async (req, res) => {
  if (!stixEnabled()) return res.status(404).json({ error: "STIX export disabled" });
  const col = taxiiCollection();
  if (req.params.id !== col.id) return res.status(404).json({ error: "unknown collection" });
  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 1000);
  const bundle = await buildStixBundle({ limit });
  res.type("application/stix+json;version=2.1").json(bundle);
});

export default router;
