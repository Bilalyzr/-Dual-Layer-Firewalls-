/**
 * /api/alerts — recent firewall + outbound alerts for dashboard history (Req 4.1).
 * /api/samples — low-confidence allowed traffic retained for review (Req 1.5).
 */
import { Router } from "express";
import { recentAlerts, sampleCount, stats } from "../db/mongo.js";
import { engineHealth } from "../firewall/mlClient.js";
import { llmConfig } from "../llm/client.js";

const router = Router();

router.get("/", async (_req, res) => {
  const alerts = await recentAlerts(50);
  res.json({ alerts });
});

router.get("/samples", async (_req, res) => {
  res.json({ samples: await sampleCount() });
});

/** Operational status: modes, thresholds, engine + LLM + db health. */
router.get("/status", async (_req, res) => {
  const dbStats = await stats();
  const engineUp = await engineHealth();
  res.json({
    firewall: {
      mode: (process.env.FIREWALL_MODE || "shadow").toLowerCase(),
      threshold: parseFloat(process.env.FIREWALL_THRESHOLD || "0.65"),
      adversarialSampleRate: parseFloat(process.env.ADVERSARIAL_SAMPLE_RATE || "0.05"),
    },
    biometric: {
      mode: (process.env.BIOMETRIC_MODE || "shadow").toLowerCase(),
      minSamples: parseInt(process.env.BIOMETRIC_MIN_SAMPLES || "120", 10),
      zThreshold: parseFloat(process.env.BIOMETRIC_Z_THRESHOLD || "2.5"),
    },
    engine: { up: engineUp },
    llm: llmConfig(),
    db: dbStats,
    tiers: {
      current: "Tier 1 + Tier 2 (Phases 1–5, Epics A–H)",
      implemented: [
        "Phase 4: LSTM + RF/GB/MLP biometric ensemble + async SHAP",
        "Phase 5: Trifecta Reader→Validator→Actor agents (schema validation + RBAC)",
        "Epic A/B: signed sessions + FIDO2/WebAuthn step-up MFA enforcement",
        "Epic C: Llama Guard safety layer (input + output)",
        "Epic D: AES-256 at-rest field encryption + TLS 1.3 edge",
        "Epic E: OS-level sandboxed reader-svc (read-only, cap-drop, egress isolation)",
        "Epic F: real RBAC-gated Actor tool integrations + per-tool audit trail",
        "Epic G: distributed microservices (gateway/firewall/agent/biometric + Redis bus)",
      ],
      deferred: [],
    },
  });
});

export default router;
