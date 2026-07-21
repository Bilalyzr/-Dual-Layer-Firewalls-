/**
 * Biometric service (Tier 2 · EPIC G) — Layer-2 keystroke scoring + SHAP.
 *
 * Runs /api/biometric (telemetry ingestion, rolling baseline, z-score/ensemble
 * scoring, and the EPIC B step-up enforcement hook) plus /api/shap. Marks
 * sessions `stepUpRequired` in the shared session store when trust collapses.
 */
import { startService } from "../bootstrap.js";

startService("biometric");
