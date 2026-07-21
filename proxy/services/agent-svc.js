/**
 * Agent service (Tier 2 · EPIC G) — the Trifecta Reader→Validator→Actor flow.
 *
 * Exposes only the internal /internal/agent/run endpoint (never fronted by the
 * gateway). Agent-stage audit events are published to the shared event bus so the
 * dashboard sees the full reasoning chain. Delegates untrusted-content reading to
 * the sandboxed reader-svc (EPIC E) via READER_SVC_URL.
 */
import { startService } from "../bootstrap.js";

startService("agent");
