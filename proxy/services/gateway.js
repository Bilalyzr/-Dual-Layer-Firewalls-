/**
 * Gateway service (Tier 2 · EPIC G) — the public edge.
 *
 * Terminates client requests: owns sessions/auth, serves the SSE stream off the
 * shared Redis bus, exposes the alerts/metrics read models, and reverse-proxies
 * /api/chat + /api/inspect → firewall-svc and /api/biometric + /api/shap →
 * biometric-svc. Scale horizontally behind a load balancer; the Redis bus keeps
 * every replica's SSE clients in sync.
 */
import { startService } from "../bootstrap.js";

startService("gateway");
