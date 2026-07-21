/**
 * Firewall service (Tier 2 · EPIC G) — the Layer-1 pipeline.
 *
 * Runs /api/chat + /api/inspect: heuristics + ML classifier + Llama Guard, the
 * outbound integrity check, and (via AGENT_SVC_URL) delegation of agentic prompts
 * to agent-svc. Stateless and CPU-bound — the service you scale out first
 * (`docker compose -f docker-compose.micro.yml up --scale firewall-svc=3`).
 */
import { startService } from "../bootstrap.js";

startService("firewall");
