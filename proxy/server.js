/**
 * Dual-Layer AI Firewall — Node.js Proxy (PRD §4 Proxy Layer).
 *
 * Default entrypoint: boots the monolith (role "all") — every router in one
 * process, the original single-container behavior. Set SERVICE_ROLE to run a
 * single slice instead (gateway | firewall | agent | biometric); the dedicated
 * entrypoints in services/ do exactly that for the distributed compose topology
 * (Tier 2 · EPIC G). All roles share this codebase, Mongo, and SESSION_SECRET.
 */
import { startService } from "./bootstrap.js";

startService(process.env.SERVICE_ROLE || "all");
