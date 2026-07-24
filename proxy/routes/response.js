/**
 * /api/response — ops surface for the Tier-3 auto-response engine (Epic C).
 *
 *   GET  /api/response/status      — mode, kill switch, thresholds
 *   GET  /api/response/bans        — active IP + CIDR bans and top offenders
 *   POST /api/response/ban         — manual ban   { ip | cidr, ttl?, reason? }
 *   POST /api/response/unban       — lift a ban    { ip | cidr }
 *   POST /api/response/killswitch  — engage/release { enabled: true|false }
 *
 * Optional protection: if OPS_TOKEN is set, every call must send a matching
 * `x-ops-token` header. Unset (demo default) leaves the surface open, consistent
 * with the rest of the dashboard's read/ops endpoints.
 */
import { Router } from "express";
import {
  responseMode,
  killSwitchEngaged,
  setKillSwitch,
  listBans,
  banIp,
  banCidr,
  unbanIp,
  unbanCidr,
} from "../response/banStore.js";
import { parseCidr } from "../lib/cidr.js";

const router = Router();

function opsGuard(req, res, next) {
  const required = process.env.OPS_TOKEN;
  if (!required) return next();
  if (req.headers["x-ops-token"] === required) return next();
  return res.status(403).json({ error: "forbidden", detail: "invalid or missing x-ops-token" });
}
router.use(opsGuard);

router.get("/status", (_req, res) => {
  res.json({
    mode: responseMode(),
    killSwitch: killSwitchEngaged(),
    thresholds: {
      autoBanThreshold: parseInt(process.env.AUTO_BAN_THRESHOLD || "5", 10),
      autoBanWindowSec: parseInt(process.env.AUTO_BAN_WINDOW || "600", 10),
      autoBanTtlSec: parseInt(process.env.AUTO_BAN_TTL || "3600", 10),
      cidrThreshold: parseInt(process.env.AUTO_BAN_CIDR_THRESHOLD || "3", 10),
    },
  });
});

router.get("/bans", async (_req, res) => {
  res.json(await listBans());
});

router.post("/ban", async (req, res) => {
  const { ip, cidr, ttl, reason } = req.body || {};
  const ttlSec = ttl ? parseInt(ttl, 10) : undefined;
  if (cidr) {
    if (!parseCidr(cidr)) return res.status(400).json({ error: "invalid cidr" });
    const banned = await banCidr(cidr, ttlSec, reason || "manual");
    return res.json({ ok: true, banned });
  }
  if (ip) {
    const banned = await banIp(ip, ttlSec, reason || "manual");
    if (!banned) return res.status(400).json({ error: "invalid ip" });
    return res.json({ ok: true, banned });
  }
  return res.status(400).json({ error: "provide 'ip' or 'cidr'" });
});

router.post("/unban", async (req, res) => {
  const { ip, cidr } = req.body || {};
  if (cidr) return res.json({ ok: true, removed: await unbanCidr(cidr) });
  if (ip) return res.json({ ok: true, removed: await unbanIp(ip) });
  return res.status(400).json({ error: "provide 'ip' or 'cidr'" });
});

router.post("/killswitch", (req, res) => {
  const { enabled } = req.body || {};
  if (typeof enabled !== "boolean") return res.status(400).json({ error: "'enabled' must be boolean" });
  const state = setKillSwitch(enabled);
  res.json({ ok: true, killSwitch: state });
});

export default router;
