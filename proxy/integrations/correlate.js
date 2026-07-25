/**
 * Tier 3 · Wave 2 · Epic D — threat correlation (coordinated-campaign detection).
 *
 * A single block is an event; a *pattern* across blocks is a campaign. This scans
 * recent alerts for the two coordination signals called out in §12.1:
 *
 *   • Distributed campaign — one attack SIGNATURE reused across many distinct IPs
 *     (a botnet/proxy pool running the same playbook). "Same typing pattern /
 *     different IPs" generalizes to same structural signature / different IPs.
 *   • Account-takeover / spray — one IP hitting many distinct USERS (credential
 *     spraying or a shared exit node probing accounts).
 *
 * Pure read model over recentAlerts — no new storage, no request-path cost. Callers
 * (routes/intel.js, a scheduled job, the dashboard) get a ranked list of campaigns
 * with the evidence that supports each flag.
 */
import { recentAlerts } from "../db/mongo.js";

const distinctIpThreshold = () => parseInt(process.env.CORRELATE_IP_THRESHOLD || "3", 10);
const distinctUserThreshold = () => parseInt(process.env.CORRELATE_USER_THRESHOLD || "3", 10);

function add(map, key, value) {
  if (!key) return;
  let set = map.get(key);
  if (!set) map.set(key, (set = new Set()));
  if (value) set.add(value);
}

/**
 * Analyze recent alerts for coordinated campaigns.
 * @param {{ limit?: number }} opts
 * @returns {Promise<{ generatedAt:string, scanned:number, campaigns:object[] }>}
 */
export async function correlateThreats({ limit = 300 } = {}) {
  const alerts = await recentAlerts(limit);

  const ipsBySignature = new Map(); // signature -> Set<ip>
  const usersByIp = new Map(); // ip -> Set<userId>
  const countBySignature = new Map();
  const countByIp = new Map();

  // Shadow-mode detections count too — they are real hits, just not enforced.
  for (const a of alerts) {
    const ip = a.forensics?.clientIp || null;
    const sig = a.signature || null;
    const user = a.userId || null;
    if (sig) {
      add(ipsBySignature, sig, ip);
      countBySignature.set(sig, (countBySignature.get(sig) || 0) + 1);
    }
    if (ip) {
      add(usersByIp, ip, user);
      countByIp.set(ip, (countByIp.get(ip) || 0) + 1);
    }
  }

  const campaigns = [];

  for (const [signature, ipSet] of ipsBySignature) {
    if (ipSet.size >= distinctIpThreshold()) {
      campaigns.push({
        type: "distributed-signature",
        severity: ipSet.size >= distinctIpThreshold() * 2 ? "high" : "medium",
        signature,
        distinctIps: ipSet.size,
        events: countBySignature.get(signature) || 0,
        ips: [...ipSet].slice(0, 25),
        rationale: `Signature ${signature} reused across ${ipSet.size} distinct IPs — coordinated/distributed attack.`,
      });
    }
  }

  for (const [ip, userSet] of usersByIp) {
    if (userSet.size >= distinctUserThreshold()) {
      campaigns.push({
        type: "account-spray",
        severity: userSet.size >= distinctUserThreshold() * 2 ? "high" : "medium",
        ip,
        distinctUsers: userSet.size,
        events: countByIp.get(ip) || 0,
        users: [...userSet].slice(0, 25),
        rationale: `IP ${ip} targeted ${userSet.size} distinct users — credential spraying / account probing.`,
      });
    }
  }

  // Rank: high severity first, then by breadth of the campaign.
  campaigns.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === "high" ? -1 : 1;
    return (b.distinctIps || b.distinctUsers || 0) - (a.distinctIps || a.distinctUsers || 0);
  });

  return {
    generatedAt: new Date().toISOString(),
    scanned: alerts.length,
    coordinated: campaigns.length > 0,
    campaigns,
  };
}
