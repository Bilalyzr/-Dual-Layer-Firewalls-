/**
 * Tier 3 · Wave 2 · Epic D — STIX 2.1 indicator export.
 *
 * Publishes the firewall's observed threats as STIX 2.1 so they can be shared with
 * a community feed or ingested by a TAXII-aware SIEM/TIP. We derive two kinds of
 * Indicator from the stored alerts:
 *   • ipv4/ipv6-addr indicators  — source IPs seen on BLOCK events (from forensics)
 *   • prompt-signature indicators — structural attack signatures (Epic D fingerprint)
 * each linked to an attack-pattern SDO carrying the OWASP-LLM category.
 *
 * Deterministic IDs: an indicator's UUID is derived (UUIDv5-style, namespaced) from
 * its pattern so re-exporting the same indicator yields a stable id — a TAXII puller
 * can de-duplicate across pulls. Zero external dependencies; pure data transform.
 */
import crypto from "node:crypto";
import { recentAlerts } from "../db/mongo.js";

export function stixEnabled() {
  return String(process.env.STIX_ENABLED ?? "true").toLowerCase() !== "false";
}

// A fixed namespace so the same pattern always maps to the same id (RFC 4122 §4.3
// UUIDv5 over SHA-1, computed by hand to avoid a dependency).
const NS = Buffer.from("a1b2c3d4e5f60718293a4b5c6d7e8f90", "hex");
function uuid5(name) {
  const hash = crypto.createHash("sha1").update(NS).update(name).digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
const sdoId = (type, key) => `${type}--${uuid5(`${type}:${key}`)}`;

/** Map an OWASP-LLM code to a MITRE ATT&CK-ish label for the attack-pattern SDO. */
const CATEGORY_NAME = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM10: "Unbounded Consumption",
};

function ipObjectType(ip) {
  return ip && ip.includes(":") ? "ipv6-addr" : "ipv4-addr";
}

/**
 * Build a STIX 2.1 bundle from recent alerts. Only BLOCK/threat events contribute
 * indicators (a detection isn't an indicator we'd want to share as high-confidence).
 * @param {{ limit?: number }} opts
 * @returns {Promise<object>} a STIX bundle object
 */
export async function buildStixBundle({ limit = 200 } = {}) {
  const alerts = await recentAlerts(limit);
  const nowIso = new Date().toISOString();
  const objects = [];
  const seen = new Set();

  // One identity SDO for us as the producer.
  const identityId = sdoId("identity", "dual-layer-ai-firewall");
  objects.push({
    type: "identity",
    spec_version: "2.1",
    id: identityId,
    created: nowIso,
    modified: nowIso,
    name: "Dual-Layer AI Firewall",
    identity_class: "system",
  });

  const attackPatterns = new Map(); // category -> id (dedup)
  function attackPatternFor(category) {
    if (!category) return null;
    if (attackPatterns.has(category)) return attackPatterns.get(category);
    const id = sdoId("attack-pattern", category);
    attackPatterns.set(category, id);
    objects.push({
      type: "attack-pattern",
      spec_version: "2.1",
      id,
      created: nowIso,
      modified: nowIso,
      name: CATEGORY_NAME[category] || category,
      external_references: [{ source_name: "OWASP-LLM-Top-10", external_id: category }],
    });
    return id;
  }

  function addIndicator(pattern, name, category, ts) {
    if (seen.has(pattern)) return;
    seen.add(pattern);
    const id = sdoId("indicator", pattern);
    const created = ts || nowIso;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id,
      created_by_ref: identityId,
      created,
      modified: created,
      name,
      indicator_types: ["malicious-activity"],
      pattern_type: "stix",
      pattern,
      valid_from: created,
    });
    const apId = attackPatternFor(category);
    if (apId) {
      objects.push({
        type: "relationship",
        spec_version: "2.1",
        id: sdoId("relationship", `${id}|${apId}`),
        created,
        modified: created,
        relationship_type: "indicates",
        source_ref: id,
        target_ref: apId,
      });
    }
  }

  for (const a of alerts) {
    if (!a.blocked) continue;
    const ts = a.ts instanceof Date ? a.ts.toISOString() : a.ts;
    const ip = a.forensics?.clientIp;
    if (ip) {
      const objType = ipObjectType(ip);
      addIndicator(`[${objType}:value = '${ip}']`, `Source IP ${ip}`, a.category, ts);
    }
    if (a.signature) {
      addIndicator(
        `[x-prompt-firewall:signature = '${a.signature}']`,
        `Attack signature ${a.signature}`,
        a.category,
        ts
      );
    }
  }

  return {
    type: "bundle",
    id: `bundle--${crypto.randomUUID()}`,
    objects,
  };
}

/**
 * Minimal TAXII 2.1 collection descriptor for the pull endpoint. We expose a single
 * read-only collection of our indicators.
 */
export function taxiiCollection() {
  return {
    id: uuid5("taxii:collection:indicators"),
    title: "Dual-Layer AI Firewall — Indicators",
    description: "IP + prompt-signature indicators observed by the AI firewall (STIX 2.1).",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  };
}
