/**
 * EPIC D — AES-256-GCM field-level encryption for sensitive data at rest.
 *
 * Protects prompt snippets in alerts/samples and keystroke timing in baselines,
 * so a Mongo dump / backup doesn't expose raw biometric "typing DNA" or user
 * prompts. This is application-level encryption (the PRD's "or" option) — it
 * works with vanilla MongoDB Community, no Atlas/Enterprise requirement.
 *
 * Design:
 *   - Master key from APP_ENCRYPTION_KEY (32 bytes, base64). If unset, encryption
 *     is DISABLED (transparent pass-through) so local dev/demo keeps working.
 *   - Per-field random IV (12 bytes) + auth tag (16 bytes) — standard GCM.
 *   - Wire format: "enc:v1:" + base64(iv || ciphertext || tag).
 *   - The helper is FIELD-aware: it encrypts only the sensitive string fields of
 *     a doc, leaving metadata (ts, userId, category) in plaintext so queries/indexes
 *     still work. Encrypted fields are listed in SENSITIVE_FIELDS below.
 */
import crypto from "node:crypto";

const KEY_ENV = "APP_ENCRYPTION_KEY";
const PREFIX = "enc:v1:";

// Fields that carry sensitive content (prompts, biometric timing, reasoning).
// Indexed/metadata fields (userId, ts, category, mode, blocked) stay plaintext.
export const SENSITIVE_ALERT_FIELDS = ["prompt", "label", "reasons", "snippets"];
export const SENSITIVE_SAMPLE_FIELDS = ["prompt"];
export const SENSITIVE_BASELINE_FIELDS = ["dwellHistory", "flightHistory"];

let _key = null; // Buffer (32 bytes) or false when disabled.

function loadKey() {
  if (_key !== null) return _key;
  const b64 = process.env[KEY_ENV];
  if (!b64) return (_key = false); // disabled
  // Accept raw 32-byte base64 OR a 64-char hex string OR a passphrase (derive).
  let buf;
  try {
    buf = Buffer.from(b64, "base64");
    if (buf.length === 32) return (_key = buf);
    if (b64.length === 64) {
      const hex = Buffer.from(b64, "hex");
      if (hex.length === 32) return (_key = hex);
    }
  } catch { /* fall through to derive */ }
  // Derive a stable key from a passphrase via scrypt — supports any-length input.
  _key = crypto.scryptSync(b64, "dlf-fixed-salt", 32);
  return _key;
}

/** Test hook: reset the cached key so env changes take effect. */
export function __resetKeyCacheForTests() {
  _key = null;
}

/** True when a usable master key is configured. */
export function encryptionEnabled() {
  return !!loadKey();
}

/** Encrypt a single string. Returns the prefixed wire format, or the original
 *  string unchanged when encryption is disabled or the value isn't a string. */
export function encryptString(plain) {
  const key = loadKey();
  if (!key || typeof plain !== "string" || plain.length === 0) return plain;
  if (plain.startsWith(PREFIX)) return plain; // idempotent
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, ct, tag]).toString("base64");
}

/** Decrypt a string produced by encryptString. Returns the original plaintext,
 *  or the input unchanged when disabled / not encrypted / tampered (fail-safe). */
export function decryptString(enc) {
  const key = loadKey();
  if (!key || typeof enc !== "string" || !enc.startsWith(PREFIX)) return enc;
  try {
    const buf = Buffer.from(enc.slice(PREFIX.length), "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(buf.length - 16);
    const ct = buf.subarray(12, buf.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    // Tampered or wrong key — return the ciphertext rather than crashing callers.
    return enc;
  }
}

/**
 * Encrypt configured sensitive fields on a doc (returns a shallow copy).
 * @param {object} doc
 * @param {string[]} fields  which keys to encrypt
 */
export function encryptFields(doc, fields) {
  if (!doc || typeof doc !== "object" || !encryptionEnabled()) return doc;
  const out = { ...doc };
  for (const f of fields) {
    if (f in out) {
      const v = out[f];
      if (typeof v === "string") out[f] = encryptString(v);
      else if (Array.isArray(v)) out[f] = v.map((x) => (typeof x === "string" ? encryptString(x) : x));
    }
  }
  return out;
}

/** Decrypt configured sensitive fields on a doc (returns a shallow copy). */
export function decryptFields(doc, fields) {
  if (!doc || typeof doc !== "object" || !encryptionEnabled()) return doc;
  const out = { ...doc };
  for (const f of fields) {
    if (f in out) {
      const v = out[f];
      if (typeof v === "string") out[f] = decryptString(v);
      else if (Array.isArray(v)) out[f] = v.map((x) => (typeof x === "string" ? decryptString(x) : x));
    }
  }
  return out;
}
