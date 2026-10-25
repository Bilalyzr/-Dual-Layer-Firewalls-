/**
 * EPIC I — Append-only, hash-chained audit log (tamper-evident).
 *
 * Every security-significant event (block, step-up, ban, consent change, erasure)
 * is appended as a link in a hash chain: each entry's `prev` = SHA-256 of the
 * previous entry. Any after-the-fact tampering breaks the chain — auditors can
 * verify integrity by replaying it.
 *
 * Store is in-process (ring buffer); production would persist each entry to an
 * append-only Mongo collection or a WORM store (S3 Object Lock). The chain logic
 * is identical either way.
 */
import crypto from "node:crypto";

const MAX = 10000;
const GENESIS_HASH = "0".repeat(64);
const _chain = []; // [{ index, ts, type, payload, prev, hash }]
let _nextIndex = 0;
let _anchorPrev = GENESIS_HASH;

function _hash(entry) {
  // hash covers everything except the hash field itself
  const material = JSON.stringify({ ...entry, hash: undefined });
  return crypto.createHash("sha256").update(material).digest("hex");
}

/** Append a tamper-evident entry. Returns the entry (with its hash). */
export function appendAudit(type, payload) {
  const prev = _chain.length ? _chain[_chain.length - 1].hash : _anchorPrev;
  const entry = {
    index: _nextIndex++,
    ts: new Date().toISOString(),
    type,
    payload,
    prev,
  };
  entry.hash = _hash(entry);
  _chain.push(entry);
  if (_chain.length > MAX) {
    const evicted = _chain.shift(); // ring buffer: advance anchor to evicted entry's hash
    _anchorPrev = evicted.hash;
  }
  return entry;
}

/** Verify the whole chain is intact (no tampering). Returns {valid, brokenAt?} */
export function verifyChain() {
  let prev = _anchorPrev;
  for (let i = 0; i < _chain.length; i++) {
    const e = _chain[i];
    if (e.prev !== prev) return { valid: false, brokenAt: i };
    const recomputed = _hash({ ...e, hash: undefined });
    if (recomputed !== e.hash) return { valid: false, brokenAt: i };
    prev = e.hash;
  }
  return { valid: true, length: _chain.length };
}

/** Read-only copy of the chain (most-recent first). */
export function auditChain(limit = 100) {
  return _chain.slice(-limit).reverse();
}

/** Test hook. */
export function _resetChain() {
  _chain.length = 0;
  _nextIndex = 0;
  _anchorPrev = GENESIS_HASH;
}
