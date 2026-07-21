/**
 * MongoDB data layer (PRD §4 Database Layer).
 *
 * Collections:
 *   alerts       — firewall blocks/warnings (Req 1.5, 4.1)
 *   samples      — low-confidence allowed traffic retained for review (Req 1.5)
 *   baselines    — per-user keystroke history ("typing DNA") (Req 3.1)
 *   biometric_events — trust-score decisions over time (Req 4.2)
 *   sessions     — signed server-side sessions + trustState (Tier 2 EPIC A)
 *   credentials  — WebAuthn/FIDO2 passkeys per user (Tier 2 EPIC B)
 *
 * Exposes a thin repository. Everything degrades gracefully when Mongo is
 * unavailable: in-memory maps keep the demo working, and a flag is surfaced
 * on /metrics so the operator can see persistence is degraded.
 */
import { MongoClient } from "mongodb";

const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URI_LOCAL || "mongodb://localhost:27017/firewall";

// EPIC D: at-rest field encryption (transparent when APP_ENCRYPTION_KEY unset).
import {
  encryptFields,
  decryptFields,
  SENSITIVE_ALERT_FIELDS,
  SENSITIVE_SAMPLE_FIELDS,
  SENSITIVE_BASELINE_FIELDS,
} from "./encryption.js";

let client = null;
let db = null;
let connected = false;

// In-memory fallbacks (used if Mongo is down — demo-safe).
const mem = {
  alerts: [],
  samples: [],
  baselines: new Map(),
  biometric_events: [],
  sessions: new Map(),      // sessionId -> session doc
  credentials: [],          // WebAuthn credential docs
};

export async function connect() {
  if (connected) return db;
  try {
    client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 2000 });
    await client.connect();
    db = client.db();
    await Promise.all([
      db.collection("alerts").createIndex({ ts: -1 }),
      db.collection("samples").createIndex({ ts: -1 }),
      db.collection("baselines").createIndex({ userId: 1 }, { unique: true }),
      db.collection("biometric_events").createIndex({ ts: -1 }),
      db.collection("sessions").createIndex({ sessionId: 1 }, { unique: true }),
      db.collection("credentials").createIndex({ credentialID: 1 }, { unique: true }),
      db.collection("credentials").createIndex({ userId: 1 }),
    ]);
    connected = true;
    console.log("[db] connected to MongoDB");
  } catch (err) {
    connected = false;
    console.warn(`[db] mongo unavailable, using in-memory fallback: ${err.message}`);
  }
  return db;
}

export function isPersistent() {
  return connected;
}

// ---- Alerts (firewall) --------------------------------------------------- //
export async function insertAlert(doc) {
  const full = { ts: new Date(), ...encryptFields(doc, SENSITIVE_ALERT_FIELDS) };
  if (connected) await db.collection("alerts").insertOne(full);
  mem.alerts.unshift(full);
  mem.alerts = mem.alerts.slice(0, 500);
  return full;
}

export async function recentAlerts(limit = 50) {
  const rows = connected
    ? await db.collection("alerts").find().sort({ ts: -1 }).limit(limit).toArray()
    : mem.alerts.slice(0, limit);
  return rows.map((r) => decryptFields(r, SENSITIVE_ALERT_FIELDS));
}

// ---- Low-confidence samples (Req 1.5) ------------------------------------ //
export async function insertSample(doc) {
  const full = { ts: new Date(), ...encryptFields(doc, SENSITIVE_SAMPLE_FIELDS) };
  if (connected) await db.collection("samples").insertOne(full);
  mem.samples.unshift(full);
  mem.samples = mem.samples.slice(0, 500);
  return full;
}

export async function sampleCount() {
  if (connected) return await db.collection("samples").countDocuments();
  return mem.samples.length;
}

// ---- Biometric baselines ------------------------------------------------- //
export async function getBaseline(userId) {
  const row = connected
    ? await db.collection("baselines").findOne({ userId })
    : mem.baselines.get(userId) || null;
  return row ? decryptFields(row, SENSITIVE_BASELINE_FIELDS) : null;
}

export async function upsertBaseline(userId, patch) {
  const enc = encryptFields(patch, SENSITIVE_BASELINE_FIELDS);
  if (connected) {
    await db.collection("baselines").updateOne(
      { userId },
      { $set: { userId, updatedAt: new Date(), ...enc } },
      { upsert: true }
    );
    return await getBaseline(userId);
  }
  const prev = mem.baselines.get(userId) || { userId };
  const next = { ...prev, ...enc, updatedAt: new Date() };
  mem.baselines.set(userId, next);
  return decryptFields(next, SENSITIVE_BASELINE_FIELDS);
}

// ---- Biometric events (trust score history) ------------------------------ //
export async function insertBiometricEvent(doc) {
  const full = { ts: new Date(), ...doc };
  if (connected) await db.collection("biometric_events").insertOne(full);
  mem.biometric_events.unshift(full);
  mem.biometric_events = mem.biometric_events.slice(0, 500);
  return full;
}

// ---- Sessions (Tier 2 EPIC A) -------------------------------------------- //
export async function createSessionDoc(doc) {
  if (connected) await db.collection("sessions").insertOne(doc);
  mem.sessions.set(doc.sessionId, doc);
  return doc;
}

export async function getSessionDoc(sessionId) {
  if (connected) return await db.collection("sessions").findOne({ sessionId });
  return mem.sessions.get(sessionId) || null;
}

export async function updateSessionDoc(sessionId, patch) {
  if (connected) {
    await db.collection("sessions").updateOne(
      { sessionId },
      { $set: { updatedAt: new Date(), ...patch } }
    );
    return await getSessionDoc(sessionId);
  }
  const prev = mem.sessions.get(sessionId);
  if (!prev) return null;
  const next = { ...prev, ...patch, updatedAt: new Date() };
  mem.sessions.set(sessionId, next);
  return next;
}

// ---- WebAuthn credentials (Tier 2 EPIC B) -------------------------------- //
export async function insertCredential(doc) {
  const full = { createdAt: new Date(), ...doc };
  if (connected) await db.collection("credentials").insertOne(full);
  mem.credentials.push(full);
  return full;
}

export async function getCredentialsByUser(userId) {
  if (connected) return await db.collection("credentials").find({ userId }).toArray();
  return mem.credentials.filter((c) => c.userId === userId);
}

export async function getCredentialById(credentialID) {
  if (connected) return await db.collection("credentials").findOne({ credentialID });
  return mem.credentials.find((c) => c.credentialID === credentialID) || null;
}

export async function updateCredentialCounter(credentialID, counter) {
  if (connected) {
    await db.collection("credentials").updateOne(
      { credentialID },
      { $set: { counter, lastUsedAt: new Date() } }
    );
    return;
  }
  const c = mem.credentials.find((x) => x.credentialID === credentialID);
  if (c) {
    c.counter = counter;
    c.lastUsedAt = new Date();
  }
}

// ---- Aggregate stats for /metrics --------------------------------------- //
export async function stats() {
  const s = { persistent: connected };
  if (connected) {
    s.alerts = await db.collection("alerts").countDocuments();
    s.samples = await db.collection("samples").countDocuments();
    s.baselines = await db.collection("baselines").countDocuments();
    s.biometric_events = await db.collection("biometric_events").countDocuments();
    s.sessions = await db.collection("sessions").countDocuments();
    s.credentials = await db.collection("credentials").countDocuments();
  } else {
    s.alerts = mem.alerts.length;
    s.samples = mem.samples.length;
    s.baselines = mem.baselines.size;
    s.biometric_events = mem.biometric_events.length;
    s.sessions = mem.sessions.size;
    s.credentials = mem.credentials.length;
  }
  return s;
}
