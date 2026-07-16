/**
 * MongoDB data layer (PRD §4 Database Layer).
 *
 * Collections:
 *   alerts       — firewall blocks/warnings (Req 1.5, 4.1)
 *   samples      — low-confidence allowed traffic retained for review (Req 1.5)
 *   baselines    — per-user keystroke history ("typing DNA") (Req 3.1)
 *   biometric_events — trust-score decisions over time (Req 4.2)
 *
 * Exposes a thin repository. Everything degrades gracefully when Mongo is
 * unavailable: in-memory maps keep the demo working, and a flag is surfaced
 * on /metrics so the operator can see persistence is degraded.
 */
import { MongoClient } from "mongodb";

const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URI_LOCAL || "mongodb://localhost:27017/firewall";

let client = null;
let db = null;
let connected = false;

// In-memory fallbacks (used if Mongo is down — demo-safe).
const mem = {
  alerts: [],
  samples: [],
  baselines: new Map(),
  biometric_events: [],
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
  const full = { ts: new Date(), ...doc };
  if (connected) await db.collection("alerts").insertOne(full);
  mem.alerts.unshift(full);
  mem.alerts = mem.alerts.slice(0, 500);
  return full;
}

export async function recentAlerts(limit = 50) {
  if (connected) {
    return await db.collection("alerts").find().sort({ ts: -1 }).limit(limit).toArray();
  }
  return mem.alerts.slice(0, limit);
}

// ---- Low-confidence samples (Req 1.5) ------------------------------------ //
export async function insertSample(doc) {
  const full = { ts: new Date(), ...doc };
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
  if (connected) {
    return await db.collection("baselines").findOne({ userId });
  }
  return mem.baselines.get(userId) || null;
}

export async function upsertBaseline(userId, patch) {
  if (connected) {
    await db.collection("baselines").updateOne(
      { userId },
      { $set: { userId, updatedAt: new Date(), ...patch } },
      { upsert: true }
    );
    return await getBaseline(userId);
  }
  const prev = mem.baselines.get(userId) || { userId };
  const next = { ...prev, ...patch, updatedAt: new Date() };
  mem.baselines.set(userId, next);
  return next;
}

// ---- Biometric events (trust score history) ------------------------------ //
export async function insertBiometricEvent(doc) {
  const full = { ts: new Date(), ...doc };
  if (connected) await db.collection("biometric_events").insertOne(full);
  mem.biometric_events.unshift(full);
  mem.biometric_events = mem.biometric_events.slice(0, 500);
  return full;
}

// ---- Aggregate stats for /metrics --------------------------------------- //
export async function stats() {
  const s = { persistent: connected };
  if (connected) {
    s.alerts = await db.collection("alerts").countDocuments();
    s.samples = await db.collection("samples").countDocuments();
    s.baselines = await db.collection("baselines").countDocuments();
    s.biometric_events = await db.collection("biometric_events").countDocuments();
  } else {
    s.alerts = mem.alerts.length;
    s.samples = mem.samples.length;
    s.baselines = mem.baselines.size;
    s.biometric_events = mem.biometric_events.length;
  }
  return s;
}
