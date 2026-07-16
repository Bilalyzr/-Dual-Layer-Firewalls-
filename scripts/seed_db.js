/**
 * seed_db.js — optional seed for demo threat taxonomies.
 *
 * Mostly the system is self-populating (alerts/samples/baselines accrue as
 * traffic flows). This script inserts a handful of representative OWASP LLM
 * Top 10 reference entries so the dashboard isn't empty on first load.
 *
 *   node scripts/seed_db.js                       (uses MONGO_URI / MONGO_URI_LOCAL)
 *   PROXY_URL=http://localhost:4000 node ...      (alternatively POST via proxy)
 */
import { MongoClient } from "mongodb";

const URI =
  process.env.MONGO_URI ||
  process.env.MONGO_URI_LOCAL ||
  "mongodb://localhost:27017/firewall";

const REFERENCE_THREATS = [
  { category: "LLM01", title: "Prompt Injection", note: "Direct or indirect override of model instructions." },
  { category: "LLM02", title: "Sensitive Information Disclosure", note: "Exposure of secrets / PII in output." },
  { category: "LLM03", title: "Supply Chain", note: "Vulnerable components / plugins in the LLM stack." },
  { category: "LLM04", title: "Data and Model Poisoning", note: "Manipulation of training / fine-tuning data." },
  { category: "LLM05", title: "Improper Output Handling", note: "Unvalidated LLM output passed downstream." },
  { category: "LLM06", title: "Excessive Agency", note: "Agents with too much authority / tool access." },
  { category: "LLM07", title: "System Prompt Leakage", note: "Extraction of the system prompt." },
  { category: "LLM08", title: "Vector and Embedding Weaknesses", note: "Poisoned retrieval sources (RAG)." },
  { category: "LLM09", title: "Misinformation", note: "Plausible but false / hallucinated output." },
  { category: "LLM10", title: "Unbounded Consumption", note: "Resource exhaustion via heavy requests." },
];

async function main() {
  const client = new MongoClient(URI, { serverSelectionTimeoutMS: 3000 });
  try {
    await client.connect();
    const db = client.db();
    const col = db.collection("threat_taxonomy");
    for (const t of REFERENCE_THREATS) {
      await col.updateOne(
        { category: t.category },
        { $set: { ...t, seededAt: new Date() } },
        { upsert: true }
      );
    }
    const count = await col.countDocuments();
    console.log(`[seed] upserted ${REFERENCE_THREATS.length} OWASP LLM Top 10 entries (total ${count}) into ${db.databaseName}.threat_taxonomy`);
  } catch (err) {
    console.error(`[seed] failed: ${err.message}`);
    console.error("       is MongoDB running? Try: docker compose up -d mongo");
    process.exit(1);
  } finally {
    await client.close();
  }
}

main();
