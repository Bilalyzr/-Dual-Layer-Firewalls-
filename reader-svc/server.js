/**
 * EPIC E — reader-svc: the sandboxed Reader-Agent as its own service.
 *
 * A tiny Express app that does ONE thing: accept untrusted text, call the LLM
 * with the Reader system prompt, validate the output against READER_OUTPUT, and
 * return strict JSON. Nothing else. No Mongo, no tools, no proxy internals.
 *
 * Hardening (applied in docker-compose):
 *   - read_only filesystem (only writes are to tmpfs /tmp)
 *   - cap_drop: ALL  +  no-new-privileges
 *   - non-root user
 *   - dedicated egress network: may reach ONLY the LLM endpoint — not Mongo,
 *     not the engine, not the proxy
 *
 * This is real isolation: a prompt-injection that compromises the Reader cannot
 * reach internal services. Its only possible outbound call is the LLM API.
 */
import express from "express";
import cors from "cors";

// The Reader logic is SHARED with the proxy — same source so the behavior stays
// identical. We import the pure functions directly from the proxy agents dir.
import { read } from "../proxy/agents/readerAgent.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
  res.json({
    service: "reader-svc",
    role: "reader",
    description: "Sandboxed Reader-Agent. Accepts untrusted text → returns validated JSON.",
    tools: [], // readers have NO tools — the core Trifecta guarantee
  });
});

app.get("/health", (_req, res) => res.json({ status: "ok" }));

/**
 * POST /read  { content: string }
 * → { json, raw, valid, errors, attempts, simulated }
 */
app.post("/read", async (req, res) => {
  const content = req.body?.content;
  if (!content || typeof content !== "string" || !content.trim()) {
    return res.status(400).json({ error: "missing 'content'" });
  }
  const result = await read(content);
  res.json(result);
});

const PORT = parseInt(process.env.READER_PORT || "8012", 10);
app.listen(PORT, () => {
  console.log(`[reader-svc] sandboxed Reader-Agent listening on :${PORT} (no tools, no DB)`);
});
