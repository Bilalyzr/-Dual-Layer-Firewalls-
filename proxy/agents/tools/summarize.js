/**
 * EPIC F — `summarize` tool adapter.
 *
 * This one is inherently a no-op side-effect (the actual summarization happened
 * in the Reader). The Actor uses it to "record" that a summary action was taken
 * — so the audit trail has the tool call, but there's no external API to hit.
 * If SUMMARY_INDEX_URL is set, it POSTs the topic to an indexing service for
 * real persistence; otherwise it's mock.
 */
import { recordCall } from "./_audit.js";

export async function summarize(args) {
  const topic = String(args?.topic || "").slice(0, 120);
  recordCall("summarize", { length: topic.length });

  const indexUrl = process.env.SUMMARY_INDEX_URL;
  if (indexUrl) {
    try {
      const r = await fetch(indexUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ topic }),
        signal: AbortSignal.timeout(5000),
      });
      return {
        tool: "summarize",
        ok: r.ok,
        mode: "index",
        result: `Summary of "${topic}" recorded (index ${r.status}).`,
      };
    } catch {
      // fall through to mock
    }
  }

  return {
    tool: "summarize",
    ok: true,
    mode: "mock",
    result: `Summary of "${topic}" recorded.`,
  };
}

export const config = {
  name: "summarize",
  rateLimit: { windowMs: 60_000, max: 10 },
  requiresCreds: ["SUMMARY_INDEX_URL"],
};
