/**
 * llm_speed_check.mjs — time the LLM client hop-by-hop the way a real chat
 * request experiences it. Run with the same env the proxy uses:
 *
 *   node scripts/llm_speed_check.mjs
 *
 * Shows per-call wall time for 3 consecutive calls so the circuit breaker's
 * effect is visible (call 3+ skips the dead primary entirely).
 */
import { readFileSync } from "node:fs";
import { chatCompletion } from "../proxy/llm/client.js";

// load .env.local / .env like the proxy does
for (const f of [".env.local", ".env"]) {
  try {
    for (const line of readFileSync(f, "utf-8").split(/\r?\n/)) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    }
  } catch {}
}

for (let i = 1; i <= 3; i++) {
  const t0 = Date.now();
  try {
    const r = await chatCompletion("Reply with exactly: ok");
    const ms = Date.now() - t0;
    const via = r.via || (r.simulated ? "simulated" : "primary");
    console.log(`call ${i}: ${(ms / 1000).toFixed(1)}s via=${via} content="${String(r.content).slice(0, 40)}"`);
  } catch (e) {
    console.log(`call ${i}: ${((Date.now() - t0) / 1000).toFixed(1)}s ERROR ${String(e.message).slice(0, 80)}`);
  }
}
