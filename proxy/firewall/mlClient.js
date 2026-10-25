/**
 * Client for the Python Processing Engine (Req 1.3 classification + Req 3.x biometrics).
 *
 * Failures degrade gracefully: if the engine is unreachable we return a
 * "not-assessed" verdict rather than crashing the request path — matching the
 * plan's fail-open-vs-fail-closed decision (default fail-open in shadow mode).
 */

const ENGINE_URL =
  process.env.ENGINE_URL || "http://127.0.0.1:8011";

/** Classify a prompt. Returns { threatProbability, latencyMs, ready }. */
export async function classifyPrompt(text) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 4000);
  try {
    const res = await fetch(`${ENGINE_URL}/classify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`engine ${res.status}`);
    const j = await res.json();
    return {
      threatProbability: j.threat_probability ?? 0,
      latencyMs: j.latency_ms ?? 0,
      ready: j.ready !== false,
    };
  } catch (err) {
    return { threatProbability: 0, latencyMs: 0, ready: false, error: String(err.message || err) };
  } finally {
    clearTimeout(timeout);
}
}

/** Liveness probe for /metrics. */
export async function engineHealth() {
  try {
    const res = await fetch(`${ENGINE_URL}/health`, { signal: AbortSignal.timeout(2500) });
    return res.ok;
  } catch {
    return false;
  }
}
