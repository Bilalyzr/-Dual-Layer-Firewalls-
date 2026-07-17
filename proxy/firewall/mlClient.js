/**
 * Client for the Python Processing Engine (Req 1.3 classification + Req 3.x biometrics).
 *
 * Failures degrade gracefully: if the engine is unreachable we return a
 * "not-assessed" verdict rather than crashing the request path — matching the
 * plan's fail-open-vs-fail-closed decision (default fail-open in shadow mode).
 */

const ENGINE_URL =
  process.env.ENGINE_URL || "http://localhost:8011";

/** Classify a prompt. Returns { threatProbability, latencyMs, ready }. */
export async function classifyPrompt(text) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 2000);
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

/**
 * Score a keystroke batch against the user's baseline.
 * @param {object} p
 * @returns {Promise<object>} { trust_score, risk_score, z, cold_start, reason, ... }
 */
export async function scoreBiometricBatch(p) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 2000);
  try {
    const res = await fetch(`${ENGINE_URL}/score-batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(p),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`engine ${res.status}`);
    return await res.json();
  } catch (err) {
    return {
      trust_score: 100,
      risk_score: 0,
      z: 0,
      cold_start: true,
      reason: `engine unavailable: ${String(err.message || err)}`,
      degraded: true,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/** Liveness probe for /metrics. */
export async function engineHealth() {
  try {
    const res = await fetch(`${ENGINE_URL}/health`, { signal: AbortSignal.timeout(1000) });
    return res.ok;
  } catch {
    return false;
  }
}
