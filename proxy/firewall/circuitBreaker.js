/**
 * EPIC J — Circuit breaker pattern across all backends.
 *
 * When a backend (engine, LLM, reader-svc) repeatedly fails, trip the breaker
 * so we stop hammering it and degrade gracefully instead of cascading timeouts.
 * States: CLOSED (normal) → OPEN (reject fast) → HALF_OPEN (probe one request).
 *
 * Generalizes the partial degrade behavior that today lives ad-hoc in
 * mlClient/llamaGuard. One reusable primitive.
 */

const _breakers = new Map(); // name -> { state, failures, openedAt }

const THRESHOLD = parseInt(process.env.CIRCUIT_BREAKER_THRESHOLD || "5", 10);
const RESET_MS = parseInt(process.env.CIRCUIT_BREAKER_RESET_MS || "30000", 10); // 30s

function _get(name) {
  if (!_breakers.has(name)) {
    _breakers.set(name, { state: "closed", failures: 0, openedAt: 0 });
  }
  return _breakers.get(name);
}

/** Is the circuit closed (safe to call)? */
export function canCall(name) {
  const b = _get(name);
  if (b.state === "open") {
    if (Date.now() - b.openedAt > RESET_MS) {
      b.state = "half-open";
      return true; // let one probe through
    }
    return false;
  }
  return true;
}

/** Report a success — resets the breaker. */
export function recordSuccess(name) {
  const b = _get(name);
  b.failures = 0;
  b.state = "closed";
}

/** Report a failure — may trip the breaker. */
export function recordFailure(name) {
  const b = _get(name);
  b.failures += 1;
  if (b.failures >= THRESHOLD) {
    b.state = "open";
    b.openedAt = Date.now();
  }
}

/**
 * Wrap an async call in the circuit breaker. Throws {circuit:"open"} when
 * tripped; otherwise returns/rethrows the inner call's result, recording the
 * outcome.
 */
export async function withBreaker(name, fn) {
  if (!canCall(name)) {
    const err = new Error(`circuit_open: ${name}`);
    err.circuit = "open";
    throw err;
  }
  try {
    const r = await fn();
    recordSuccess(name);
    return r;
  } catch (err) {
    // Don't trip on a benign 4xx (client error) — only on connection/5xx.
    const trip = !err.status || err.status >= 500 || /ECONNREFUSED|ETIMEDOUT|fetch failed/i.test(err.message);
    if (trip) recordFailure(name);
    throw err;
  }
}

export function breakerState(name) {
  return _get(name);
}
