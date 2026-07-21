/**
 * Strict "real-only" mode (default ON).
 *
 * When enabled, the system refuses to silently fall back to simulated/mock
 * behavior: if a real backend (LLM, a tool's external service) is not configured,
 * the call fails loudly instead of returning fabricated output. Set
 * STRICT_REAL=false to re-enable the offline demo fallbacks.
 */
export function strictReal() {
  return String(process.env.STRICT_REAL ?? "true").toLowerCase() !== "false";
}
