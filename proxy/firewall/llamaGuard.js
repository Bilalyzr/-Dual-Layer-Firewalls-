/**
 * Llama Guard 4 safety layer (Tier 2 · EPIC C).
 *
 * A dedicated safety-model pass on both INPUT (user prompt) and OUTPUT (LLM
 * response), complementing the regex heuristics + scikit-learn classifier. Llama
 * Guard returns a "safe" / "unsafe" verdict plus MLCommons hazard categories
 * (S1–S13); we map those to the dashboard's OWASP LLM Top-10 taxonomy.
 *
 * Hosting: any OpenAI-compatible endpoint that serves a Llama-Guard model
 *   Groq:     LLAMAGUARD_URL=https://api.groq.com/openai/v1   LLAMAGUARD_MODEL=meta-llama/llama-guard-4-12b
 *   Together: LLAMAGUARD_URL=https://api.together.xyz/v1      LLAMAGUARD_MODEL=meta-llama/Llama-Guard-4-12B
 *   Ollama:   LLAMAGUARD_URL=http://localhost:11434/v1        LLAMAGUARD_MODEL=llama-guard3
 *
 * Fail semantics (mirrors the firewall): the decision to block on a degraded
 * endpoint is left to the caller (fail-open in shadow, fail-closed in enforce) —
 * this module just reports `degraded: true` and a safe-by-default verdict.
 */

const enabled = () => /^(1|true|yes|on)$/i.test(process.env.LLAMAGUARD_ENABLED || "");
const guardUrl = () => (process.env.LLAMAGUARD_URL || process.env.LLM_BASE_URL || "").replace(/\/$/, "");
const guardModel = () => process.env.LLAMAGUARD_MODEL || "meta-llama/llama-guard-4-12b";
const guardKey = () => process.env.LLAMAGUARD_API_KEY || process.env.LLM_API_KEY || "";

/**
 * MLCommons hazard category (S1–S13) → OWASP LLM Top-10 tag + human title.
 * Most unsafe *content* maps to LLM05 (Improper Output Handling); privacy leaks
 * map to LLM02 (Sensitive Information Disclosure).
 */
export const LLAMAGUARD_CATEGORIES = {
  S1:  { name: "Violent Crimes",            owasp: "LLM05" },
  S2:  { name: "Non-Violent Crimes",        owasp: "LLM05" },
  S3:  { name: "Sex-Related Crimes",        owasp: "LLM05" },
  S4:  { name: "Child Sexual Exploitation", owasp: "LLM05" },
  S5:  { name: "Defamation",                owasp: "LLM09" },
  S6:  { name: "Specialized Advice",        owasp: "LLM09" },
  S7:  { name: "Privacy",                   owasp: "LLM02" },
  S8:  { name: "Intellectual Property",     owasp: "LLM02" },
  S9:  { name: "Indiscriminate Weapons",    owasp: "LLM06" },
  S10: { name: "Hate",                      owasp: "LLM05" },
  S11: { name: "Suicide & Self-Harm",       owasp: "LLM05" },
  S12: { name: "Sexual Content",            owasp: "LLM05" },
  S13: { name: "Elections",                 owasp: "LLM09" },
};

export function llamaGuardEnabled() {
  return enabled();
}

/**
 * Parse a Llama Guard completion string.
 * Format: "safe" | "unsafe\nS1,S10".
 * @param {string} text
 * @returns {{ safe: boolean, categories: string[] }}
 */
export function parseVerdict(text) {
  const t = String(text || "").trim();
  if (/^safe/i.test(t)) return { safe: true, categories: [] };
  if (/^unsafe/i.test(t)) {
    const codes = (t.match(/S\d{1,2}/gi) || []).map((c) => c.toUpperCase());
    return { safe: false, categories: [...new Set(codes)] };
  }
  // Unrecognized output — treat as safe but let the caller see it's inconclusive.
  return { safe: true, categories: [], unrecognized: true };
}

/** Map parsed category codes to OWASP tags for the dashboard threat feed. */
export function toOwasp(categories) {
  return categories
    .map((c) => LLAMAGUARD_CATEGORIES[c])
    .filter(Boolean)
    .map((m, i) => ({ code: categories[i], name: m.name, owasp: m.owasp }));
}

/**
 * Moderate a single piece of content with Llama Guard.
 * @param {{ text: string, role?: "user"|"assistant" }} p
 * @returns {Promise<{enabled:boolean, safe:boolean, categories:string[], owasp:Array, latencyMs:number, degraded?:boolean, error?:string}>}
 */
export async function moderateContent({ text, role = "user" }) {
  if (!enabled()) return { enabled: false, safe: true, categories: [], owasp: [], latencyMs: 0 };
  if (!guardUrl()) {
    return { enabled: true, safe: true, categories: [], owasp: [], latencyMs: 0, degraded: true, error: "LLAMAGUARD_URL unset" };
  }
  const t0 = performance.now();
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 4000);
  try {
    const res = await fetch(`${guardUrl()}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(guardKey() ? { Authorization: `Bearer ${guardKey()}` } : {}),
      },
      body: JSON.stringify({
        model: guardModel(),
        messages: [{ role, content: String(text || "") }],
        temperature: 0,
        max_tokens: 20,
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`llamaguard ${res.status}`);
    const data = await res.json();
    const verdict = parseVerdict(data?.choices?.[0]?.message?.content);
    return {
      enabled: true,
      safe: verdict.safe,
      categories: verdict.categories,
      owasp: toOwasp(verdict.categories),
      unrecognized: verdict.unrecognized || false,
      latencyMs: +(performance.now() - t0).toFixed(2),
    };
  } catch (err) {
    // Degraded — verdict is safe-by-default here; the caller applies fail-open
    // (shadow) vs fail-closed (enforce).
    return {
      enabled: true,
      safe: true,
      categories: [],
      owasp: [],
      latencyMs: +(performance.now() - t0).toFixed(2),
      degraded: true,
      error: String(err.message || err),
    };
  } finally {
    clearTimeout(timeout);
  }
}
