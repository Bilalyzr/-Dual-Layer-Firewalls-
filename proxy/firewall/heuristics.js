/**
 * Regex heuristic layer (Req 1.2).
 *
 * Detects well-known jailbreak / prompt-injection signatures and maps each
 * signal to the relevant OWASP LLM Top 10 (2025) category so the dashboard
 * can render a real threat taxonomy (Req 4.1).
 *
 * Categories:
 *   LLM01 Prompt Injection
 *   LLM02 Sensitive Information Disclosure
 *   LLM03 Supply Chain
 *   LLM04 Data and Model Poisoning
 *   LLM05 Improper Output Handling
 *   LLM06 Excessive Agency
 *   LLM07 System Prompt Leakage
 *   LLM08 Vector and Embedding Weaknesses
 *   LLM09 Misinformation
 *   LLM10 Unbounded Consumption
 */

// Each rule: regex (case-insensitive), category, label.
const RULES = [
  // Direct / indirect instruction overrides — LLM01.
  {
    re: /\b(ignore|disregard|forget|override|skip)\b[^.]{0,40}\b(previous|prior|above|earlier|all)\s+(instructions?|rules?|prompts?|directives?|directions?)\b/i,
    category: "LLM01",
    label: "Instruction override (ignore previous instructions)",
  },
  {
    re: /\b(new|updated?)\s+(instructions?|rules?)\s*[:\-]/i,
    category: "LLM01",
    label: "Prompt redefinition (new instructions)",
  },
  // Role-play jailbreaks (DAN, AIM, developer mode) — LLM01.
  {
    re: /\b(dan|aim|developer\s+mode|jailbreak|stan|evil\s+assistant|unrestricted\s+model|gpt-?[5-9])\b/i,
    category: "LLM01",
    label: "Role-play jailbreak persona",
  },
  {
    re: /\b(act|pretend|roleplay)\s+as\b[^.]{0,40}\b(no|without|free|unrestricted)\b[^.]{0,30}(restriction|policy|rules?|constraint)/i,
    category: "LLM01",
    label: "Constraint-stripping persona",
  },
  // System prompt leakage — LLM07.
  {
    re: /\b(reveal|show|print|display|output|repeat|tell me)\b[^.]{0,40}\b(system\s+(prompt|message|instructions?)|initial\s+prompt|hidden\s+(rules?|context)|secret)\b/i,
    category: "LLM07",
    label: "System prompt exfiltration",
  },
  {
    re: /\bwhat\b[^.]{0,20}\b(your|the)\b\s+(rules?|instructions?|guidelines?|system\s+prompt)\b/i,
    category: "LLM07",
    label: "System prompt probing",
  },
  // Filter bypass / policy override — LLM01 + LLM05.
  {
    re: /\b(bypass|circumvent|disable|turn off|break\s+out)\b[^.]{0,30}(filter|safety|moderation|content\s*policy|guardrail|constraint)/i,
    category: "LLM01",
    label: "Safety filter bypass",
  },
  {
    re: /\brespond\s+without\s+(ethical|content|safety)\s+(constraint|policy|filter|guideline)/i,
    category: "LLM05",
    label: "Improper-output solicitation",
  },
  // Sensitive info / credential disclosure — LLM02.
  {
    re: /\b(api\s*key|secret\s*key|password|passwd|admin\s+credentials?|token|private\s+key|\.env)\b[^.]{0,30}(reveal|show|share|send|output|leak|dump)/i,
    category: "LLM02",
    label: "Credential disclosure attempt",
  },
  {
    re: /\b(reveal|dump|exfiltrate|send\s+me)\b[^.]{0,40}(api\s*keys?|secrets?|credentials?|database)/i,
    category: "LLM02",
    label: "Data exfiltration attempt",
  },
  // Code execution / tool abuse — LLM06 (Excessive Agency).
  {
    re: /\b(write|generate|create|build)\b[^.]{0,30}(malware|ransomware|virus|payload|exploit|keylogger|backdoor)/i,
    category: "LLM06",
    label: "Malware generation (excessive agency)",
  },
  {
    re: /\b(run|execute|eval|system|exec|subprocess|rm\s+-rf|curl\s+.*\|\s*sh)\b/i,
    category: "LLM06",
    label: "Shell/code execution attempt",
  },
  {
    re: /\bignore\b[^.]{0,30}(policy|legal|law|moderation)/i,
    category: "LLM05",
    label: "Policy disregard",
  },
  // Harmful-content instructions — LLM05 (Improper Output Handling) + LLM06.
  {
    re: /\b(provide|give|show|tell|explain|describe|walk me through|list)\b[^.]{0,40}\b(step[- ]?by[- ]?step|instructions?|guide|tutorial|how to)\b[^.]{0,60}\b(make|build|create|synthesize|manufacture|cook|hotwire|hack|steal|pick a lock|bomb|explosives?|weapon|meth|phishing|malware|virus|fake id|counterfeit)\b/i,
    category: "LLM05",
    label: "Harmful-content instructions",
  },
  {
    re: /\b(make|build|create|synthesize|manufacture|cook)\b[^.]{0,40}\b(bomb|explosives?|weapon|meth|methamphetamine|ricin|pipe bomb|untraceable weapon)\b/i,
    category: "LLM06",
    label: "Weapon/substance synthesis request",
  },
];

/**
 * Scan a prompt against all heuristic rules.
 * @param {string} text
 * @returns {{ matched: boolean, signals: Array<{category,label,snippet}>, latencyMs: number }}
 */
export function runHeuristics(text) {
  const t0 = performance.now();
  const signals = [];
  if (typeof text === "string" && text.length) {
    for (const rule of RULES) {
      const m = text.match(rule.re);
      if (m) {
        const start = Math.max(0, (m.index || 0) - 20);
        const end = Math.min(text.length, (m.index || 0) + m[0].length + 20);
        signals.push({
          category: rule.category,
          label: rule.label,
          snippet: text.slice(start, end).trim(),
        });
      }
    }
  }
  const latencyMs = +(performance.now() - t0).toFixed(3);
  return { matched: signals.length > 0, signals, latencyMs };
}

/** Convenience: OWASP category titles for the dashboard legend. */
export const OWASP_TITLES = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};
