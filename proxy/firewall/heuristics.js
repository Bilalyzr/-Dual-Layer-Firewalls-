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
  // Direct / indirect instruction overrides — LLM01. Covers inflections
  // ("ignoring", "ignored") that dodge a bare `ignore` match, and the same
  // noun set as the v2 sanitizer (incl. constraints/guidelines).
  {
    re: /\b(ignore[sd]?|ignoring|disregard(?:ing|ed)?|forget(?:ting)?|override|skip(?:ping)?)\b[^.]{0,40}\b(previous|prior|above|earlier|all|any)\s+(instructions?|rules?|prompts?|directives?|directions?|constraints?|guidelines?)\b/i,
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
  // ---- Cross-lingual instruction-override (EPIC F) ------------------------ //
  // Spanish
  { re: /\b(ignora|ignorar|desactiva|olvida)\b[^.]{0,30}\b(instrucciones|reglas|indicaciones|anteriores|previas|todas)\b/i, category: "LLM01", label: "Instruction override (ES)" },
  // French (imperative: ignore/oublie/néglige/désactive)
  { re: /\b(ignor(e|er|r)?|oublie|néglige|désactive)\b[^.]{0,30}\b(instructions?|règles?|consignes?|précédentes?|précédent|toutes|tous)\b/i, category: "LLM01", label: "Instruction override (FR)" },
  // German
  { re: /\b(ignoriere|vergiss|deaktiviere)\b[^.]{0,30}\b(Anweisungen|Regeln|vorigen|vorherigen|alle)\b/i, category: "LLM01", label: "Instruction override (DE)" },
  // Portuguese
  { re: /\b(ignora|ignore|esqueça|desative)\b[^.]{0,30}\b(instruções|regras|anteriores|todas)\b/i, category: "LLM01", label: "Instruction override (PT)" },
  // Hindi (romanized — most attacks use Latin script)
  { re: /\b(purani|pichhli|sabhi)\b[^.]{0,20}\b(nirdesh|niyam|instructions?|rules?)\b[^.]{0,20}\b(ignor|bhul|hatkar)/i, category: "LLM01", label: "Instruction override (HI)" },
  // Chinese (romanized pinyin + a few CJK common terms)
  { re: /\b(hulüe|wangji|zhixing)\b[^.]{0,20}\b(yiqian|suoyou|zhiling|guize)/i, category: "LLM01", label: "Instruction override (ZH-pinyin)" },
  { re: /(忽略|忘记|无视|执行)[^。]{0,20}(之前|以前|所有|指令|规则|指令)/i, category: "LLM01", label: "Instruction override (ZH-CJK)" },
  // Russian (romanized)
  { re: /\b(ignoriruy|zabud|otmeni)\b[^.]{0,25}\b(instruktsii|pravila|predydushchie|vse)\b/i, category: "LLM01", label: "Instruction override (RU)" },
  // Arabic (romanized)
  { re: /\b(tajahal|insa|ilgha)\b[^.]{0,25}\b(al-ta'alimat|al-qawanin|sabiqah|jami'a)\b/i, category: "LLM01", label: "Instruction override (AR)" },
  // Role-play jailbreaks — cross-lingual "you are now / developer mode"
  { re: /\b(tu es maintenant|tu eres ahora|du bist jetzt|você é agora|sei jetzt)\b[^.]{0,20}\b(un|uma|ein)\b[^.]{0,20}\b(ia?|ai|modelo?|assistant)/i, category: "LLM01", label: "Role-play jailbreak (multilingual)" },
  // ---- Native-script instruction-override (Wave 4) ----------------------- //
  // These cover non-Latin scripts the romanized rules above miss. No \b word
  // boundaries (meaningless between non-ASCII chars) and no ASCII \w (which does
  // not match Cyrillic/Devanagari) — use \p{L} or literal-substring matching.
  // Russian (Cyrillic)
  { re: /(игнорир\p{L}*|забудь\p{L}*|отмени\p{L}*|пропусти\p{L}*)[\s\S]{0,25}(инструкц\p{L}+|правил\p{L}+|предыдущ\p{L}+|все)/iu, category: "LLM01", label: "Instruction override (RU native)" },
  // Hindi (Devanagari) — match on stems as substrings (matras are combining marks)
  { re: /(निर्देश|नियम|आदेश|हिदायत)[\s\S]{0,25}(अनदेखा|भूल|नज़रअंदाज़|छोड़)|(अनदेखा|नज़रअंदाज़|भूल)[\s\S]{0,25}(निर्देश|नियम|आदेश)/u, category: "LLM01", label: "Instruction override (HI native)" },
  // Arabic (Arabic script)
  { re: /(تجاهل|انس|ألغ|الغ|تخط)[\s\S]{0,25}(التعليمات|القواعد|الأوامر|السابقة)/u, category: "LLM01", label: "Instruction override (AR native)" },
  // Japanese
  { re: /(以前|前|すべて|全て)[\s\S]{0,14}(指示|命令|ルール|指令)[\s\S]{0,14}(無視|忘れ|破棄)/u, category: "LLM01", label: "Instruction override (JA native)" },
  // Korean
  { re: /(이전|모든|앞의)[\s\S]{0,12}(지시|명령|규칙|지침)[\s\S]{0,12}(무시|잊어)/u, category: "LLM01", label: "Instruction override (KO native)" },
];

/**
 * Normalize text to defeat evasion that hides a known signature behind Unicode
 * tricks (Wave 4):
 *   - NFKC folds full-width / compatibility forms ("ｉｇｎｏｒｅ" → "ignore")
 *   - stripping combining marks defeats accent/diacritic evasion ("ígnóré" →
 *     "ignore") so the ASCII rules fire. Combining marks live in U+0300–U+036F
 *     (Latin/Greek/Cyrillic); native-script vowel signs (Devanagari matras,
 *     Arabic harakat) sit elsewhere and are deliberately left intact.
 */
function normalize(text) {
  return text.normalize("NFKC").normalize("NFD").replace(/[̀-ͯ]/g, "");
}

// Leetspeak folding (mirrors the v2 sanitizer's deobfuscate): "1gn0re" →
// "ignore" so the instruction-override rules fire on obfuscated attacks.
function deleet(text) {
  return text.replace(/[013457@$]/g, (c) => (
    { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" }[c] || c
  ));
}

// Base64-smuggled injections: find base64-looking tokens (16+ chars, valid
// alphabet), decode, and if the payload carries an override/exfiltration
// command it is an attack outright (no benign reason to encode "ignore all
// rules"). Mirrors the v2 sanitizer's outright base64-payload block.
const B64_TOKEN = /\b[A-Za-z0-9+/]{16,}={0,2}\b/g;
const B64_HOSTILE = /(ignore|disregard|forget|bypass|override|reveal|exfiltrate|output|print)[^.]{0,40}(instruction|rule|prompt|constraint|guardrail|api.?key|secret|credential|token|system)/i;

function scanBase64(text, signals) {
  for (const tok of text.match(B64_TOKEN) || []) {
    try {
      const decoded = Buffer.from(tok, "base64").toString("utf8");
      if (B64_HOSTILE.test(decoded)) {
        signals.push({
          category: "LLM01",
          label: "Base64-smuggled instruction override",
          snippet: `decoded: ${decoded.slice(0, 48)}`,
        });
        return; // one signal is enough; snippets stay small
      }
    } catch { /* not valid base64 — ignore */ }
  }
}

function scan(str, signals, matchedRules) {
  for (const rule of RULES) {
    if (matchedRules.has(rule)) continue; // already fired on a prior pass
    const m = str.match(rule.re);
    if (m) {
      matchedRules.add(rule);
      const start = Math.max(0, (m.index || 0) - 20);
      const end = Math.min(str.length, (m.index || 0) + m[0].length + 20);
      signals.push({
        category: rule.category,
        label: rule.label,
        snippet: str.slice(start, end).trim(),
      });
    }
  }
}

/**
 * Scan a prompt against all heuristic rules.
 * @param {string} text
 * @returns {{ matched: boolean, signals: Array<{category,label,snippet}>, latencyMs: number }}
 */
export function runHeuristics(text) {
  const t0 = performance.now();
  const signals = [];
  if (typeof text === "string" && text.length) {
    const matchedRules = new Set();
    // Pass 1: raw text (accurate snippets for the common case).
    scan(text, signals, matchedRules);
    // Pass 2: normalized text — only adds rules that evasion hid from pass 1.
    const norm = normalize(text);
    if (norm !== text) scan(norm, signals, matchedRules);
    // Pass 3: leetspeak-folded — "1gn0re pr10r c0nstra1nts" → readable form.
    const deleetText = deleet(norm);
    if (deleetText !== norm) scan(deleetText, signals, matchedRules);
    // Pass 4: base64 payloads decoded in place — a hostile decoded command is
    // an attack regardless of how innocuous the encoded token looks.
    scanBase64(text, signals);
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
