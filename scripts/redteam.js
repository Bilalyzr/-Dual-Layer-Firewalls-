/**
 * EPIC K — Automated red-team runner.
 *
 * Fires the full prompt-injection attack battery (prompts/prompt_injection_attacks.json)
 * at a running firewall and reports BLOCK/LEAK per attack. Designed to run in CI
 * (nightly) to catch regressions: if an attack that used to be blocked starts
 * leaking through, the gate fails.
 *
 *   node scripts/redteam.js
 *   PROXY_URL=http://localhost:4001 node scripts/redteam.js
 *   EXIT_ON_LEAK=1 node scripts/redteam.js   # exit non-zero on any leak (for CI)
 */
import { allPrompts, benignControls } from "../prompts/index.js";

const BASE = (process.env.PROXY_URL || "http://localhost:4001").replace(/\/$/, "");
const EXIT_ON_LEAK = process.env.EXIT_ON_LEAK === "1";

async function inspect(text) {
  const r = await fetch(`${BASE}/api/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt: text }),
  }).then((x) => x.json()).catch(() => ({ threat: false }));
  return r;
}

async function main() {
  console.log(`\n  🔴 Automated Red-Team Run — ${allPrompts.length} attacks + ${benignControls.length} benign controls`);
  console.log(`  target: ${BASE}\n`);

  let blocked = 0, leaked = 0, benignBlocked = 0;

  // Attacks (single-turn)
  for (const { text, owasp, difficulty, kind } of allPrompts.filter((p) => p.kind === "single")) {
    const r = await inspect(text);
    if (r.threat) {
      blocked++;
    } else {
      leaked++;
      console.log(`  ⚠ LEAK  [${owasp}] ${difficulty}  ${text.slice(0, 50)}`);
    }
  }

  // Benign controls (must NOT be blocked — false-positive check)
  for (const { text } of benignControls) {
    const r = await inspect(text);
    if (r.threat) {
      benignBlocked++;
      console.log(`  ⚠ FALSE-POSITIVE (benign blocked): ${text.slice(0, 50)}`);
    }
  }

  console.log(`\n  ── Result ──`);
  console.log(`  attacks blocked: ${blocked}   attacks leaked: ${leaked}`);
  console.log(`  benign passed:   ${benignControls.length - benignBlocked}   benign false-blocked: ${benignBlocked}`);

  const pass = leaked === 0 && benignBlocked === 0;
  console.log(`  ${pass ? "✅ PASS" : "❌ FAIL"}\n`);
  if (!pass && EXIT_ON_LEAK) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
