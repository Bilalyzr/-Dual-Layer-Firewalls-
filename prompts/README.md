# Prompt-Injection Attack Battery

A reusable, categorized library of prompt-injection test cases for red-teaming the
Dual-Layer AI Firewall.

## Files
- **`prompt_injection_attacks.json`** — the single source of truth. 10 categories, 51
  single-turn prompts, 3 multi-turn sequences, 8 benign controls (65 items total).
- **`index.js`** — ES-module loader with helpers (`allPrompts`, `byCategory`, `benignControls`).

## Schema (per category)
```json
{
  "id": "encoding_smuggling",
  "name": "Encoding / Payload Smuggling",
  "owasp": "LLM01",
  "difficulty": "hard",
  "prompts": ["..."]
}
```
`difficulty` — `easy | medium | hard` — predicts whether the Tier-1 firewall catches it.

## How to use

### 1. Paste manually (dashboard demo)
Open http://localhost:5174, set firewall to `enforce`, and paste prompts. Watch the
Real-Time Threat Feed for the OWASP tag.

### 2. In a Node script
```js
import { allPrompts, benignControls } from "./prompts/index.js";

for (const { text, owasp, difficulty } of allPrompts) {
  const res = await fetch("/api/inspect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt: text }),
  }).then((r) => r.json());
  console.log(`${res.blocked ? "BLOCK" : "LEAK"}  [${owasp}] ${difficulty}  ${text.slice(0, 40)}`);
}
```

### 3. In Python
```python
import json, urllib.request
battery = json.load(open("prompts/prompt_injection_attacks.json"))
for cat in battery["categories"]:
    for p in cat.get("prompts", []):
        ...
```

## Categories
| # | Category | OWASP | Difficulty |
|---|---|---|---|
| 1 | Direct Instruction Override | LLM01 | easy |
| 2 | Indirect Injection (untrusted content) | LLM01 | hard |
| 3 | Role-Play / Persona Jailbreaks | LLM01 | easy |
| 4 | System-Prompt Leakage | LLM07 | easy |
| 5 | Credential / Data Exfiltration | LLM02 | easy |
| 6 | Obfuscation (leetspeak) | LLM01 | medium |
| 7 | Encoding / Payload Smuggling | LLM01 | hard |
| 8 | Multi-Turn / Trust-Building | LLM01 | hard |
| 9 | Tool-Call / Excessive Agency | LLM06 | medium |
| 10 | Outbound Leak (response scan) | LLM02 | medium |

The `hard` rows are the honest Tier-1 gaps that Tier 2 (Llama Guard 4, context-aware
multi-turn analysis) is meant to close.
