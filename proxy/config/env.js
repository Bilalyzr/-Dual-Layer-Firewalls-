/**
 * Environment loader — MUST be imported before any module that reads env at
 * load time (llm/client.js, firewall/mlClient.js, routes/biometric.js).
 *
 * Why a dedicated module: ES `import` statements are hoisted and their target
 * modules are fully evaluated *before* the importing module's body runs. If we
 * called `dotenv.config()` inside server.js's body (after the imports), every
 * imported module that captured `process.env.*` in a top-level `const` would
 * already have read an EMPTY env — leaving the LLM permanently "not configured"
 * and every response simulated. Importing this file first guarantees the .env
 * is loaded before those modules evaluate.
 *
 * Precedence: .env.local (local dev) > .env (docker). Existing process env wins.
 */
import dotenv from "dotenv";
import { existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

if (existsSync(path.join(__root, ".env.local"))) {
  dotenv.config({ path: path.join(__root, ".env.local") });
} else {
  dotenv.config({ path: path.join(__root, ".env") });
}
