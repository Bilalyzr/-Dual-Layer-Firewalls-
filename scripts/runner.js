/**
 * scripts/runner.js — one-command local orchestrator.
 *
 * Boots engine (uvicorn) + proxy (node) + dashboard (vite) as child processes,
 * streams their output with colored prefixes, and wires the proxy to the engine
 * and the dashboard to the proxy using the ports in .env.local / .env.
 *
 *   node scripts/runner.js        (or press F5 in VS Code)
 *
 * Ctrl-C kills all three.
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// ---- Load .env.local (preferred) or .env --------------------------------- //
function loadEnv() {
  for (const f of [".env.local", ".env"]) {
    const p = path.join(ROOT, f);
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split(/\r?\n/)) {
      const m = line.match(/^([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/);
      if (m && process.env[m[1]] === undefined) {
        process.env[m[1]] = m[2];
      }
    }
    return;
  }
}
loadEnv();

const PY = process.env.PYTHON || pickPython();
// NOTE: engine uses 8011 by default because Docker Desktop squats on 8001.
const ENGINE_PORT = process.env.ENGINE_PORT || "8011";
const PROXY_PORT = process.env.PROXY_PORT || "4001";
const CLIENT_PORT = process.env.CLIENT_PORT || "5174";

const C = { engine: "\x1b[36m", proxy: "\x1b[33m", client: "\x1b[35m", dim: "\x1b[2m", reset: "\x1b[0m", bold: "\x1b[1m" };

function pickPython() {
  const venvExe = path.join(ROOT, ".venv", "Scripts", "python.exe");
  if (existsSync(venvExe)) return venvExe;
  return "python";
}

const IS_WIN = process.platform === "win32";

const children = [];

// On Windows, .cmd/.bat shims and npx need a shell. We must quote the command
// path ourselves (Node doesn't) because our project path contains a space
// ("Dual layer"). For explicit binaries (.exe, node) we spawn directly.
function start(name, color, cmd, args, opts) {
  const isShim = /\.(cmd|bat)$/i.test(cmd);
  const needsShell = IS_WIN && (isShim || cmd === "npx" || cmd === "npm");
  // Quote any arg that contains a space so cmd.exe doesn't split it.
  const quotedArgs = args.map((a) => (/\s/.test(a) ? `"${a}"` : a));
  const child = spawn(needsShell ? `"${cmd}"` : cmd, quotedArgs, {
    stdio: ["ignore", "pipe", "pipe"],
    shell: needsShell ? true : false,
    windowsVerbatimArguments: needsShell,
    ...opts,
  });
  child.on("error", (err) => {
    console.error(`${color}[${name}]${C.reset} failed to start: ${err.message}`);
    if (err.code === "ENOENT" && needsShell) {
      console.error(`${color}[${name}]${C.reset} hint: '${cmd}' not found on PATH.`);
    }
  });
  children.push(child);
  const tag = `${color}[${name}]${C.reset} `;
  const line = (buf) =>
    buf.toString().split(/\r?\n/).forEach((l) => l.trim() && process.stdout.write(tag + l + "\n"));
  child.stdout.on("data", line);
  child.stderr.on("data", line);
  child.on("exit", (code) => {
    console.log(`${tag}exited (${code})`);
    if (children.some((c) => !c.killed && c.exitCode === null && c !== child)) return;
    shutdown();
  });
}

function shutdown() {
  for (const c of children) {
    try { if (!c.killed) c.kill("SIGTERM"); } catch {}
  }
  setTimeout(() => process.exit(0), 200);
}
process.on("SIGINT", () => { console.log("\nshutting down…"); shutdown(); });
process.on("SIGTERM", shutdown);

console.log(`${C.bold}Dual-Layer AI Firewall — local run${C.reset}`);
console.log(`${C.dim}  python:   ${PY}`);
console.log(`  model:    ${process.env.LLM_MODEL || "(none)"}  @  ${process.env.LLM_BASE_URL || "(none)"}`);
console.log(`  engine → :${ENGINE_PORT}   proxy → :${PROXY_PORT}   dashboard → :${CLIENT_PORT}${C.reset}\n`);

// Engine first.
start("engine", C.engine, PY, ["-m", "uvicorn", "engine.app:app", "--host", "127.0.0.1", "--port", ENGINE_PORT], { cwd: ROOT });

// Proxy after a short delay (engine needs a moment to boot).
setTimeout(() => {
  start("proxy", C.proxy, process.execPath, ["server.js"], {
    cwd: path.join(ROOT, "proxy"),
    env: { ...process.env, ENGINE_URL: `http://localhost:${ENGINE_PORT}`, PROXY_PORT },
  });
}, 2500);

// Dashboard next. Prefer the local vite binary to avoid npx/PATH issues on Windows.
const VITE_BIN = path.join(ROOT, "client", "node_modules", ".bin", IS_WIN ? "vite.cmd" : "vite");
const viteCmd = existsSync(VITE_BIN) ? VITE_BIN : "npx";
const viteArgs = existsSync(VITE_BIN)
  ? ["--port", CLIENT_PORT, "--host"]
  : ["vite", "--port", CLIENT_PORT, "--host"];
setTimeout(() => {
  start("client", C.client, viteCmd, viteArgs, {
    cwd: path.join(ROOT, "client"),
    env: { ...process.env, PROXY_URL: `http://localhost:${PROXY_PORT}` },
  });
  setTimeout(() => {
    console.log(`\n${C.bold}✓ Dashboard ready → open http://localhost:${CLIENT_PORT}${C.reset}\n`);
  }, 4500);
}, 4000);
