/**
 * scripts/expose-live.mjs — one-command live-site bridge.
 *
 * While the Render proxy is suspended (free instance-hour reset on the 1st),
 * this exposes the LOCAL stack (npm run dev) through a free Cloudflare
 * quick tunnel and repoints the Vercel rewrite at it, then pushes so the
 * live dashboard (dual-layer-firewalls.vercel.app) serves from this machine.
 *
 * Usage (stack must be running first):
 *   1. npm run dev                          (terminal 1 — engine+proxy+vite)
 *   2. node scripts/expose-live.mjs         (terminal 2 — tunnel + auto-push)
 *
 * The quick-tunnel URL is random per run; this script handles the
 * vercel.json update + git push automatically. Ctrl-C kills the tunnel.
 * When Render resumes: revert client/vercel.json to
 * https://dlf-proxy.onrender.com and stop using this script.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VERCEL_JSON = path.join(ROOT, "client", "vercel.json");
const RENDER_DEST = "https://dlf-proxy.onrender.com/api/:path*";

function findCloudflared() {
  const candidates = [
    path.join(ROOT, "tools", "cloudflared.exe"),
    path.join(ROOT, "..", "tools", "cloudflared.exe"),
    path.join(ROOT, "..", "tools", "cloudflared"),
  ];
  for (const c of candidates) if (existsSync(c)) return c;
  return "cloudflared"; // PATH
}

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", ...opts });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

// ---- sanity: local proxy must be up ----------------------------------------
// (curl, not node fetch: immediate process.exit with a live keep-alive socket
// trips a libuv assertion on Windows and corrupts the exit code)
const probe = sh("curl", ["-sf", "-m", "5", "-o", "NUL", "http://127.0.0.1:4001/healthz"], { shell: true });
if (probe.code !== 0) {
  console.error("[expose-live] local proxy :4001 is not up — run `npm run dev` first.");
  process.exit(1);
}

// ---- start the quick tunnel -------------------------------------------------
const bin = findCloudflared();
console.log(`[expose-live] starting cloudflare quick tunnel (${bin}) -> 127.0.0.1:4001`);
const child = spawn(bin, ["tunnel", "--url", "http://127.0.0.1:4001", "--no-autoupdate"], {
  stdio: ["ignore", "pipe", "pipe"],
});

let host = "";
const pick = (chunk) => {
  const m = String(chunk).match(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/);
  if (m && !host) {
    host = m[1];
    repoint(host);
  }
};
child.stdout.on("data", pick);
child.stderr.on("data", pick);
child.on("exit", (code) => {
  console.error(`[expose-live] tunnel exited (code ${code}) — the live site is now DOWN until rerun.`);
  process.exit(code ?? 1);
});

function repoint(host) {
  const dest = `https://${host}/api/:path*`;
  const raw = readFileSync(VERCEL_JSON, "utf8");
  const updated = raw.replace(/"destination":\s*"https:\/\/[a-z0-9.-]+\/api\/:path\*"/,
    `"destination": "${dest}"`);
  if (updated === raw && !raw.includes(dest)) {
    console.error("[expose-live] could not find a rewrite destination to replace in client/vercel.json");
    child.kill();
    process.exit(1);
  }
  writeFileSync(VERCEL_JSON, updated);
  console.log(`[expose-live] tunnel URL: https://${host}`);
  console.log(`[expose-live] client/vercel.json -> ${dest}`);

  const add = sh("git", ["add", "client/vercel.json"]);
  const commit = sh("git", ["commit", "-m",
    `chore(live): repoint tunnel URL ${host} (Render suspended; auto via scripts/expose-live.mjs)`]);
  const push = sh("git", ["push", "origin", "main"]);
  if (push.code === 0) {
    console.log("[expose-live] pushed — Vercel redeploys in ~1 min.");
    console.log(`[expose-live] LIVE SITE: https://dual-layer-firewalls.vercel.app`);
    console.log("[expose-live] keep this terminal + `npm run dev` running. Ctrl-C to stop the tunnel.");
  } else {
    console.warn(`[expose-live] git push failed — push manually. (${(add.out || "") + (commit.out || "") + push.out}).trim()`);
  }
}
