/**
 * /api/auth/login — Login system with behavioral risk analysis.
 *
 * Validates credentials, then runs the FULL behavioral risk pipeline on the
 * login attempt and ENFORCES the verdict:
 *   - CRITICAL / HIGH (score >= 80) → login refused (403)
 *   - MEDIUM (or engine unavailable) → session issued but FROZEN behind
 *     WebAuthn step-up (requireStepUp) until an assertion clears it
 *   - LOW → normal login + session issued
 *
 * Trust boundary hardening: every risk-relevant telemetry field is derived
 * SERVER-SIDE (clock, tracked failed-login count) or pinned to a neutral
 * constant. The request body can no longer lower its own risk score —
 * `failed_auth_count`, `device_trust`, `location_change`, `working_hours`…
 * from the body are ignored.
 */
import crypto from "crypto";
import { Router } from "express";
import { publish } from "../middleware/eventBus.js";
import { appendAudit } from "../compliance/auditChain.js";
import { createSession, requireStepUp } from "../auth/session.js";
import { bumpFailedLogins, getLoginState, resetFailedLogins } from "../db/mongo.js";

const router = Router();
const ENGINE_URL = process.env.ENGINE_URL || "http://127.0.0.1:8011";

function safePasswordMatch(expected, provided) {
  if (typeof expected !== "string" || typeof provided !== "string") return false;
  const a = crypto.createHash("sha256").update(expected, "utf8").digest();
  const b = crypto.createHash("sha256").update(provided, "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

// User store (demo). Passwords come from the environment when set; the
// built-in demo passwords only apply when the *_PASSWORD vars are absent.
const USERS = {
  admin: { password: process.env.ADMIN_PASSWORD || "admin123", role: "admin", privilege_level: 0.9, normal_hours: [9, 18] },
  analyst: { password: process.env.ANALYST_PASSWORD || "sec123", role: "user", privilege_level: 0.4, normal_hours: [9, 18] },
  demo: { password: process.env.DEMO_PASSWORD || "demo", role: "user", privilege_level: 0.2, normal_hours: [9, 18] },
};
if (!process.env.ADMIN_PASSWORD || !process.env.ANALYST_PASSWORD || !process.env.DEMO_PASSWORD) {
  console.warn(
    "[login] DEMO credentials active — set ADMIN_PASSWORD / ANALYST_PASSWORD / DEMO_PASSWORD " +
    "before any deployment beyond the local demo."
  );
}

// Per-user session state (in-process; integrates with the existing session system in production).
const _sessions = new Map();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const clientIp = req.ipContext?.clientIp || req.ip || "127.0.0.1";

  // 1. Credential validation (constant-time digest comparison)
  const user = USERS[username?.toLowerCase()];
  const passwordValid = Boolean(user && safePasswordMatch(user.password, password));

  // Server-tracked failure count: bumped on every bad password, reset on
  // success. Never read from the request body.
  let failedAuthCount = 0;
  if (!passwordValid) {
    failedAuthCount = await bumpFailedLogins(username?.toLowerCase() || "unknown");
    appendAudit("login_failed", { username, ip: clientIp, failedAuthCount, ts: new Date() });
    publish("behavior", {
      user_id: username || "unknown",
      decision: "DENY",
      risk_level: "HIGH",
      risk_score: 100,
      reasons: ["Invalid credentials"],
      ts: new Date(),
    });
    return res.status(401).json({
      success: false,
      error: "Invalid credentials",
      behavioral: { risk_level: "HIGH", decision: "DENY" },
    });
  }

  // 2. Build behavioral telemetry from SERVER-DERIVED context only.
  //    Risk-relevant fields the client used to control are pinned: without a
  //    device registry / geoip the server cannot verify them, so they take
  //    neutral constants — the body can only supply harmless labels.
  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay();
  const failedState = await getLoginState(username.toLowerCase());
  const telemetry = {
    user_id: username,
    role: user.role,
    device_id: req.body.device_id || "browser",      // label only
    device_type: req.body.device_type || "laptop",   // label only
    device_trust: 0.5,                               // unknown — server constant
    registered_device: true,                         // unverified — neutral constant
    device_change: false,                            // server constant (no registry yet)
    country: req.ipContext?.geoip?.country || "IN",  // server geoip when present
    region: req.ipContext?.geoip?.region || "TN",
    location_change: false,                          // server constant (no history yet)
    location_frequency: 0.8,                         // neutral constant
    hour,                                            // server clock — always
    working_hours: hour >= user.normal_hours[0] && hour < user.normal_hours[1],
    working_day: day >= 1 && day <= 5,               // server calendar — always
    time_since_prev_request: 3600,                   // server constant
    session_id: `login-${Date.now()}`,
    session_duration: 0,
    request_count: 1,
    failed_auth_count: failedState.failedLogins || 0, // server-tracked
    resource_type: "auth",
    resource_sensitivity: "high",
    request_frequency: 1,
    resource_access_frequency: 1,
  };

  // 3. Run behavioral risk analysis on this login attempt. Engine failure or
  //    a non-JSON reply degrades to a STEP_UP-gated login — never a silent
  //    LOW/ALLOW (fail-open let an attacker just DDoS the engine instead).
  let behavioral = { risk_level: "MEDIUM", risk_score: 50, decision: "STEP_UP", degraded: true };
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(telemetry),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error(`engine HTTP ${r.status}`);
    const parsed = await r.json();
    if (!parsed || typeof parsed.risk_level !== "string") throw new Error("engine returned non-JSON body");
    behavioral = parsed;
  } catch (err) {
    behavioral.reasons = [`behavioral engine unavailable (${err.message}) — login gated behind step-up`];
  }

  // 4. Decision: combine credential validity + behavioral risk
  publish("behavior", { ...behavioral, event_type: "login", user_id: username, ts: new Date() });

  // Hard-deny CRITICAL, and HIGH at score >= 80: a genuinely hostile context
  // (new device + new location + off hours + failed auths) still blocks.
  const hardDeny = ["HIGH", "CRITICAL"].includes(behavioral.risk_level) && (behavioral.risk_score ?? 100) >= 80;
  if (hardDeny) {
    appendAudit("login_blocked", { username, ip: clientIp, risk: behavioral.risk_score, reasons: behavioral.reasons, ts: new Date() });
    return res.status(403).json({
      success: false,
      error: "Login blocked by behavioral risk analysis",
      behavioral,
      user: { username, role: user.role },
    });
  }

  // 5. Issue session. MEDIUM (or degraded) risk → the session is created but
  //    FROZEN behind WebAuthn step-up: /api/chat returns 401 until a verified
  //    assertion clears it (see routes/auth.js verify endpoint).
  const stepUpRequired = behavioral.risk_level === "MEDIUM" || behavioral.degraded === true;
  const signedSession = await createSession({ userId: username });
  const token = signedSession.token;
  if (stepUpRequired) {
    await requireStepUp(signedSession.sessionId, "login risk MEDIUM — WebAuthn step-up required");
    appendAudit("login_stepup_required", { username, ip: clientIp, risk: behavioral.risk_score, degraded: Boolean(behavioral.degraded), ts: new Date() });
  }
  _sessions.set(token, { username, role: user.role, loginTime: now, behavioral, sessionId: signedSession.sessionId });
  await resetFailedLogins(username.toLowerCase());
  appendAudit("login_success", { username, ip: clientIp, risk: behavioral.risk_score, stepUpRequired, ts: new Date() });

  res.json({
    success: true,
    token,
    sessionId: signedSession.sessionId,
    stepUpRequired,
    user: { username, role: user.role, privilege_level: user.privilege_level },
    behavioral,
  });
});

router.post("/logout", (req, res) => {
  const token = req.body.token;
  if (token) _sessions.delete(token);
  res.json({ success: true });
});

router.get("/users", (_req, res) => {
  // Demo helper — lists available test accounts (passwords redacted)
  res.json({
    accounts: Object.entries(USERS).map(([u, d]) => ({
      username: u,
      role: d.role,
      password_hint: "***",
    })),
  });
});

export default router;
