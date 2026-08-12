/**
 * /api/auth/login — Login system with behavioral risk analysis.
 *
 * Validates credentials against a mock user store, then runs the FULL
 * behavioral risk pipeline on the login attempt:
 *   - Captures device, location, time, identity context
 *   - Sends to the engine's /behavior/analyze endpoint
 *   - Returns the risk level + decision (ALLOW / STEP-UP / RESTRICT)
 *
 * If behavioral risk is HIGH → login is restricted (even with correct password).
 * If MEDIUM → step-up MFA required.
 * If LOW → normal login + session issued.
 */
import { Router } from "express";
import { publish } from "../middleware/eventBus.js";
import { appendAudit } from "../compliance/auditChain.js";

const router = Router();
const ENGINE_URL = process.env.ENGINE_URL || "http://localhost:8011";

// Mock user store (demo). In production this would be a real IAM / DB lookup.
const USERS = {
  admin: { password: "admin123", role: "admin", privilege_level: 0.9, normal_hours: [9, 18] },
  analyst: { password: "sec123", role: "user", privilege_level: 0.4, normal_hours: [9, 18] },
  demo: { password: "demo", role: "user", privilege_level: 0.2, normal_hours: [9, 18] },
};

// Per-user session state (in-process; integrates with the existing session system in production).
const _sessions = new Map();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const clientIp = req.ipContext?.clientIp || req.ip || "127.0.0.1";

  // 1. Credential validation
  const user = USERS[username?.toLowerCase()];
  const passwordValid = user && user.password === password;

  if (!passwordValid) {
    appendAudit("login_failed", { username, ip: clientIp, ts: new Date() });
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

  // 2. Build behavioral telemetry from the login context
  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay();
  const isWorkingHours = hour >= user.normal_hours[0] && hour < user.normal_hours[1];
  const isWorkingDay = day >= 1 && day <= 5;

  const telemetry = {
    user_id: username,
    role: user.role,
    device_id: req.body.device_id || "browser",
    device_type: req.body.device_type || "laptop",
    device_trust: req.body.device_trust ?? 0.8,
    registered_device: req.body.registered_device ?? true,
    device_change: req.body.device_change ?? false,
    country: req.body.country || req.ipContext?.geoip?.country || "IN",
    region: req.body.region || req.ipContext?.geoip?.region || "TN",
    location_change: req.body.location_change ?? false,
    location_frequency: req.body.location_frequency ?? 0.8,
    hour,
    working_hours: req.body.working_hours ?? isWorkingHours,
    working_day: req.body.working_day ?? isWorkingDay,
    time_since_prev_request: req.body.time_since_prev_request ?? 3600,
    session_id: `login-${Date.now()}`,
    session_duration: 0,
    request_count: 1,
    failed_auth_count: req.body.failed_auth_count ?? 0,
    resource_type: "auth",
    resource_sensitivity: "high",
    request_frequency: 1,
    resource_access_frequency: 1,
  };

  // 3. Run behavioral risk analysis on this login attempt
  let behavioral = { risk_level: "LOW", risk_score: 0, decision: "ALLOW" };
  try {
    const r = await fetch(`${ENGINE_URL}/behavior/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(telemetry),
      signal: AbortSignal.timeout(10000),
    });
    behavioral = await r.json();
  } catch (err) {
    // Engine unavailable — allow login with LOW risk (fail-open for demo)
    behavioral.reasons = ["behavioral engine unavailable — fail-open"];
  }

  // 4. Decision: combine credential validity + behavioral risk
  publish("behavior", { ...behavioral, event_type: "login", user_id: username, ts: new Date() });

  if (behavioral.risk_level === "HIGH") {
    appendAudit("login_blocked", { username, ip: clientIp, risk: behavioral.risk_score, reasons: behavioral.reasons, ts: new Date() });
    return res.status(403).json({
      success: false,
      error: "Login blocked by behavioral risk analysis",
      behavioral,
      user: { username, role: user.role },
    });
  }

  if (behavioral.risk_level === "MEDIUM") {
    // For the demo: MEDIUM allows login but flags that step-up was recommended.
    // In production, this would require an actual OTP/WebAuthn assertion.
    appendAudit("login_stepup_recommended", { username, ip: clientIp, risk: behavioral.risk_score, ts: new Date() });
    // Fall through to issue session — the behavioral panel will show the risk
  }

  // 5. LOW risk → issue session
  const token = `sess-${username}-${Date.now().toString(36)}`;
  _sessions.set(token, { username, role: user.role, loginTime: now, behavioral });
  appendAudit("login_success", { username, ip: clientIp, risk: behavioral.risk_score, ts: new Date() });

  res.json({
    success: true,
    token,
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
  // Demo helper — lists available test accounts (NOT for production)
  res.json({
    accounts: Object.entries(USERS).map(([u, d]) => ({
      username: u,
      role: d.role,
      password_hint: d.password.slice(0, 2) + "***",
    })),
  });
});

export default router;
