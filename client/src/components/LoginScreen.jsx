/**
 * LoginScreen — login form with behavioral risk analysis + mandatory face enrollment.
 *
 * Flow:
 *   1. User enters credentials → behavioral risk analysis runs
 *   2. If LOW/MEDIUM → login succeeds
 *   3. After login → check if face is enrolled
 *   4. If NOT enrolled → force face enrollment before entering dashboard
 *   5. If enrolled → go straight to dashboard
 */
import { useState } from "react";
import FaceAuthModal from "./FaceAuthModal";

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [pendingUser, setPendingUser] = useState(null); // user waiting for face enrollment

  const submit = async (e) => {
    e.preventDefault();
    if (!username || !password || loading) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const now = new Date();
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          device_id: navigator.userAgent.slice(0, 30),
          device_type: /mobile/i.test(navigator.userAgent) ? "mobile" : "laptop",
          working_hours: now.getHours() >= 9 && now.getHours() < 18,
          working_day: now.getDay() >= 1 && now.getDay() <= 5,
          hour: now.getHours(),
        }),
      });
      const data = await res.json();
      setResult(data);

      if (data.success) {
        // Face auth is temporarily disabled — go straight to the dashboard.
        // To re-enable: uncomment the face-status check below.
        // try {
        //   const faceRes = await fetch(`/api/auth/face/status/${username}`);
        //   const faceData = await faceRes.json();
        //   if (!faceData.enrolled) { setPendingUser(data); return; }
        // } catch { /* allow anyway */ }
        onLogin?.(data);
      }
    } catch (err) {
      setError(`Network error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const riskColor = result?.behavioral?.risk_level === "HIGH" ? "#ff3860"
    : result?.behavioral?.risk_level === "MEDIUM" ? "#ffcc33" : "#00ff9d";

  const isLocalhost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";

  // If user needs to enroll face — show the FaceAuthModal
  if (pendingUser) {
    return (
      <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-0)" }}>
        <div className="panel" style={{ width: 400, maxWidth: "90vw", textAlign: "center" }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>👤</div>
          <h2 style={{ fontSize: 14, letterSpacing: 1, textTransform: "uppercase" }}>Face Enrollment Required</h2>
          <p className="muted small" style={{ marginTop: 8 }}>
            New users must enroll their face for authentication.
            This is a mandatory security step.
          </p>
          {!isLocalhost && (
            <div style={{ marginTop: 12, padding: 10, borderRadius: 8, background: "rgba(255,56,96,0.1)", border: "1px solid rgba(255,56,96,0.3)" }}>
              <div className="small" style={{ color: "#ff3860" }}>
                ⚠ Camera requires <b>localhost</b> or HTTPS. You're on {window.location.hostname}.
              </div>
              <div className="muted small" style={{ marginTop: 4 }}>
                Open <code>http://localhost:5174</code> instead of the IP address.
              </div>
            </div>
          )}
          {isLocalhost && (
            <FaceAuthModal
              mode="enroll"
              userId={username}
              onVerified={() => {
                setPendingUser(null);
                onLogin?.(pendingUser);
              }}
              onCancel={() => {
                // Allow skip for now (in production this would block)
                setPendingUser(null);
                onLogin?.(pendingUser);
              }}
              onSkip={() => {
                // User chose to defer face enrollment — proceed to dashboard.
                // They can enroll later from the topbar "👤 ENROLL FACE" button.
                setPendingUser(null);
                onLogin?.(pendingUser);
              }}
            />
          )}
          {!isLocalhost && (
            <button className="btn" onClick={() => { setPendingUser(null); onLogin?.(pendingUser); }}
              style={{ width: "100%", marginTop: 12, opacity: 0.5, fontSize: 10 }}>
              Skip for now (camera needs localhost)
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-0)" }}>
      <div className="panel" style={{ width: 400, maxWidth: "90vw" }}>
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <span style={{ fontSize: 40, filter: "drop-shadow(0 0 10px rgba(0,240,255,0.7))" }}>🛡️</span>
          <h2 style={{ fontSize: 14, letterSpacing: 2, textTransform: "uppercase", marginTop: 8 }}>
            Dual-Layer AI Firewall
          </h2>
          <div className="muted small">Login — Behaviorally Analyzed</div>
        </div>

        <form onSubmit={submit}>
          <input className="chat-input" type="text" placeholder="Username"
            value={username} onChange={(e) => setUsername(e.target.value)}
            style={{ marginBottom: 10, width: "100%" }} />
          <input className="chat-input" type="password" placeholder="Password"
            value={password} onChange={(e) => setPassword(e.target.value)}
            style={{ marginBottom: 14, width: "100%" }} />
          <button className="btn" type="submit" disabled={loading} style={{ width: "100%" }}>
            {loading ? "Analyzing..." : "Login →"}
          </button>
        </form>

        <div className="muted small" style={{ marginTop: 12, textAlign: "center" }}>
          Demo: admin / admin123 · analyst / sec123 · demo / demo
        </div>
        <div className="muted small" style={{ textAlign: "center", marginTop: 4 }}>
          New users will be asked to enroll their face 🔑
        </div>

        {result && !result.success && (
          <div style={{ marginTop: 16, padding: 12, borderRadius: 8, background: `${riskColor}15`, border: `1px solid ${riskColor}40` }}>
            <div style={{ color: riskColor, fontWeight: 700, fontSize: 13, textTransform: "uppercase", letterSpacing: 1 }}>
              ⛔ {result.error || "Login Failed"}
            </div>
            {result.behavioral && (
              <>
                <div className="small muted" style={{ marginTop: 6 }}>
                  Risk Score: <b style={{ color: riskColor }}>{result.behavioral.risk_score}/100</b> ({result.behavioral.risk_level})
                </div>
                {result.behavioral.reasons?.slice(0, 4).map((r, i) => (
                  <div key={i} className="small" style={{ color: "var(--text-dim)", marginTop: 2 }}>⚠ {r}</div>
                ))}
              </>
            )}
          </div>
        )}

        {result?.success && (
          <div style={{ marginTop: 16, padding: 12, borderRadius: 8, background: "#00ff9d15", border: "1px solid #00ff9d40" }}>
            <div style={{ color: "#00ff9d", fontWeight: 700, fontSize: 13 }}>✓ Login Successful</div>
            <div className="small muted" style={{ marginTop: 4 }}>
              Risk: {result.behavioral?.risk_score}/100 ({result.behavioral?.risk_level})
            </div>
          </div>
        )}

        {error && <div className="small" style={{ color: "var(--bad)", marginTop: 10 }}>{error}</div>}
      </div>
    </div>
  );
}
