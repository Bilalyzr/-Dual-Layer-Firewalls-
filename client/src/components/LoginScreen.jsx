/**
 * LoginScreen — login form with behavioral risk analysis.
 *
 * Flow: user enters credentials → behavioral risk analysis runs →
 * LOW/MEDIUM risk logs in, HIGH is rejected with the risk breakdown.
 */
import { useState } from "react";
import { IconAlert, IconBan, IconCheck, IconKey, IconUser } from "./Icons.jsx";
import Logo from "./Logo.jsx";

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

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
        onLogin?.(data);
      }
    } catch (err) {
      setError(`Network error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const riskColor = result?.behavioral?.risk_level === "HIGH" ? "#e59896"
    : result?.behavioral?.risk_level === "MEDIUM" ? "#e0b36a" : "#a3c979";

  const isLocalhost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-1)" }}>
      <div className="panel" style={{ width: 400, maxWidth: "90vw" }}>
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <span style={{ filter: "drop-shadow(0 0 14px rgba(217,119,87,0.45))" }}><Logo idPrefix="login" size={52} /></span>
          <h2 style={{ fontSize: 14, letterSpacing: 2, textTransform: "uppercase", marginTop: 8 }}>
            Orthrus AI Firewall
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

        {result && !result.success && (
          <div style={{ marginTop: 16, padding: 12, borderRadius: 8, background: `${riskColor}15`, border: `1px solid ${riskColor}40` }}>
            <div style={{ color: riskColor, fontWeight: 700, fontSize: 13, textTransform: "uppercase", letterSpacing: 1 }}>
              <IconBan size={13} style={{ verticalAlign: "-2px", marginRight: 5 }} /> {result.error || "Login Failed"}
            </div>
            {result.behavioral && (
              <>
                <div className="small muted" style={{ marginTop: 6 }}>
                  Risk Score: <b style={{ color: riskColor }}>{result.behavioral.risk_score}/100</b> ({result.behavioral.risk_level})
                </div>
                {result.behavioral.reasons?.slice(0, 4).map((r, i) => (
                  <div key={i} className="small" style={{ color: "var(--text-dim)", marginTop: 2 }}><IconAlert size={11} style={{ verticalAlign: "-1px", marginRight: 4 }} /> {r}</div>
                ))}
              </>
            )}
          </div>
        )}

        {result?.success && (
          <div style={{ marginTop: 16, padding: 12, borderRadius: 8, background: "rgba(163,201,121,0.12)", border: "1px solid rgba(22,163,74,0.35)" }}>
            <div style={{ color: "#a3c979", fontWeight: 700, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}><IconCheck size={14} /> Login Successful</div>
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
