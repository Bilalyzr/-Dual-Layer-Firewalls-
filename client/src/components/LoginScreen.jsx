/**
 * LoginScreen — login form with behavioral risk analysis.
 *
 * Flow: user enters credentials → behavioral risk analysis runs →
 * LOW/MEDIUM risk logs in, HIGH/CRITICAL is rejected with the risk breakdown.
 *
 * Fine-tuned (ui-ux-pro-max pass): labelled accessible fields with icons,
 * password visibility toggle, loading spinner, clickable demo-account chips,
 * CRITICAL risk color, server-derived telemetry only (the proxy ignores
 * client-claimed risk context — only device labels are sent).
 */
import { useState } from "react";
import { IconAlert, IconBan, IconCheck, IconEye, IconEyeOff, IconLock, IconUser } from "./Icons.jsx";
import Logo from "./Logo.jsx";

const DEMO_ACCOUNTS = [
  { label: "admin", password: "admin123", hint: "full console" },
  { label: "analyst", password: "sec123", hint: "operator" },
  { label: "secops", password: "secops123", hint: "SOC lead" },
  { label: "auditor", password: "auditor123", hint: "read-only" },
  { label: "demo", password: "demo", hint: "viewer" },
];

const RISK_COLORS = {
  LOW: "#34d399",
  MEDIUM: "#fbbf24",
  HIGH: "#f87171",
  CRITICAL: "#dc2626",
};

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [showPw, setShowPw] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!username || !password || loading) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          password,
          // Labels only — every risk-relevant field is derived server-side.
          device_id: navigator.userAgent.slice(0, 30),
          device_type: /mobile/i.test(navigator.userAgent) ? "mobile" : "laptop",
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

  const level = result?.behavioral?.risk_level;
  const riskColor = RISK_COLORS[level] || RISK_COLORS.LOW;

  const prefill = (acc) => {
    setUsername(acc.label);
    setPassword(acc.password);
  };

  return (
    <div className="login-page">
      <div className="panel login-card">
        <div className="login-brand">
          <span className="login-crest"><Logo idPrefix="login" size={52} /></span>
          <h2>Orthrus AI Firewall</h2>
          <div className="muted small">Login — Behaviorally Analyzed</div>
        </div>

        <form onSubmit={submit} noValidate>
          <div className="login-field">
            <label htmlFor="login-user" className="login-label">
              <IconUser size={13} /> Username
            </label>
            <input
              id="login-user"
              className="chat-input login-input"
              type="text"
              placeholder="e.g. admin"
              autoComplete="username"
              autoFocus
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              aria-invalid={Boolean(error && !username)}
            />
          </div>

          <div className="login-field">
            <label htmlFor="login-pass" className="login-label">
              <IconLock size={13} /> Password
            </label>
            <div className="login-pass-wrap">
              <input
                id="login-pass"
                className="chat-input login-input"
                type={showPw ? "text" : "password"}
                placeholder="••••••••"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={Boolean(error && !password)}
                style={{ paddingRight: 44 }}
              />
              <button
                type="button"
                className="login-eye"
                onClick={() => setShowPw((v) => !v)}
                aria-label={showPw ? "Hide password" : "Show password"}
                title={showPw ? "Hide password" : "Show password"}
              >
                {showPw ? <IconEyeOff size={15} /> : <IconEye size={15} />}
              </button>
            </div>
          </div>

          <button className="btn login-submit" type="submit" disabled={loading || !username || !password}>
            {loading ? (
              <>
                <span className="login-spinner" aria-hidden="true" /> Analyzing behavior…
              </>
            ) : (
              <>Login <span aria-hidden="true">→</span></>
            )}
          </button>
        </form>

        <div className="login-demo">
          <div className="login-demo-title muted small">Demo accounts — click to fill</div>
          <div className="login-chips">
            {DEMO_ACCOUNTS.map((acc) => (
              <button
                key={acc.label}
                type="button"
                className="login-chip"
                onClick={() => prefill(acc)}
                title={`${acc.label} / ${acc.password} (${acc.hint})`}
              >
                <b>{acc.label}</b>
                <span className="muted">· {acc.hint}</span>
              </button>
            ))}
          </div>
        </div>

        {result && !result.success && (
          <div
            role="alert"
            className="login-result"
            style={{ background: `${riskColor}15`, borderColor: `${riskColor}40` }}
          >
            <div className="login-result-title" style={{ color: riskColor }}>
              <IconBan size={13} /> {result.error || "Login Failed"}
            </div>
            {result.behavioral && (
              <>
                <div className="small muted" style={{ marginTop: 6 }}>
                  Risk Score: <b style={{ color: riskColor }}>{result.behavioral.risk_score}/100</b> ({level})
                </div>
                {result.behavioral.reasons?.slice(0, 4).map((r, i) => (
                  <div key={i} className="small login-result-reason">
                    <IconAlert size={11} /> {r}
                  </div>
                ))}
              </>
            )}
          </div>
        )}

        {result?.success && (
          <div
            role="status"
            className="login-result"
            style={{ background: "rgba(52,211,153,0.12)", borderColor: "rgba(52,211,153,0.35)" }}
          >
            <div className="login-result-title" style={{ color: "#34d399", display: "flex", alignItems: "center", gap: 6 }}>
              <IconCheck size={14} /> Login Successful
            </div>
            <div className="small muted" style={{ marginTop: 4 }}>
              Risk: {result.behavioral?.risk_score}/100 ({result.behavioral?.risk_level})
              {result.stepUpRequired ? " · step-up recommended" : ""}
            </div>
          </div>
        )}

        {error && (
          <div className="small login-net-error" role="alert">
            <IconAlert size={12} /> {error}
          </div>
        )}
      </div>
    </div>
  );
}
