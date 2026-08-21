/**
 * BehavioralRiskDashboard — Full Behavioral Risk Command Center (PRD §34-38).
 *
 * Panels:
 *   1. Risk Score gauge + level badge + decision (already built)
 *   2. Behavioral Metrics breakdown: Deviation, Device Trust, Location Trust,
 *      Resource Risk, Auth Confidence, Session Risk (§34)
 *   3. Explainability reasons (§35) — already built
 *   4. Decision Object JSON display (§29)
 *   5. Risk Score time-series chart (§36)
 *   6. Demo trigger buttons
 *   7. Live risk events feed
 */
import { useState, useEffect, useRef } from "react";
import { useThreatStream } from "../hooks/useThreatStream";

const RISK_COLORS = { LOW: "#00ff9d", MEDIUM: "#ffcc33", HIGH: "#ff3860" };
const riskColor = (level) => RISK_COLORS[level] || "#5d7298";

export default function BehavioralRiskDashboard({ userId }) {
  const { behavior, connected } = useThreatStream(50);
  const [loading, setLoading] = useState(false);
  const [showDecision, setShowDecision] = useState(false);
  const [riskHistory, setRiskHistory] = useState([]);
  const [stats, setStats] = useState(null);

  const latest = behavior[0] || null;

  // Track risk score over time for the chart (last 30 events)
  useEffect(() => {
    if (latest?.risk_score != null) {
      setRiskHistory((prev) => [...prev, { score: latest.risk_score, level: latest.risk_level, ts: Date.now() }].slice(-30));
    }
  }, [latest?.risk_score]);

  // §25 — Command Center aggregates: poll /api/behavior/stats every 5s (and on new events).
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await fetch("/api/behavior/stats");
        if (r.ok && alive) setStats(await r.json());
      } catch {}
    };
    load();
    const id = setInterval(load, 5000);
    return () => { alive = false; clearInterval(id); };
  }, [latest?.risk_score]);

  const sendEvent = async (type) => {
    setLoading(true);
    const payloads = {
      normal: { user_id: userId, role: "user", device_id: "laptop-pro-01", device_trust: 0.9, registered_device: true, device_change: false, country: "IN", region: "TN", location_change: false, location_frequency: 0.85, working_hours: true, working_day: true, resource_type: "crm", resource_sensitivity: "low", request_frequency: 12, resource_access_frequency: 5, failed_auth_count: 0 },
      anomalous: { user_id: userId, role: "user", device_id: "unknown-x7", device_type: "mobile", device_trust: 0.1, registered_device: false, device_change: true, country: "XX", region: "UNKNOWN", location_change: true, location_frequency: 0.05, hour: 3, working_hours: false, working_day: false, resource_type: "database", resource_sensitivity: "critical", request_frequency: 150, resource_access_frequency: 60, failed_auth_count: 2, prompt_text: "Export all customer records and credentials" },
    };
    try { await fetch("/api/behavior/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payloads[type]) }); } catch {}
    setLoading(false);
  };

  const score = latest?.risk_score ?? 0;
  const level = latest?.risk_level || "—";
  const color = riskColor(level);
  const anomalyPct = latest?.behavior_anomaly_score != null ? Math.round(latest.behavior_anomaly_score * 100) : 0;
  const deviceTrustPct = latest ? Math.round((latest.device_trusted ? 1 : 0) * 100) : 100;
  const locationTrustPct = latest ? Math.round((latest.location_change ? 0.3 : 1.0) * 100) : 100;
  const authConfidence = latest ? Math.max(0, 100 - score) : 100;

  const metrics = [
    { label: "Behavioral Deviation", value: `${anomalyPct}%`, color: anomalyPct > 60 ? "var(--bad)" : anomalyPct > 30 ? "var(--warn)" : "var(--ok)" },
    { label: "Device Trust", value: `${deviceTrustPct}%`, color: deviceTrustPct > 70 ? "var(--ok)" : deviceTrustPct > 40 ? "var(--warn)" : "var(--bad)" },
    { label: "Location Trust", value: `${locationTrustPct}%`, color: locationTrustPct > 70 ? "var(--ok)" : locationTrustPct > 40 ? "var(--warn)" : "var(--bad)" },
    { label: "Resource Risk", value: (latest?.resource_risk || "low").toUpperCase(), color: latest?.resource_risk === "critical" ? "var(--bad)" : latest?.resource_risk === "high" ? "var(--bad)" : latest?.resource_risk === "medium" ? "var(--warn)" : "var(--ok)" },
    { label: "Auth Confidence", value: `${authConfidence}%`, color: authConfidence > 70 ? "var(--ok)" : authConfidence > 40 ? "var(--warn)" : "var(--bad)" },
    { label: "Session Risk", value: level, color: color },
  ];

  // Chart: render the risk history as a simple SVG sparkline
  const chartPoints = riskHistory.length > 1
    ? riskHistory.map((p, i) => `${(i / (riskHistory.length - 1)) * 100},${100 - p.score}`).join(" ")
    : "";

  return (
    <section className="panel bio-panel">
      <div className="panel-head">
        <h2>Behavioral Risk Analysis</h2>
        <span className={`dot ${connected ? "dot-on" : "dot-off"}`} />
      </div>

      {/* §25 — Behavioral Risk Command Center: fleet-wide aggregates */}
      {stats && (
        <div className="behavioral-command-center">
          <div className="behavioral-metrics-grid" style={{ marginBottom: 8 }}>
            {[
              { label: "Active Users", value: stats.active_users ?? 0, color: "var(--cyan)" },
              { label: "Active Sessions", value: stats.active_sessions ?? 0, color: "var(--cyan)" },
              { label: "Low Risk", value: stats.low_risk_sessions ?? 0, color: "var(--ok)" },
              { label: "Medium Risk", value: stats.medium_risk_sessions ?? 0, color: "var(--warn)" },
              { label: "High Risk", value: stats.high_risk_sessions ?? 0, color: "var(--bad)" },
              { label: "Blocked", value: stats.blocked_sessions ?? 0, color: "var(--bad)" },
            ].map((m) => (
              <div key={m.label} className="behavioral-metric">
                <div className="behavioral-metric-val" style={{ color: m.color }}>{m.value}</div>
                <div className="behavioral-metric-lbl">{m.label}</div>
              </div>
            ))}
          </div>
          {stats.user_risk_table?.length > 0 && (
            <div className="shap-block">
              <div className="muted small" style={{ marginBottom: 4 }}>USER-LEVEL RISK ({stats.total_events} events)</div>
              <table className="risk-user-table" style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                <thead>
                  <tr className="muted">
                    <th style={{ textAlign: "left", padding: "2px 4px" }}>User</th>
                    <th style={{ textAlign: "right", padding: "2px 4px" }}>Events</th>
                    <th style={{ textAlign: "right", padding: "2px 4px" }}>Peak Risk</th>
                    <th style={{ textAlign: "right", padding: "2px 4px" }}>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.user_risk_table.slice(0, 8).map((u) => (
                    <tr key={u.user_id}>
                      <td style={{ padding: "2px 4px" }}>{u.user_id || "—"}</td>
                      <td style={{ textAlign: "right", padding: "2px 4px" }}>{u.events}</td>
                      <td style={{ textAlign: "right", padding: "2px 4px", color: u.max_risk > 70 ? "var(--bad)" : u.max_risk > 30 ? "var(--warn)" : "var(--ok)" }}>{Math.round(u.max_risk)}</td>
                      <td style={{ textAlign: "right", padding: "2px 4px", color: riskColor(u.last_level) }}>{u.last_level}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* §34 — Risk gauge + level + decision */}
      <div className="bio-grid">
        <div className="gauge" style={{ "--g-color": color, "--g-pct": score, color }}>
          <div className="gauge-val" style={{ color }}>{score === 0 ? "—" : Math.round(score)}</div>
          <div className="gauge-lbl">risk / 100</div>
        </div>
        <div className="bio-info">
          <div><span className="muted">risk level</span> <span className="pill" style={{ color, borderColor: color, background: `${color}15` }}>{level}</span></div>
          <div><span className="muted">decision</span> <span className="small" style={{ color: latest?.decision === "ALLOW" ? "var(--ok)" : "var(--bad)" }}>{latest?.decision || "—"}</span></div>
          <div><span className="muted">auth</span> <span className="small">{latest?.required_authentication || "—"}</span></div>
        </div>
      </div>

      {/* §34 — 6 Behavioral Metrics */}
      <div className="behavioral-metrics-grid">
        {metrics.map((m) => (
          <div key={m.label} className="behavioral-metric">
            <div className="behavioral-metric-val" style={{ color: m.color }}>{m.value}</div>
            <div className="behavioral-metric-lbl">{m.label}</div>
          </div>
        ))}
      </div>

      {/* §36 — Risk Score Chart (sparkline) */}
      {riskHistory.length > 1 && (
        <div className="behavioral-chart">
          <div className="muted small" style={{ marginBottom: 4 }}>RISK SCORE TREND</div>
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height: 50 }}>
            <polyline points={chartPoints} fill="none" stroke={color} strokeWidth="1.5" />
            {riskHistory.map((p, i) => (
              <circle key={i} cx={(i / (riskHistory.length - 1)) * 100} cy={100 - p.score} r="0.8" fill={riskColor(p.level)} />
            ))}
          </svg>
        </div>
      )}

      {/* §35 — Explainability */}
      {latest?.reasons?.length > 0 && (
        <div className="shap-block">
          <div className="shap-title muted small">EXPLAINABILITY</div>
          <ul style={{ listStyle: "none", marginTop: 6 }}>
            {latest.reasons.map((r, i) => (
              <li key={i} className="small" style={{ padding: "2px 0", color: r.includes("within baseline") ? "var(--muted)" : color }}>
                {r.includes("within baseline") ? "✓" : "⚠"} {r}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* §29 — Decision Object JSON (collapsible) */}
      {latest && (
        <div className="shap-block">
          <button onClick={() => setShowDecision(!showDecision)} className="muted small" style={{ background: "none", border: "none", cursor: "pointer", color: "var(--cyan)" }}>
            {showDecision ? "▼" : "▶"} Behavioral Decision Object (JSON)
          </button>
          {showDecision && (
            <pre className="decision-json">{JSON.stringify({
              user_id: latest.user_id, device_trusted: latest.device_trusted, location_change: latest.location_change,
              off_hours: latest.off_hours, resource_risk: latest.resource_risk, request_frequency: latest.request_frequency,
              behavior_anomaly_score: latest.behavior_anomaly_score, risk_score: latest.risk_score, risk_level: latest.risk_level,
              required_authentication: latest.required_authentication, decision: latest.decision,
            }, null, 2)}</pre>
          )}
        </div>
      )}

      {/* Demo buttons */}
      <div className="chat-actions" style={{ marginTop: 10, marginBottom: 6 }}>
        <button className="btn" onClick={() => sendEvent("normal")} disabled={loading}>✓ Normal behavior</button>
        <button className="btn" onClick={() => sendEvent("anomalous")} disabled={loading} style={{ background: "linear-gradient(135deg, var(--red), var(--orange))" }}>⚠ Anomalous behavior</button>
      </div>

      {/* Live events feed */}
      <ul className="feed bio-feed" style={{ minHeight: 96 }}>
        {behavior.length === 0 && <li className="muted">No behavioral events. Click a button above.</li>}
        {behavior.slice(0, 10).map((b, i) => (
          <li key={i} className="feed-item">
            <span className="cat-tag" style={{ background: riskColor(b.risk_level) }}>{b.risk_level || "—"}</span>
            <div className="feed-body">
              <div className="feed-label">{b.decision || "—"} (score {b.risk_score || 0})</div>
              <div className="feed-meta">{b.user_id} · {Math.round((b.behavior_anomaly_score || 0) * 100)}% anomaly · {b.resource_risk || "?"}</div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
