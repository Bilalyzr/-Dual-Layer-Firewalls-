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
import { IconAlert, IconCheck } from "./Icons.jsx";

const RISK_COLORS = { LOW: "#34d399", MEDIUM: "#fbbf24", HIGH: "#f87171" };
const riskColor = (level) => RISK_COLORS[level] || "#5d7298";

/**
 * The engine embeds each reason's real contribution in its text (e.g.
 * "weightage 92%" for injection weight, "78% of baseline" for deviation).
 * Extract it so the explainability list can draw true contribution bars.
 */
const weightOf = (r) => {
  const m = String(r).match(/(\d+(?:\.\d+)?)\s*%/);
  return m ? Math.min(100, parseFloat(m[1])) : null;
};

export default function BehavioralRiskDashboard({ userId }) {
  const { behavior, connected } = useThreatStream(50);
  const [loading, setLoading] = useState(false);
  const [showDecision, setShowDecision] = useState(false);
  const [riskHistory, setRiskHistory] = useState([]);
  const [stats, setStats] = useState(null);
  // Chart UX: hover crosshair index, range filter (0=all / 15 / 60 minutes),
  // and a pause that freezes history + the live pulse (a11y for flashing).
  const [hover, setHover] = useState(null);
  const [range, setRange] = useState(0);
  const [paused, setPaused] = useState(false);
  const svgRef = useRef(null);

  const latest = behavior[0] || null;

  // Track risk score over time (last 30 events). Tracks the EVENT identity —
  // not the score value — so two consecutive attacks with the same score both
  // land as points (the old value-dep silently dropped them). Injection
  // blocks are flagged so the line can color them red vs benign green.
  useEffect(() => {
    if (!latest || latest.risk_score == null || paused) return;
    const ts = latest.ts ? new Date(latest.ts).getTime() : Date.now();
    const blocked = latest.decision === "RESTRICT" || latest.decision === "DENY";
    const injection = (latest.reasons || []).some((r) => String(r).includes("Prompt injection"));
    setRiskHistory((prev) => {
      if (prev.length && prev[prev.length - 1].ts === ts) return prev; // dedupe replayed events
      return [...prev, {
        score: Math.round(latest.risk_score),
        level: latest.risk_level,
        ts,
        blocked: blocked || injection,
      }].slice(-30);
    });
  }, [latest, paused]);

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
    { label: "Behavioral Deviation", value: `${anomalyPct}%`, color: anomalyPct > 60 ? "var(--red)" : anomalyPct > 30 ? "var(--yellow)" : "var(--green)" },
    { label: "Device Trust", value: `${deviceTrustPct}%`, color: deviceTrustPct > 70 ? "var(--green)" : deviceTrustPct > 40 ? "var(--yellow)" : "var(--red)" },
    { label: "Location Trust", value: `${locationTrustPct}%`, color: locationTrustPct > 70 ? "var(--green)" : locationTrustPct > 40 ? "var(--yellow)" : "var(--red)" },
    { label: "Resource Risk", value: (latest?.resource_risk || "low").toUpperCase(), color: latest?.resource_risk === "critical" ? "var(--red)" : latest?.resource_risk === "high" ? "var(--red)" : latest?.resource_risk === "medium" ? "var(--yellow)" : "var(--green)" },
    { label: "Auth Confidence", value: `${authConfidence}%`, color: authConfidence > 70 ? "var(--green)" : authConfidence > 40 ? "var(--yellow)" : "var(--red)" },
    { label: "Session Risk", value: level, color: color },
  ];

  // Chart: risk history as an area sparkline — the line is the risk score,
  // points are colored by verdict (red = injection block, green = allowed).

  // ---- §36 chart geometry: a real coordinate plane, not a stretched svg ----
  const CW = 520, CH = 170, PL = 38, PR = 14, PT = 12, PB = 20;
  // Range filter (all / 15m / 1h); falls back to the full window when the
  // selected range holds fewer than two points.
  const ranged = range === 0 ? riskHistory : riskHistory.filter((p) => p.ts >= Date.now() - range * 60000);
  const hist = ranged.length > 1 ? ranged : riskHistory;
  const n = hist.length;
  const lastPoint = hist[n - 1];
  const xAt = (i) => PL + (n > 1 ? (i * (CW - PL - PR)) / (n - 1) : 0);
  const yAt = (score) => PT + ((100 - score) * (CH - PT - PB)) / 100;
  // Catmull-Rom -> cubic Bezier for a smooth curve through the points
  const smoothPath = (() => {
    if (n < 2) return "";
    const pts = hist.map((p, i) => [xAt(i), yAt(p.score)]);
    let d = `M ${pts[0][0].toFixed(1)} ${pts[0][1].toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)], p1 = pts[i],
            p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
      const c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = p1[1] + (p2[1] - p0[1]) / 6;
      const c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = p2[1] - (p3[1] - p1[1]) / 6;
      d += ` C ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${c2x.toFixed(1)} ${c2y.toFixed(1)}, ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
    }
    return d;
  })();
  const areaPath = smoothPath
    ? `${smoothPath} L ${xAt(n - 1).toFixed(1)} ${yAt(0)} L ${xAt(0).toFixed(1)} ${yAt(0)} Z`
    : "";
  const trendColor = RISK_COLORS[lastPoint?.level] || "#34d399";
  const fmt = (ts) => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  // Hover crosshair: map the pointer's x to the nearest point index.
  const onChartMove = (e) => {
    const svg = svgRef.current;
    if (!svg || n < 2) return;
    const r = svg.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * CW;
    const step = (CW - PL - PR) / (n - 1);
    setHover(Math.max(0, Math.min(n - 1, Math.round((x - PL) / step))));
  };
  const hoverPt = hover != null ? hist[hover] : null;

  return (
    <section className="panel p-risk">
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
              { label: "Low Risk", value: stats.low_risk_sessions ?? 0, color: "var(--green)" },
              { label: "Medium Risk", value: stats.medium_risk_sessions ?? 0, color: "var(--yellow)" },
              { label: "High Risk", value: stats.high_risk_sessions ?? 0, color: "var(--red)" },
              { label: "Blocked", value: stats.blocked_sessions ?? 0, color: "var(--red)" },
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
                      <td style={{ textAlign: "right", padding: "2px 4px", color: u.max_risk > 70 ? "var(--red)" : u.max_risk > 30 ? "var(--yellow)" : "var(--green)" }}>{Math.round(u.max_risk)}</td>
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
          <div><span className="muted">decision</span> <span className="small" style={{ color: latest?.decision === "ALLOW" ? "var(--green)" : "var(--red)" }}>{latest?.decision || "—"}</span></div>
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

      {/* §36 — Risk Score Trend: a real instrument — axes, zone bands,
          block threshold, smooth curve, tooltips, live pulse marker */}
      {n > 1 && (
        <div className={`behavioral-chart${paused ? " rc-paused" : ""}`}>
          <div className="rc-head">
            <span className="rc-title">RISK SCORE TREND</span>
            <span className="rc-ranges">
              {[[0, "all"], [15, "15m"], [60, "1h"]].map(([v, l]) => (
                <button key={l} type="button" className={`drill-btn${range === v ? " rc-btn-on" : ""}`} onClick={() => setRange(v)}>
                  {l}
                </button>
              ))}
              <button
                type="button"
                className="drill-btn"
                onClick={() => setPaused((p) => !p)}
                title="freeze the chart and its live pulse (prefers-reduced-motion friendly)"
              >
                {paused ? "resume" : "pause"}
              </button>
            </span>
          </div>
          <div className="rc-sub" style={{ display: "block", marginBottom: 4 }}>
            {n} events ·{" "}
            <span style={{ color: "var(--red)" }}>{hist.filter((p) => p.blocked).length} blocked</span>
            {" "}· {paused ? "paused" : "live"}
            {range !== 0 && ranged.length > 1 ? ` · last ${range === 15 ? "15 min" : "hour"}` : ""}
          </div>
          <div style={{ position: "relative" }}>
          <svg
            viewBox={`0 0 ${CW} ${CH}`}
            className="rc-svg"
            role="img"
            aria-label="Risk score over time"
            ref={svgRef}
            onMouseMove={onChartMove}
            onMouseLeave={() => setHover(null)}
          >
            <defs>
              <linearGradient id="rcArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={trendColor} stopOpacity="0.30" />
                <stop offset="100%" stopColor={trendColor} stopOpacity="0.02" />
              </linearGradient>
            </defs>

            {/* traffic-light zone bands */}
            <rect x={PL} y={yAt(100)} width={CW - PL - PR} height={yAt(70) - yAt(100)} fill="rgba(255,59,48,0.07)" />
            <rect x={PL} y={yAt(70)}  width={CW - PL - PR} height={yAt(35) - yAt(70)}  fill="rgba(255,204,0,0.06)" />
            <rect x={PL} y={yAt(35)}  width={CW - PL - PR} height={yAt(0) - yAt(35)}   fill="rgba(48,209,88,0.05)" />

            {/* gridlines + y labels */}
            {[100, 70, 35, 0].map((v) => (
              <g key={v}>
                <line x1={PL} x2={CW - PR} y1={yAt(v)} y2={yAt(v)} stroke="#1e2a44" strokeWidth="1" strokeDasharray={v === 100 || v === 0 ? "none" : "3 4"} />
                <text x={PL - 6} y={yAt(v) + 3} textAnchor="end" className="rc-y">{v}</text>
              </g>
            ))}

            {/* the BLOCK threshold — where the firewall cuts */}
            <line x1={PL} x2={CW - PR} y1={yAt(55)} y2={yAt(55)} stroke="#60a5fa" strokeWidth="1.3" strokeDasharray="6 4" />
            <text x={CW - PR} y={yAt(55) - 4} textAnchor="end" className="rc-th">BLOCK 55</text>

            {/* the curve + its area */}
            {areaPath && <path d={areaPath} fill="url(#rcArea)" />}
            {smoothPath && <path d={smoothPath} fill="none" stroke={trendColor} strokeWidth="2.2" strokeLinecap="round" className="rc-line" />}

            {/* points: red = blocked, green = allowed; older points fade so the
                newest activity reads brightest; hover = full detail */}
            {hist.map((p, i) => (
              <g key={i} opacity={0.35 + (0.65 * i) / Math.max(1, n - 1)}>
                {p.blocked && <circle cx={xAt(i)} cy={yAt(p.score)} r="5.5" fill="none" stroke="#f87171" strokeWidth="1" opacity="0.45" />}
                <circle cx={xAt(i)} cy={yAt(p.score)} r={p.blocked ? 3 : 2.2} fill={p.blocked ? "#f87171" : "#34d399"} />
                <circle cx={xAt(i)} cy={yAt(p.score)} r="9" fill="transparent" className="rc-hit">
                  <title>{`${p.blocked ? "BLOCKED" : "allowed"} · risk ${p.score}/100 · ${fmt(p.ts)}`}</title>
                </circle>
              </g>
            ))}

            {/* hover crosshair + highlighted point */}
            {hoverPt && (
              <g className="rc-cross">
                <line x1={xAt(hover)} x2={xAt(hover)} y1={PT} y2={CH - PB} />
                <circle cx={xAt(hover)} cy={yAt(hoverPt.score)} r="4.5" fill="none" stroke="var(--cyan-soft)" strokeWidth="1.5" />
              </g>
            )}

            {/* live pulse on the newest point */}
            {lastPoint && (
              <g>
                <circle cx={xAt(n - 1)} cy={yAt(lastPoint.score)} r="6" fill={trendColor} opacity="0.35" className="rc-pulse" />
                <text x={Math.min(xAt(n - 1) + 8, CW - PR - 4)} y={yAt(lastPoint.score) - 7} className="rc-now" textAnchor="end" fill={trendColor}>
                  {lastPoint.score}
                </text>
              </g>
            )}

            {/* x labels: window start / end */}
            <text x={PL} y={CH - 5} className="rc-x">{fmt(hist[0].ts)}</text>
            <text x={CW - PR} y={CH - 5} className="rc-x" textAnchor="end">{fmt(lastPoint?.ts || hist[0].ts)}</text>
          </svg>
          {hoverPt && (
            <div
              className="rc-tip"
              style={{
                left: `${Math.max(10, Math.min(90, (xAt(hover) / CW) * 100))}%`,
                top: `${(yAt(hoverPt.score) / CH) * 100}%`,
              }}
            >
              <b style={{ color: hoverPt.blocked ? "var(--red)" : "var(--green)" }}>
                {hoverPt.blocked ? "BLOCKED" : "allowed"}
              </b>
              {" "}risk {hoverPt.score}/100 · {hoverPt.level} · {fmt(hoverPt.ts)}
            </div>
          )}
          </div>
          <div className="rc-legend">
            <span><i className="band-key" style={{ background: "rgba(255,59,48,0.5)" }} /> HIGH 70+</span>
            <span><i className="band-key" style={{ background: "rgba(255,204,0,0.5)" }} /> MEDIUM 35–70</span>
            <span><i className="band-key" style={{ background: "rgba(48,209,88,0.45)" }} /> LOW &lt;35</span>
            <span style={{ color: "#f87171" }}>● blocked</span>
            <span style={{ color: "#34d399" }}>● allowed</span>
            <span style={{ color: "#60a5fa" }}>– – block threshold</span>
          </div>
        </div>
      )}

      {/* §35 — Explainability (contribution bars: the engine embeds each
          reason's real weight in its text, e.g. "weightage 92%") */}
      {latest?.reasons?.length > 0 && (
        <div className="shap-block">
          <div className="shap-title muted small">EXPLAINABILITY</div>
          <ul style={{ listStyle: "none", marginTop: 6 }}>
            {latest.reasons.map((r, i) => {
              const w = weightOf(r);
              const baseline = String(r).includes("within baseline");
              return (
                <li key={i} className="small reason-row" style={{ color: baseline ? "var(--muted)" : color }}>
                  <span className="reason-ico">
                    {baseline ? <IconCheck size={10} /> : <IconAlert size={10} />}
                  </span>
                  <span className="reason-body">
                    <span className="reason-text">{r}</span>
                    <span className="reason-bar">
                      <i
                        style={{
                          width: `${w != null ? w : (baseline ? 8 : 20)}%`,
                          background: baseline ? "var(--muted)" : color,
                          boxShadow: `0 0 6px ${baseline ? "transparent" : color + "55"}`,
                        }}
                      />
                    </span>
                    {w != null && <span className="reason-w">{Math.round(w)}%</span>}
                  </span>
                </li>
              );
            })}
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
        <button className="btn" onClick={() => sendEvent("normal")} disabled={loading}><IconCheck size={12} style={{ verticalAlign: "-2px", marginRight: 5 }} /> Normal behavior</button>
        <button className="btn" onClick={() => sendEvent("anomalous")} disabled={loading} style={{ background: "linear-gradient(135deg, var(--red), var(--orange))" }}><IconAlert size={12} style={{ verticalAlign: "-2px", marginRight: 5 }} /> Anomalous behavior</button>
      </div>

      {/* Live events feed */}
      <ul className="feed" style={{ maxHeight: 200 }}>
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
