/**
 * RiskSummary — Dashboard cards (PRD §36).
 *
 * Shows aggregate counts: Active Users, Events, Low/Medium/High Risk,
 * Blocked. Derived from the SSE behavior event stream. Each card carries a
 * sparkline of its recent values (rolling client-side history, persisted to
 * localStorage) so trends are visible at a glance, not just the current number.
 */
import { useEffect, useRef, useState } from "react";
import { useThreatStream } from "../hooks/useThreatStream";

const HIST_KEY = "dlf.kpiHist";
const HIST_MAX = 40;

function loadHist() {
  try {
    const v = JSON.parse(localStorage.getItem(HIST_KEY));
    return Array.isArray(v) ? v.slice(-HIST_MAX) : [];
  } catch {
    return [];
  }
}

/** Mini area sparkline; a dashed baseline while fewer than two samples. */
function Sparkline({ samples, color }) {
  const n = samples.length;
  if (n < 2) {
    return (
      <svg className="risk-card-spark" viewBox="0 0 100 26" preserveAspectRatio="none" aria-hidden="true">
        <line x1="0" y1="13" x2="100" y2="13" stroke={color} strokeWidth="1" strokeDasharray="2 3" opacity="0.35" />
      </svg>
    );
  }
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const span = max - min || 1;
  const d = samples
    .map((v, i) => {
      const x = (i / (n - 1)) * 100;
      const y = 21 - ((v - min) / span) * 16;
      return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg className="risk-card-spark" viewBox="0 0 100 26" preserveAspectRatio="none" aria-hidden="true">
      <path d={`${d} L100 26 L0 26 Z`} fill={color} opacity="0.16" />
      <path d={d} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" opacity="0.9" />
    </svg>
  );
}

export default function RiskSummary() {
  const { behavior } = useThreatStream(100);
  const [hist, setHist] = useState(loadHist);
  const lastLen = useRef(-1);

  // Derive stats from the recent events
  const users = new Set(behavior.map((b) => b.user_id));
  const low = behavior.filter((b) => b.risk_level === "LOW").length;
  const med = behavior.filter((b) => b.risk_level === "MEDIUM").length;
  const high = behavior.filter((b) => b.risk_level === "HIGH").length;
  const blocked = behavior.filter((b) => b.decision === "RESTRICT" || b.decision === "DENY").length;

  // Sample the six card values each time a new event lands, so the sparklines
  // grow with live traffic. Persisted so a reload keeps the session's trend.
  const values = [users.size, behavior.length, low, med, high, blocked];
  useEffect(() => {
    if (behavior.length === lastLen.current) return;
    lastLen.current = behavior.length;
    setHist((prev) => {
      const next = [...prev, { t: Date.now(), v: values }].slice(-HIST_MAX);
      try { localStorage.setItem(HIST_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [behavior.length]);

  const cards = [
    { label: "Active Users", value: users.size, color: "var(--cyan)" },
    { label: "Events", value: behavior.length, color: "var(--text)" },
    { label: "Low Risk", value: low, color: "var(--green)" },
    { label: "Medium Risk", value: med, color: "var(--yellow)" },
    { label: "High Risk", value: high, color: "var(--red)" },
    { label: "Blocked", value: blocked, color: "var(--red)" },
  ];

  return (
    <section className="panel p-summary">
      <div className="panel-head">
        <h2>Risk Overview</h2>
      </div>
      <div className="risk-cards-grid">
        {cards.map((c, idx) => (
          <div key={c.label} className="risk-card">
            <div className="risk-card-val" style={{ color: c.color }}>{c.value}</div>
            <div className="risk-card-lbl">{c.label}</div>
            <Sparkline samples={hist.map((h) => h.v[idx] ?? 0)} color={c.color === "var(--text)" ? "var(--cyan-soft)" : c.color} />
          </div>
        ))}
      </div>
    </section>
  );
}
