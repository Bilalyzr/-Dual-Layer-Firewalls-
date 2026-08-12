/**
 * RiskSummary — Dashboard cards (PRD §36).
 *
 * Shows aggregate counts: Active Users, Active Sessions, Low/Medium/High Risk,
 * Blocked Sessions. Derived from the SSE behavior event stream.
 */
import { useThreatStream } from "../hooks/useThreatStream";

export default function RiskSummary() {
  const { behavior } = useThreatStream(100);

  // Derive stats from the recent events
  const users = new Set(behavior.map((b) => b.user_id));
  const low = behavior.filter((b) => b.risk_level === "LOW").length;
  const med = behavior.filter((b) => b.risk_level === "MEDIUM").length;
  const high = behavior.filter((b) => b.risk_level === "HIGH").length;
  const blocked = behavior.filter((b) => b.decision === "RESTRICT" || b.decision === "DENY").length;

  const cards = [
    { label: "Active Users", value: users.size || 0, color: "var(--cyan)" },
    { label: "Events", value: behavior.length, color: "var(--text)" },
    { label: "Low Risk", value: low, color: "var(--ok)" },
    { label: "Medium Risk", value: med, color: "var(--warn)" },
    { label: "High Risk", value: high, color: "var(--bad)" },
    { label: "Blocked", value: blocked, color: "#ff8a3d" },
  ];

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Risk Overview</h2>
      </div>
      <div className="risk-cards-grid">
        {cards.map((c) => (
          <div key={c.label} className="risk-card">
            <div className="risk-card-val" style={{ color: c.color }}>{c.value}</div>
            <div className="risk-card-lbl">{c.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
