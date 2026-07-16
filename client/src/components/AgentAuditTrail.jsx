/**
 * AgentAuditTrail — placeholder for the Trifecta Reader/Actor audit view (Req 4.3).
 *
 * In Tier 1 there is no live agent (LangGraph lands in Phase 5), so this panel
 * documents the intended audit trail and shows outbound-integrity blocks that
 * the firewall already records — a faithful preview of the Tier 2 surface.
 */
import { useThreatStream } from "../hooks/useThreatStream";

export default function AgentAuditTrail() {
  const { threats } = useThreatStream(40);
  const outbound = threats.filter((t) => t.kind === "outbound");

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Agent Audit Trail</h2>
        <span className="pill pill-warn">Tier 2</span>
      </div>

      <p className="muted small">
        In Tier 2, Reader-Agents process untrusted content in a sandbox (no
        outbound network / DB / tools), emit schema-validated JSON, and only
        validated output reaches the Actor-Agent under strict RBAC. This panel
        will visualize Actor reasoning traces + tool calls. Below are the
        outbound-integrity blocks the firewall already records.
      </p>

      <ul className="feed">
        {outbound.length === 0 && (
          <li className="muted">No outbound blocks yet.</li>
        )}
        {outbound.map((t, i) => (
          <li key={i} className="feed-item">
            <span className="cat-tag" style={{ background: "#f97316" }}>{t.category}</span>
            <div className="feed-body">
              <div className="feed-label">{t.label}</div>
              <div className="feed-meta">{new Date(t.ts).toLocaleTimeString()}</div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
