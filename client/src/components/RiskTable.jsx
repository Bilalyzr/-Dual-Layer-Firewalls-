/**
 * RiskTable — Per-user risk table (PRD §36).
 *
 * Columns: User | Device | Location | Anomaly | Risk | Action
 * Click a row to expand the user's behavioral profile (§37).
 */
import { Fragment, useState } from "react";
import { useThreatStream } from "../hooks/useThreatStream";
import { IconAlert, IconCheck } from "./Icons.jsx";

const RISK_COLORS = { LOW: "#a3c979", MEDIUM: "#e0b36a", HIGH: "#e59896" };

export default function RiskTable({ onFocusUser = null }) {
  const { behavior } = useThreatStream(50);
  const [selectedUser, setSelectedUser] = useState(null);

  // Deduplicate by user (keep most recent)
  const userMap = new Map();
  for (const b of behavior) {
    if (b.user_id) userMap.set(b.user_id, b);
  }
  const rows = [...userMap.values()].slice(0, 20);

  return (
    <section className="panel p-table">
      <div className="panel-head">
        <h2>User Risk Table</h2>
      </div>
      {rows.length === 0 ? (
        <p className="muted small">No behavioral events yet.</p>
      ) : (
        <table className="risk-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Device</th>
              <th>Location</th>
              <th>Anomaly</th>
              <th>Risk</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((b) => (
              <Fragment key={b.user_id}>
                <tr onClick={() => setSelectedUser(selectedUser === b.user_id ? null : b.user_id)} style={{ cursor: "pointer" }}>
                  <td className="mono">{b.user_id}</td>
                  <td>{b.device_trusted ? <><IconCheck size={11} style={{ verticalAlign: "-1px", marginRight: 3 }} /> Trusted</> : <><IconAlert size={11} style={{ verticalAlign: "-1px", marginRight: 3 }} /> New</>}</td>
                  <td>{b.location_change ? <><IconAlert size={11} style={{ verticalAlign: "-1px", marginRight: 3 }} /> Changed</> : "Normal"}</td>
                  <td>{Math.round((b.behavior_anomaly_score || 0) * 100)}%</td>
                  <td style={{ color: RISK_COLORS[b.risk_level] || "var(--muted)" }}>{b.risk_level || "—"}</td>
                  <td>{b.decision || "—"}</td>
                </tr>
                {/* §37 — User Behavioral Profile (expandable) */}
                {selectedUser === b.user_id && (
                  <tr className="profile-detail-row">
                    <td colSpan={6}>
                      <div className="profile-detail">
                        <div className="muted small" style={{ marginBottom: 6, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span>BEHAVIORAL PROFILE — {b.user_id}</span>
                          {onFocusUser && (
                            <button
                              type="button"
                              className="drill-btn"
                              onClick={() => onFocusUser(b.user_id)}
                              title="show only this user's threats in the Real-Time Threat Feed"
                            >
                              filter threat feed
                            </button>
                          )}
                        </div>
                        <div className="profile-grid">
                          <div><span className="muted">Risk Score:</span> {b.risk_score}/100</div>
                          <div><span className="muted">Auth Required:</span> {b.required_authentication || "—"}</div>
                          <div><span className="muted">Resource Risk:</span> {(b.resource_risk || "low").toUpperCase()}</div>
                          <div><span className="muted">Off Hours:</span> {b.off_hours ? "Yes" : "No"}</div>
                          <div><span className="muted">Req Frequency:</span> {b.request_frequency || 0}/hr</div>
                          <div><span className="muted">Decision:</span> {b.decision}</div>
                        </div>
                        {b.reasons?.length > 0 && (
                          <div style={{ marginTop: 8 }}>
                            <span className="muted small">REASONS:</span>
                            <ul style={{ listStyle: "none", marginTop: 4 }}>
                              {b.reasons.map((r, i) => (
                                <li key={i} className="small" style={{ color: "var(--text-dim)", padding: "1px 0" }}>
                                  {r.includes("within baseline") ? <IconCheck size={10} style={{ verticalAlign: "-1px", marginRight: 4 }} /> : <IconAlert size={10} style={{ verticalAlign: "-1px", marginRight: 4 }} />}{r}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
