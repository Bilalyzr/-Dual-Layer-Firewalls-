/**
 * ThreatFeed — real-time stream of blocked semantic threats (Req 4.1).
 *
 * Events arrive via SSE (useThreatStream) and are tagged with their OWASP
 * LLM Top 10 category. A compact summary bar shows counts per category.
 */
import { useMemo, useState } from "react";
import { useThreatStream } from "../hooks/useThreatStream";

/**
 * Source IPs are PII, so the feed redacts them by default (Epic A). The reveal
 * toggle is an operator action; even redacted we keep enough of the address to
 * recognize a repeat offender (first + last octet for IPv4).
 */
function redactIp(ip) {
  if (typeof ip !== "string" || !ip) return "";
  if (ip.includes(":")) return "····:····"; // IPv6 — hide entirely
  const parts = ip.split(".");
  if (parts.length !== 4) return "···";
  return `${parts[0]}.···.···.${parts[3]}`;
}

const CAT_COLORS = {
  LLM01: "#ff3860",
  LLM02: "#ff8a3d",
  LLM03: "#ffcc33",
  LLM04: "#00ff9d",
  LLM05: "#00f0ff",
  LLM06: "#9d6bff",
  LLM07: "#ff3df0",
  LLM08: "#36e2ff",
  LLM09: "#5d7298",
  LLM10: "#2f7bff",
};

export default function ThreatFeed() {
  const { threats, connected } = useThreatStream(40);
  const [showIps, setShowIps] = useState(false);

  const byCategory = useMemo(() => {
    const m = {};
    for (const t of threats) m[t.category] = (m[t.category] || 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [threats]);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Real-Time Threat Feed</h2>
        <button
          type="button"
          className="ip-toggle"
          onClick={() => setShowIps((v) => !v)}
          title={showIps ? "Redact source IPs" : "Reveal source IPs"}
        >
          {showIps ? "Hide IPs" : "Show IPs"}
        </button>
        <span className={`dot ${connected ? "dot-on" : "dot-off"}`} title={connected ? "live" : "disconnected"} />
      </div>

      {byCategory.length > 0 && (
        <div className="cat-bar">
          {byCategory.map(([cat, n]) => (
            <span key={cat} className="cat-chip" style={{ borderColor: CAT_COLORS[cat] }}>
              <b>{cat}</b> {n}
            </span>
          ))}
        </div>
      )}

      <ul className="feed">
        {threats.length === 0 && <li className="muted">No threats detected yet.</li>}
        {threats.map((t, i) => {
          const cat = t.category || "LLM01";
          const ts = t.ts ? new Date(t.ts) : null;
          const clientIp = t.forensics?.clientIp;
          const geo = t.forensics?.enrichment?.geoip;
          return (
            <li key={i} className="feed-item">
              <span className="cat-tag" style={{ background: CAT_COLORS[cat] || "#475569" }}>
                {cat}
              </span>
              <div className="feed-body">
                <div className="feed-label">{t.label || "threat detected"}</div>
                <div className="feed-meta">
                  {t.categoryTitle || "Policy violation"} · {t.userId || "anon"} · {ts && !isNaN(ts) ? ts.toLocaleTimeString() : "—"}
                  {t.kind === "outbound" ? " · OUTBOUND" : ""}
                  {clientIp ? (
                    <span className="feed-ip" title={showIps ? clientIp : "source IP redacted"}>
                      {" · "}
                      {showIps ? clientIp : redactIp(clientIp)}
                      {geo?.country ? ` (${geo.country})` : ""}
                    </span>
                  ) : ""}
                </div>
              </div>
              <span className={`pill ${t.blocked ? "pill-bad" : "pill-warn"}`}>
                {t.blocked ? "BLOCKED" : "DETECTED"}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
