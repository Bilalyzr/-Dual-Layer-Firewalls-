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
  LLM01: "#c96462",
  LLM02: "#c96f2f",
  LLM03: "#d4a03c",
  LLM04: "#6a994e",
  LLM05: "#7d95b5",
  LLM06: "#94829c",
  LLM07: "#b57ba0",
  LLM08: "#6d8ba3",
  LLM09: "#6f6a5e",
  LLM10: "#7d95b5",
};

export default function ThreatFeed({ focusUser = null, onClearFocus = null }) {
  const { threats, connected } = useThreatStream(40);
  // Operator decision (Epic A): the feed shows the REAL source IP by default so
  // analysts can act on it immediately; the toggle lets them redact for
  // screen-sharing / PII-sensitive contexts.
  const [showIps, setShowIps] = useState(true);
  // Category filter: click a chip to focus on one OWASP category, click again
  // (or ALL) to clear. Pairs with the User Risk Table's per-user drill-down.
  const [catFilter, setCatFilter] = useState(null);

  const byCategory = useMemo(() => {
    const m = {};
    for (const t of threats) m[t.category] = (m[t.category] || 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [threats]);

  const shown = threats.filter(
    (t) => (!catFilter || t.category === catFilter) && (!focusUser || t.userId === focusUser)
  );

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
          <span
            className={`cat-chip${catFilter == null ? " cat-chip-on" : ""}`}
            onClick={() => setCatFilter(null)}
            title="Show all categories"
          >
            <b>ALL</b> {threats.length}
          </span>
          {byCategory.map(([cat, n]) => (
            <span
              key={cat}
              className={`cat-chip${catFilter === cat ? " cat-chip-on" : ""}`}
              style={{ borderColor: CAT_COLORS[cat] }}
              onClick={() => setCatFilter(catFilter === cat ? null : cat)}
              title={`filter by ${cat}`}
            >
              <b>{cat}</b> {n}
            </span>
          ))}
        </div>
      )}

      {(focusUser || catFilter) && (
        <div className="feed-filter-note small">
          filtered:
          {focusUser && (
            <span className="feed-filter-chip">
              user <b>{focusUser}</b>
              {onClearFocus && (
                <button type="button" onClick={onClearFocus} title="clear user filter">clear</button>
              )}
            </span>
          )}
          {catFilter && (
            <span className="feed-filter-chip">
              category <b>{catFilter}</b>
              <button type="button" onClick={() => setCatFilter(null)} title="clear category filter">clear</button>
            </span>
          )}
          <span className="muted"> · {shown.length} shown</span>
        </div>
      )}

      <ul className="feed">
        {shown.length === 0 && <li className="muted">{threats.length === 0 ? "No threats detected yet." : "No threats match the current filter."}</li>}
        {shown.map((t, i) => {
          const cat = t.category || "LLM01";
          const ts = t.ts ? new Date(t.ts) : null;
          const clientIp = t.forensics?.clientIp;
          const geo = t.forensics?.enrichment?.geoip;
          return (
            <li key={i} className="feed-item">
              <span className="cat-tag" style={{ background: CAT_COLORS[cat] || "#6f6a5e" }}>
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
