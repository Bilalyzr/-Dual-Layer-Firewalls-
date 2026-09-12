/**
 * SlaPanel — SLA / observability read-out (Epic H).
 *
 * Consumes /api/sla (which existed but had no consumer) and renders latency
 * percentiles (p50/p95/p99), availability, error rate, and any active anomalies.
 * Polls on a light interval; fails soft to a "no data" state if the endpoint is
 * unreachable so it never breaks the dashboard.
 */
import { useEffect, useState } from "react";
import PanelSkeleton from "./PanelSkeleton";

const POLL_MS = 5000;

/* Bar budgets: what a full bar means per metric. Latencies share a 500ms
   budget so p50/p95/p99 read comparatively; error rate fills at 5%. */
const LAT_BUDGET_MS = 500;
const ERR_BUDGET_PCT = 5;

function Cell({ num, lbl, cls = "", pct = null, barVar = "var(--cyan-soft)" }) {
  return (
    <div className="sla-cell">
      <div className={`sla-num ${cls}`}>{num}</div>
      <div className="sla-lbl">{lbl}</div>
      {pct != null && Number.isFinite(pct) && (
        <div className="stat-bar">
          <i style={{ width: `${Math.min(100, Math.max(2, pct))}%`, background: barVar, boxShadow: `0 0 6px ${barVar}` }} />
        </div>
      )}
    </div>
  );
}

function fmtMs(v) {
  return v == null ? "—" : `${Number(v).toFixed(1)}ms`;
}
function fmtPct(v) {
  return v == null ? "—" : `${(Number(v) * (v <= 1 ? 100 : 1)).toFixed(2)}%`;
}

export default function SlaPanel() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await fetch("/api/sla");
        if (!r.ok) throw new Error("bad status");
        const j = await r.json();
        if (!alive) return;
        setData(j);
        setErr(false);
      } catch {
        if (alive) setErr(true);
      }
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const sla = data?.sla || {};
  const lat = sla.latency || sla.latencyMs || {};
  const anomalies = data?.anomalies || [];
  const availability = sla.availability ?? sla.uptime;
  const errorRate = sla.errorRate ?? sla.errors;

  if (!data) return (
    <section className="panel sla-panel p-sla">
      <div className="panel-head">
        <h2>SLA &amp; Observability</h2>
        <span className="muted small">live</span>
      </div>
      <PanelSkeleton lines={3} label="loading SLA metrics" />
      {err && <p className="small muted" style={{ marginTop: 8 }}>SLA endpoint unreachable — retrying…</p>}
    </section>
  );

  return (
    <section className="panel sla-panel p-sla">
      <div className="panel-head">
        <h2>SLA &amp; Observability</h2>
        <span className="muted small">{err ? "reconnecting…" : "live"}</span>
      </div>

          <div className="sla-grid">
            <Cell num={fmtMs(lat.p50)} lbl="p50" pct={lat.p50 != null ? (lat.p50 / LAT_BUDGET_MS) * 100 : null} />
            <Cell num={fmtMs(lat.p95)} lbl="p95" pct={lat.p95 != null ? (lat.p95 / LAT_BUDGET_MS) * 100 : null} />
            <Cell num={fmtMs(lat.p99)} lbl="p99" pct={lat.p99 != null ? (lat.p99 / LAT_BUDGET_MS) * 100 : null} />
            <Cell
              num={fmtPct(availability)}
              lbl="availability"
              cls="sla-ok"
              pct={availability != null ? Number(availability) <= 1 ? Number(availability) * 100 : Number(availability) : null}
              barVar="var(--green)"
            />
            <Cell
              num={fmtPct(errorRate)}
              lbl="error rate"
              cls={Number(errorRate) > 0 ? "sla-bad" : ""}
              pct={errorRate != null ? ((Number(errorRate) <= 1 ? Number(errorRate) * 100 : Number(errorRate)) / ERR_BUDGET_PCT) * 100 : null}
              barVar="var(--red)"
            />
            <Cell
              num={anomalies.length}
              lbl="anomalies"
              cls={anomalies.length ? "sla-warn" : "sla-ok"}
              pct={(anomalies.length / 10) * 100}
              barVar={anomalies.length ? "var(--yellow)" : "var(--green)"}
            />
          </div>

          {anomalies.length > 0 && (
            <ul className="sla-anomalies">
              {anomalies.slice(0, 4).map((a, i) => (
                <li key={i} className="small">
                  <span className="pill pill-warn">{a.metric || a.type || "anomaly"}</span>{" "}
                  {a.message || a.detail || `value ${a.value ?? "?"}`}
                </li>
              ))}
            </ul>
          )}
    </section>
  );
}
