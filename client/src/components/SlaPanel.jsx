/**
 * SlaPanel — SLA / observability read-out (Epic H).
 *
 * Consumes /api/sla (which existed but had no consumer) and renders latency
 * percentiles (p50/p95/p99), availability, error rate, and any active anomalies.
 * Polls on a light interval; fails soft to a "no data" state if the endpoint is
 * unreachable so it never breaks the dashboard.
 */
import { useEffect, useState } from "react";

const POLL_MS = 5000;

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

  return (
    <section className="panel sla-panel">
      <div className="panel-head">
        <h2>SLA &amp; Observability</h2>
        <span className="muted small">live</span>
      </div>

      {err && !data ? (
        <p className="small muted">SLA endpoint unreachable — is the proxy running?</p>
      ) : (
        <>
          <div className="sla-grid">
            <div className="sla-cell">
              <div className="sla-num">{fmtMs(lat.p50)}</div>
              <div className="sla-lbl">p50</div>
            </div>
            <div className="sla-cell">
              <div className="sla-num">{fmtMs(lat.p95)}</div>
              <div className="sla-lbl">p95</div>
            </div>
            <div className="sla-cell">
              <div className="sla-num">{fmtMs(lat.p99)}</div>
              <div className="sla-lbl">p99</div>
            </div>
            <div className="sla-cell">
              <div className="sla-num sla-ok">{fmtPct(availability)}</div>
              <div className="sla-lbl">availability</div>
            </div>
            <div className="sla-cell">
              <div className={`sla-num ${Number(errorRate) > 0 ? "sla-bad" : ""}`}>
                {fmtPct(errorRate)}
              </div>
              <div className="sla-lbl">error rate</div>
            </div>
            <div className="sla-cell">
              <div className={`sla-num ${anomalies.length ? "sla-warn" : "sla-ok"}`}>
                {anomalies.length}
              </div>
              <div className="sla-lbl">anomalies</div>
            </div>
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
        </>
      )}
    </section>
  );
}
