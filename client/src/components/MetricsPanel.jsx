/**
 * MetricsPanel — Phase 3 benchmark surface (Req §6/§8).
 *
 * Shows the *measured* latency / accuracy numbers that the implementation plan
 * requires before Tier 2 investment. Replaces PRD §6 design targets with facts.
 */
import { useEffect, useState } from "react";
import PanelSkeleton from "./PanelSkeleton";

/**
 * Stat — one benchmark figure. `pct` (0–100) draws the mini instrument bar
 * under the number, scaled against the metric's budget/target so latency
 * and accuracy read comparatively at a glance.
 */
function Stat({ label, value, sub, good, pct = null, barVar = "var(--cyan-soft)" }) {
  return (
    <div className="stat">
      <div className="stat-val" style={{ color: good === false ? "#f87171" : good === true ? "#34d399" : "#60a5fa" }}>
        {value}
      </div>
      <div className="stat-lbl">{label}</div>
      {sub && <div className="stat-sub muted">{sub}</div>}
      {pct != null && Number.isFinite(pct) && (
        <div className="stat-bar">
          <i style={{ width: `${Math.min(100, Math.max(2, pct))}%`, background: barVar, boxShadow: `0 0 6px ${barVar}` }} />
        </div>
      )}
    </div>
  );
}

export default function MetricsPanel() {
  const [m, setM] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    const load = () =>
      fetch("/api/metrics")
        .then((r) => r.json())
        .then((d) => { setM(d); setErr(false); })
        .catch(() => setErr(true));
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, []);

  if (!m) return (
    <section className="panel p-metrics">
      <div className="panel-head"><h2>Benchmark</h2></div>
      <PanelSkeleton lines={3} label="loading benchmark metrics" />
      {err && <p className="small muted" style={{ marginTop: 8 }}>engine unreachable — retrying…</p>}
    </section>
  );

  const c = m.classifier || {};
  const ready = c.ready === true;
  const hasF1 = ready && typeof c.f1 === "number";
  const targetMet = typeof m.heuristicLatencyMs === "number" && m.heuristicLatencyMs < 5;

  const fmt = (v, digits = 2) => (typeof v === "number" && Number.isFinite(v) ? v.toFixed(digits) : "n/a");

  return (
    <section className="panel p-metrics">
      <div className="panel-head">
        <h2>Benchmark</h2>
        <span className="muted small">{m.note}</span>
      </div>
      <div className="stat-row">
        <Stat
          label="Heuristic latency"
          value={`${fmt(m.heuristicLatencyMs, 3)} ms`}
          sub="target < 5ms"
          good={targetMet}
          pct={typeof m.heuristicLatencyMs === "number" ? (m.heuristicLatencyMs / 5) * 100 : null}
          barVar={targetMet ? "var(--green)" : "var(--red)"}
        />
        <Stat
          label="Classifier latency"
          value={ready ? `${fmt(c.avgClassifyLatencyMs, 2)} ms` : "n/a"}
          sub="engine round-trip"
          pct={ready && typeof c.avgClassifyLatencyMs === "number" ? (c.avgClassifyLatencyMs / 50) * 100 : null}
        />
        <Stat
          label="Classifier F1"
          value={hasF1 ? c.f1.toFixed(2) : "n/a"}
          sub={ready ? `probe n=${c.probeSize ?? "?"}, thr ${c.threshold ?? "?"}` : "engine offline"}
          good={hasF1 ? c.f1 >= 0.7 : undefined}
          pct={hasF1 ? c.f1 * 100 : null}
          barVar={hasF1 ? (c.f1 >= 0.7 ? "var(--green)" : "var(--red)") : "var(--cyan-soft)"}
        />
        <Stat label="Precision" value={ready ? fmt(c.precision, 2) : "n/a"} pct={ready && typeof c.precision === "number" ? c.precision * 100 : null} />
        <Stat label="Recall" value={ready ? fmt(c.recall, 2) : "n/a"} pct={ready && typeof c.recall === "number" ? c.recall * 100 : null} />
        <Stat
          label="DB"
          value={m.db?.persistent ? "mongo" : "in-mem"}
          sub={`alerts ${m.db?.alerts ?? 0} · samples ${m.db?.samples ?? 0}`}
        />
      </div>
    </section>
  );
}
