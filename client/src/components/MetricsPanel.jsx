/**
 * MetricsPanel — Phase 3 benchmark surface (Req §6/§8).
 *
 * Shows the *measured* latency / accuracy numbers that the implementation plan
 * requires before Tier 2 investment. Replaces PRD §6 design targets with facts.
 */
import { useEffect, useState } from "react";

function Stat({ label, value, sub, good }) {
  return (
    <div className="stat">
      <div className="stat-val" style={{ color: good === false ? "#ff3860" : good === true ? "#00ff9d" : "#00f0ff" }}>
        {value}
      </div>
      <div className="stat-lbl">{label}</div>
      {sub && <div className="stat-sub muted">{sub}</div>}
    </div>
  );
}

export default function MetricsPanel() {
  const [m, setM] = useState(null);

  useEffect(() => {
    const load = () =>
      fetch("/api/metrics")
        .then((r) => r.json())
        .then(setM)
        .catch(() => setM(null));
    load();
    const id = setInterval(load, 8000);
    return () => clearInterval(id);
  }, []);

  if (!m) return <section className="panel"><p className="muted">loading metrics…</p></section>;

  const c = m.classifier || {};
  const ready = c.ready === true;
  const hasF1 = ready && typeof c.f1 === "number";
  const targetMet = typeof m.heuristicLatencyMs === "number" && m.heuristicLatencyMs < 5;

  const fmt = (v, digits = 2) => (typeof v === "number" && Number.isFinite(v) ? v.toFixed(digits) : "n/a");

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Benchmark <small>(Phase 3)</small></h2>
        <span className="muted small">{m.note}</span>
      </div>
      <div className="stat-row">
        <Stat
          label="Heuristic latency"
          value={`${fmt(m.heuristicLatencyMs, 3)} ms`}
          sub="target < 5ms"
          good={targetMet}
        />
        <Stat
          label="Classifier latency"
          value={ready ? `${fmt(c.avgClassifyLatencyMs, 2)} ms` : "n/a"}
          sub="engine round-trip"
        />
        <Stat
          label="Classifier F1"
          value={hasF1 ? c.f1.toFixed(2) : "n/a"}
          sub={ready ? `probe n=${c.probeSize ?? "?"}, thr ${c.threshold ?? "?"}` : "engine offline"}
          good={hasF1 ? c.f1 >= 0.7 : undefined}
        />
        <Stat label="Precision" value={ready ? fmt(c.precision, 2) : "n/a"} />
        <Stat label="Recall" value={ready ? fmt(c.recall, 2) : "n/a"} />
        <Stat
          label="DB"
          value={m.db?.persistent ? "mongo" : "in-mem"}
          sub={`alerts ${m.db?.alerts ?? 0} · samples ${m.db?.samples ?? 0}`}
        />
      </div>
    </section>
  );
}
