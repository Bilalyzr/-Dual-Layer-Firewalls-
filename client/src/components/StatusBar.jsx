/**
 * StatusBar — operational status bar (Req 4.x visibility).
 *
 * Polls /api/alerts/status to show firewall/biometric modes, engine + LLM +
 * DB health, and which Tier-2 capabilities are deferred. Reflects the
 * fail-open/closed and shadow/enforce decisions from the implementation plan.
 */
import { useEffect, useState } from "react";

export default function StatusBar() {
  const [s, setS] = useState(null);

  useEffect(() => {
    const load = () =>
      fetch("/api/alerts/status")
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
        // Only accept a well-formed payload; a partial body (e.g. a proxy error
        // page parsed as JSON) must not be treated as valid status.
        .then((d) => setS(d && d.firewall && d.biometric ? d : null))
        .catch(() => setS(null));
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  if (!s) return (
    <div className="statusbar loading" role="status" aria-label="waking the API">
      <span className="sb-item">
        <span className="dot dot-wake" />
        <b>API</b> waking…
      </span>
      <span className="sb-item muted small">first load can take ~30s on free-tier hosting</span>
    </div>
  );

  const Dot = ({ ok, label }) => (
    <span className="sb-item">
      <span className={`dot ${ok ? "dot-on" : "dot-off"}`} />
      {label}
    </span>
  );

  return (
    <div className="statusbar">
      <span className="sb-item">
        <b>Firewall</b>
        <span className={`pill ${s.firewall.mode === "enforce" ? "pill-bad" : "pill-warn"}`}>
          {s.firewall.mode}
        </span>
        <span className="muted small">thr≥{s.firewall.threshold}</span>
      </span>
      <span className="sb-item">
        <b>Biometric</b>
        <span className="pill pill-warn">{s.biometric.mode}</span>
        <span className="muted small">z≥{s.biometric.zThreshold} · min {s.biometric.minSamples}</span>
      </span>
      <Dot ok={s.engine?.up} label="engine" />
      <Dot ok={s.llm?.configured} label={`llm ${s.llm?.model ?? "—"}`} />
      <Dot ok={s.db?.persistent} label={`db${s.db?.persistent ? "" : " (in-mem)"}`} />
    </div>
  );
}
