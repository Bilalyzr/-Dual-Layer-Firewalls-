/**
 * BiometricMonitor — active-session trust score panel (Req 4.2).
 *
 * Shows the latest continuous-authentication decision for the local user plus
 * the rolling history of biometric events from the SSE stream.
 * SHAP explainability is deferred to Tier 2 (surfaced as a placeholder note).
 */
import { useMemo } from "react";
import { useThreatStream } from "../hooks/useThreatStream";

function trustColor(t) {
  if (t === null || t === undefined) return "#5d7298";
  if (t >= 70) return "#00ff9d";
  if (t >= 40) return "#ffcc33";
  return "#ff3860";
}

export default function BiometricMonitor({ userId }) {
  const { biometric } = useThreatStream(40);

  const mine = useMemo(() => {
    const m = biometric.find((b) => b.userId === userId);
    return m || biometric[0] || null;
  }, [biometric, userId]);

  const trust = mine?.trust_score ?? null;
  const cold = mine?.cold_start ?? true;
  const reason = mine?.reason || "awaiting keystroke telemetry";
  const color = trustColor(trust);
  const pct = trust === null ? 0 : Math.max(0, Math.min(100, trust));

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Keystroke Dynamics</h2>
        <span className="muted small">Tier 1 · rolling-average z-score</span>
      </div>

      <div className="bio-grid">
        <div
          className="gauge"
          style={{
            "--g-color": color,
            "--g-pct": pct,
            color,
          }}
        >
          <div className="gauge-val" style={{ color }}>
            {trust === null ? "—" : Math.round(trust)}
          </div>
          <div className="gauge-lbl">trust</div>
        </div>
        <div className="bio-info">
          <div>
            <span className="muted">status</span>{" "}
            {cold
              ? <span className="pill pill-warn">cold-start</span>
              : <span className="pill pill-ok">active</span>}
          </div>
          <div className="small">{reason}</div>
          {mine && (
            <div className="small muted">
              z={mine.z} · baseline {mine.baselineN}/{mine.minSamples} events
            </div>
          )}
          <div className="small muted tier2">
            Tier 2: LSTM + RF/XGBoost/MLP ensemble, async SHAP explanations.
          </div>
        </div>
      </div>

      <ul className="feed">
        {biometric.slice(0, 8).map((b, i) => {
          const t = typeof b.trust_score === "number" ? b.trust_score : null;
          const ts = b.ts ? new Date(b.ts) : null;
          return (
            <li key={i} className="feed-item">
              <span className="cat-tag" style={{ background: trustColor(t) }}>
                {t === null ? "—" : Math.round(t)}
              </span>
              <div className="feed-body">
                <div className="feed-label">{b.reason || "biometric update"}</div>
                <div className="feed-meta">
                  {b.userId || "anon"} · batch {b.batchSize ?? "?"} · {ts && !isNaN(ts) ? ts.toLocaleTimeString() : "—"}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
