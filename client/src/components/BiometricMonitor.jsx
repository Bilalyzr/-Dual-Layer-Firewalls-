/**
 * BiometricMonitor — active-session trust score panel (Req 4.2).
 *
 * Shows the latest continuous-authentication decision for the local user plus
 * the rolling history of biometric events from the SSE stream. Tier 2: when the
 * engine emits a shap_request_id, we poll /api/shap/:id (async, off-path) and
 * render the top contributing features (Req 3.4).
 */
import { useEffect, useMemo, useState } from "react";
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
  const modelUsed = mine?.model_used || "zscore";
  const pGenuine = mine?.p_genuine;
  const shapRequestId = mine?.shap_request_id;
  const color = trustColor(trust);
  const pct = trust === null ? 0 : Math.max(0, Math.min(100, trust));

  // Poll for the async SHAP result when a request id arrives (Req 3.4).
  const [shap, setShap] = useState(null);
  useEffect(() => {
    if (!shapRequestId) return;
    setShap(null);
    let cancelled = false;
    const poll = async () => {
      try {
        const r = await fetch(`/api/shap/${shapRequestId}`).then((x) => x.json());
        if (cancelled) return;
        if (r.status === "done" && r.result) {
          setShap(r.result);
          return true;
        }
        if (r.status === "error") {
          setShap({ error: r.error });
          return true;
        }
        return false;
      } catch {
        return false;
      }
    };
    const tryPoll = async () => {
      const done = await poll();
      if (done || cancelled) return;
      timer = setTimeout(tryPoll, 800);
    };
    let timer = setTimeout(tryPoll, 300);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [shapRequestId]);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Keystroke Dynamics</h2>
        <span className="muted small">
          {modelUsed === "ensemble" ? "Tier 2 · LSTM + RF/GB/MLP ensemble" : "Tier 1 · rolling-average z-score"}
        </span>
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
              {modelUsed === "ensemble" && pGenuine != null
                ? `P(genuine)=${pGenuine.toFixed(2)} · z=${mine.z}`
                : `z=${mine.z}`} · baseline {mine.baselineN}/{mine.minSamples} events
            </div>
          )}
          <div className="shap-block">
            <div className="shap-title muted small">SHAP explanation (async)</div>
            {shap?.error ? (
              <div className="small muted">shap error: {String(shap.error).slice(0, 60)}</div>
            ) : !shapRequestId ? (
              <div className="small muted">awaiting ensemble decision…</div>
            ) : !shap ? (
              <div className="small muted">computing top features…</div>
            ) : (
              <ul className="shap-list">
                {(shap.features || []).map((f, i) => (
                  <li key={i} className={`shap-row shap-${f.direction}`}>
                    <span className="shap-name">{f.name}</span>
                    <span className="shap-bar-wrap">
                      <span
                        className="shap-bar"
                        style={{ width: `${Math.min(100, Math.abs(f.shap) * 100)}%` }}
                      />
                    </span>
                    <span className="shap-val">{f.shap >= 0 ? "+" : ""}{f.shap.toFixed(3)}</span>
                  </li>
                ))}
              </ul>
            )}
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
