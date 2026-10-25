/**
 * ModuleScoreBreakdown — Visualizes the individual scores (0–100%) for each of
 * the 6 security analysis modules on every evaluated prompt:
 *   1. Prompt Sanitization
 *   2. AI Threat Detection
 *   3. Semantic Attack Memory
 *   4. Behavioral Analysis
 *   5. RAG Security
 *   6. Final Multi-Signal Decision Engine
 *
 * Includes both:
 *   - <ModuleScoreCard />: Compact inline card rendered inside ChatPanel messages
 *   - <ModuleAnalysisPanel />: Dedicated live telemetry inspector panel for the dashboard
 */
import { useEffect, useState } from "react";
import { useThreatStream } from "../hooks/useThreatStream";
import { fmtTime } from "../lib/format";

const MODULE_META = [
  {
    key: "promptSanitization",
    shortLabel: "Prompt Sanitization",
    layerTag: "L1",
    desc: "Regex heuristics · PII scrubbing · Obfuscation & Lexicon weightage",
  },
  {
    key: "aiThreatDetection",
    shortLabel: "AI Threat Detection",
    layerTag: "L2",
    desc: "Two-tier Cascade (TF-IDF fast screen → MiniLM-L6-v2 + XGBoost deep head)",
  },
  {
    key: "semanticAttackMemory",
    shortLabel: "Semantic Attack Memory",
    layerTag: "MEM",
    desc: "Qdrant vector cosine similarity against known-blocked attacks + signatures",
  },
  {
    key: "behavioralAnalysis",
    shortLabel: "Behavioral Analysis",
    layerTag: "L3",
    desc: "Stateful Redis session EWMA risk · Semantic trajectory drift · Attack proximity",
  },
  {
    key: "ragSecurity",
    shortLabel: "RAG Security",
    layerTag: "L4",
    desc: "Retrieved context consistency · Imperative injection · Credential leak filter",
  },
  {
    key: "finalDecisionEngine",
    shortLabel: "Final Decision Engine",
    layerTag: "L5",
    desc: "Multi-signal policy fusion · Corroboration rules · Final verdict",
  },
];

function scoreColor(score, isDecision = false, blocked = false) {
  if (isDecision && blocked) return "var(--red)";
  if (score >= 70) return "var(--red)";
  if (score >= 35) return "var(--yellow)";
  return "var(--green)";
}

function formatSubMetrics(key, mod) {
  if (!mod) return [];
  switch (key) {
    case "promptSanitization":
      return [
        { k: "Lexicon Weightage", v: `${mod.wordWeightage ?? 0}%` },
        { k: "Heuristic Match", v: mod.heuristicMatched ? "YES (Flagged)" : "Clean" },
        {
          k: "Scrubbed Patterns",
          v: mod.removed?.length ? mod.removed.slice(0, 3).join(", ") : "None",
        },
        { k: "Latency", v: `${Number(mod.latencyMs || 0).toFixed(2)} ms` },
      ];
    case "aiThreatDetection":
      return [
        { k: "Deep Intent Score", v: `${mod.intentScore ?? mod.score ?? 0}%` },
        { k: "Fast TF-IDF Score", v: mod.tfidfScore != null ? `${mod.tfidfScore}%` : "N/A" },
        { k: "Active Tier", v: (mod.cascadeTier || "deep").toUpperCase() },
        { k: "Model", v: mod.model || "MiniLM-L6-v2 + XGBoost" },
      ];
    case "semanticAttackMemory":
      return [
        { k: "Vector Similarity", v: `${mod.similarity ?? mod.score ?? 0}%` },
        { k: "Block Threshold", v: `≥ ${mod.threshold ?? 92}%` },
        { k: "Signature Cache", v: mod.signatureHits > 0 ? `${mod.signatureHits} prior hits` : "New pattern" },
        {
          k: "Matched Recall",
          v:
            mod.knownAttack && ((mod.similarity ?? mod.score ?? 0) >= 65 || mod.signatureHits > 0)
              ? `"${mod.knownAttack.slice(0, 42)}…"`
              : "No match",
        },
      ];
    case "behavioralAnalysis":
      return [
        { k: "Cumulative EWMA", v: `${mod.cumulativeRisk ?? mod.score ?? 0}%` },
        { k: "Semantic Drift", v: `${mod.drift ?? 0}%` },
        { k: "Attack Proximity", v: `${mod.attackProximity ?? 0}%` },
        { k: "Session Turn", v: `Turn #${mod.turnCount ?? 1}` },
      ];
    case "ragSecurity":
      return [
        { k: "Context Risk", v: `${mod.score ?? 0}%` },
        { k: "Safe Docs Passed", v: `${mod.safeDocs ?? 0} docs` },
        {
          k: "Dropped Poisoned",
          v: mod.droppedDocs?.length ? `${mod.droppedDocs.length} dropped` : "0 dropped",
        },
        {
          k: "Imperative Flags",
          v: mod.imperativeFlags?.length ? mod.imperativeFlags.join(", ") : "None",
        },
      ];
    case "finalDecisionEngine":
      return [
        { k: "Final Verdict", v: mod.verdict || mod.status || "ALLOW" },
        { k: "Triggered By", v: mod.triggeredBy || "none" },
        { k: "Gate Threshold", v: `≥ ${mod.threshold ?? 65}%` },
        { k: "Total Pipeline", v: `${Number(mod.latencyMs || 0).toFixed(1)} ms` },
      ];
    default:
      return [];
  }
}

/**
 * Dedicated dashboard panel showing the full 6-module telemetry for the latest
 * prompt (or any selected historical prompt from the session).
 */
export default function ModuleAnalysisPanel({ latestFromChat = null }) {
  const { moduleAnalyses, connected } = useThreatStream(30);
  const [selectedIdx, setSelectedIdx] = useState(0);

  // Merge SSE stream with any direct chat callback so it works immediately
  const history = [...moduleAnalyses];
  if (
    latestFromChat &&
    !history.some((h) => h.ts === latestFromChat.ts && h.prompt === latestFromChat.prompt)
  ) {
    history.unshift(latestFromChat);
  }

  const headKey = history[0] ? `${history[0].ts}:${history[0].prompt}` : "";
  useEffect(() => {
    setSelectedIdx(0);
  }, [headKey]);

  const active = history[selectedIdx] || history[0] || null;
  const finalMod = active?.finalDecisionEngine || {};
  const isBlocked = Boolean(active?.blocked || finalMod.verdict === "BLOCK");

  return (
    <section className="panel p-modules">
      <div className="panel-head">
        <h2>
          Multi-Module Security Scores{" "}
          <small>Per-Prompt Evaluation Breakdown</small>
        </h2>
        <span className="muted small">{history.length} evaluated</span>
        <span
          className={`dot ${connected ? "dot-on" : "dot-off"}`}
          title={connected ? "live SSE stream" : "disconnected"}
        />
      </div>

      {!active ? (
        <div className="mod-panel-empty muted small">
          Send any prompt in the LLM Chat panel to inspect individual scores across
          Prompt Sanitization, AI Threat Detection, Semantic Attack Memory,
          Behavioral Analysis, RAG Security, and the Final Multi-Signal Decision Engine.
        </div>
      ) : (
        <>
          {/* Prompt selector bar if multiple prompts have been evaluated */}
          {history.length > 1 && (
            <div className="mod-history-bar">
              <span className="muted small">Prompt History:</span>
              <div className="mod-history-pills">
                {history.slice(0, 8).map((item, idx) => {
                  const blk = Boolean(item.blocked || item.finalDecisionEngine?.verdict === "BLOCK");
                  return (
                    <button
                      key={idx}
                      type="button"
                      className={`mod-hist-btn${idx === selectedIdx ? " mod-hist-btn-on" : ""}`}
                      onClick={() => setSelectedIdx(idx)}
                      title={item.prompt}
                    >
                      <span
                        className="mod-hist-dot"
                        style={{ background: blk ? "var(--red)" : "var(--green)" }}
                      />
                      #{history.length - idx} ({item.finalDecisionEngine?.score ?? 0}%)
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Active prompt header banner */}
          <div className="mod-active-prompt">
            <div className="mod-active-prompt-top">
              <span className="muted small">
                USER <b>{active.userId || "anon"}</b> ·{" "}
                {active.ts ? fmtTime(new Date(active.ts)) : "just now"}
              </span>
              <span className={`pill ${isBlocked ? "pill-bad" : "pill-ok"}`}>
                {isBlocked ? `BLOCKED (${active.category || "LLM01"})` : "ALLOWED"} · COMPOSITE{" "}
                {finalMod.score ?? 0}%
              </span>
            </div>
            <div className="mod-active-prompt-text mono">
              “{active.prompt || "—"}”
            </div>
            {finalMod.reason && (
              <div className="mod-active-reason small">
                <b>Decision Rationale:</b> {finalMod.reason}{" "}
                {finalMod.triggeredBy && finalMod.triggeredBy !== "none" && (
                  <span className="muted">
                    (Primary trigger: <code>{finalMod.triggeredBy}</code>)
                  </span>
                )}
              </div>
            )}
          </div>

          {/* 6 Module Detailed Cards */}
          <div className="mod-inspector-grid">
            {MODULE_META.map(({ key, shortLabel, layerTag, desc }) => {
              const mod = active[key] || { score: 0, status: "—" };
              const score = Math.round(mod.score ?? 0);
              const isDecision = key === "finalDecisionEngine";
              const color = scoreColor(score, isDecision, isBlocked);
              const subRows = formatSubMetrics(key, mod);

              return (
                <div
                  key={key}
                  className={`mod-inspector-card${isDecision ? " mod-inspector-card-final" : ""}`}
                >
                  <div className="mod-inspector-head">
                    <div>
                      <span className="mod-layer-badge">{layerTag}</span>
                      <span className="mod-inspector-title">{shortLabel}</span>
                    </div>
                    <div className="mod-inspector-score" style={{ color }}>
                      {score}
                      <small>/100</small>
                    </div>
                  </div>
                  <div className="mod-inspector-desc muted">{desc}</div>
                  <div className="mod-score-bar mod-score-bar-lg">
                    <i
                      style={{
                        width: `${Math.max(2, Math.min(100, score))}%`,
                        background: color,
                        boxShadow: `0 0 8px ${color}`,
                      }}
                    />
                  </div>
                  <div className="mod-submetrics mod-submetrics-open">
                    {subRows.map((r) => (
                      <div key={r.k} className="mod-submetric-row">
                        <span className="muted">{r.k}</span>
                        <span className="mono">{r.v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}
