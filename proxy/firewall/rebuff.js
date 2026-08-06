/**
 * Rebuff-style multi-layer prompt-injection defense (Protect AI approach).
 *
 * The `rebuff` npm package is TypeScript-only (Node can't strip types from
 * node_modules), so we implement the same 4-layer defense natively — reusing
 * the layers we already built (heuristics, canary, ML classifier):
 *
 *   Layer 1: Heuristic detection (our existing regex rules)
 *   Layer 2: Canary token detection (EPIC F — system-prompt exfil)
 *   Layer 3: ML classification (our existing ensemble via /classify)
 *   Layer 4: Vector similarity (embedding outlier — EPIC F)
 *
 * The combined score = max across all layers. A threat flagged by ANY layer
 * is enough to block — true defense-in-depth, matching Rebuff's design.
 *
 * This runs in the proxy alongside the existing firewall pipeline and adds a
 * `rebuff` verdict to the response so the dashboard can surface it.
 */
import { runHeuristics } from "./heuristics.js";
import { detectCanaryLeak } from "./canary.js";

/**
 * Run the 4-layer Rebuff-style defense on a prompt.
 *
 * @param {string} prompt
 * @param {{ threatProbability: number, outlierFlag: boolean }} mlResult — from the engine
 * @returns {{ score: number, detected: boolean, layers: object }}
 */
export function rebuffCheck(prompt, mlResult = {}) {
  // Layer 1: Heuristics
  const heur = runHeuristics(prompt);
  const heuristicScore = heur.matched ? 1.0 : 0.0;

  // Layer 2: Canary (only relevant for outputs, but check for completeness)
  const canary = detectCanaryLeak(prompt);
  const canaryScore = canary.leaked ? 1.0 : 0.0;

  // Layer 3: ML classifier probability
  const mlScore = mlResult.threatProbability || 0;

  // Layer 4: Embedding outlier (if available)
  const outlierScore = mlResult.outlierFlag ? 0.8 : 0;

  // Combined: max across layers (any layer flagging = threat)
  const score = Math.max(heuristicScore, canaryScore, mlScore, outlierScore);
  const detected = score >= 0.5;

  return {
    score: +score.toFixed(4),
    detected,
    layers: {
      heuristic: { score: heuristicScore, matched: heur.matched, signals: heur.signals.length },
      canary: { score: canaryScore, leaked: canary.leaked },
      ml: { score: +mlScore.toFixed(4), ready: mlResult.ready !== false },
      outlier: { score: outlierScore, flagged: mlResult.outlierFlag || false },
    },
  };
}
