/**
 * Behavioral trust fusion (Epic G).
 *
 * Keystroke, mouse, and touch each yield an independent authenticity signal.
 * Historically only keystroke drove the step-up decision; mouse/touch scores
 * were computed and thrown away. This fuses the available channels into a single
 * 0–100 trust used by the step-up enforcement hook.
 *
 * Design constraints (so existing behavior is preserved):
 *   - If NO auxiliary channel is present/usable, the fused trust equals the
 *     keystroke trust exactly (fused=false) — the pre-fusion code path.
 *   - A channel only contributes once it's out of cold-start (has a real
 *     baseline) and its sample is fresh.
 *   - Fusion can move trust in *either* direction: a corroborating channel
 *     raises it, a disagreeing channel lowers it — which is the point of
 *     multi-channel continuous auth.
 *
 * Scores from the mouse/touch routes are 0..1 (1 = matches baseline); keystroke
 * trust is 0..100. We normalize to 0..100 before weighting.
 */

// Default relative weights; renormalized over whichever channels are present.
const DEFAULT_WEIGHTS = { keystroke: 0.6, mouse: 0.25, touch: 0.15 };

// A channel sample older than this is considered stale and ignored, so a trust
// collapse can't be masked by a genuine score captured minutes earlier.
const DEFAULT_FRESHNESS_MS = 60_000;

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

/** Is fusion enabled? On by default; `BIOMETRIC_FUSION=off` reverts to keystroke-only. */
export function fusionEnabled() {
  return String(process.env.BIOMETRIC_FUSION || "on").toLowerCase() !== "off";
}

/**
 * @param {object} p
 * @param {number} p.keystrokeTrust  0..100 keystroke trust score
 * @param {boolean} [p.keystrokeColdStart]
 * @param {{score:number, coldStart?:boolean, ageMs?:number}|null} [p.mouse]  score 0..1
 * @param {{score:number, coldStart?:boolean, ageMs?:number}|null} [p.touch]  score 0..1
 * @param {object} [p.weights]
 * @param {number} [p.freshnessMs]
 * @returns {{fusedTrust:number, fused:boolean, channels:object, weights:object}}
 */
export function fuseTrust({
  keystrokeTrust,
  keystrokeColdStart = false,
  mouse = null,
  touch = null,
  weights = DEFAULT_WEIGHTS,
  freshnessMs = DEFAULT_FRESHNESS_MS,
} = {}) {
  const ks = clamp(Number(keystrokeTrust), 0, 100);

  // Fusion disabled → keystroke-only, unchanged path.
  if (!fusionEnabled()) {
    return { fusedTrust: ks, fused: false, channels: { keystroke: ks }, weights: {} };
  }

  const usable = (ch) =>
    ch &&
    Number.isFinite(ch.score) &&
    !ch.coldStart &&
    (ch.ageMs == null || ch.ageMs <= freshnessMs);

  // Build the weighted set. Keystroke always participates unless it's cold-start
  // (in which case there's nothing meaningful to fuse against and we return it
  // as-is to preserve the cold-start semantics the enforcement hook relies on).
  const parts = [];
  const channels = { keystroke: ks };
  if (!keystrokeColdStart) parts.push({ w: weights.keystroke, v: ks });

  if (usable(mouse)) {
    const v = clamp(mouse.score * 100, 0, 100);
    channels.mouse = +v.toFixed(1);
    parts.push({ w: weights.mouse, v });
  }
  if (usable(touch)) {
    const v = clamp(touch.score * 100, 0, 100);
    channels.touch = +v.toFixed(1);
    parts.push({ w: weights.touch, v });
  }

  // No auxiliary channel (or keystroke cold-start with no aux) → no fusion.
  const auxCount = parts.length - (keystrokeColdStart ? 0 : 1);
  if (auxCount <= 0 || parts.length === 0) {
    return { fusedTrust: ks, fused: false, channels, weights: {} };
  }

  const totalW = parts.reduce((s, p) => s + p.w, 0) || 1;
  const fusedTrust = +clamp(
    parts.reduce((s, p) => s + p.w * p.v, 0) / totalW,
    0,
    100
  ).toFixed(1);

  const norm = {};
  for (const k of Object.keys(channels)) {
    if (k === "keystroke") norm[k] = keystrokeColdStart ? 0 : +(weights.keystroke / totalW).toFixed(3);
    else norm[k] = +(weights[k] / totalW).toFixed(3);
  }

  return { fusedTrust, fused: true, channels, weights: norm };
}

export { DEFAULT_WEIGHTS, DEFAULT_FRESHNESS_MS };
