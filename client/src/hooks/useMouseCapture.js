/**
 * EPIC G — mouse-dynamics capture hook.
 *
 * Captures mouse movement micro-features that are hard to forge and fuse them
 * with keystroke dynamics into a single behavioral trust signal:
 *   - move cadence (events/sec)
 *   - mean speed (px/ms)
 *   - direction-change rate (curvature)
 *   - click intervals
 *
 * Batched + flushed to the proxy's /api/biometric/mouse endpoint, which fuses
 * the mouse score with the keystroke score. Attach the returned listener-attach
 * fn to the window (mouse events are global).
 */
import { useCallback, useEffect, useRef, useState } from "react";

const FLUSH_MS = 3000;
const MAX_POINTS = 80; // rolling window of move samples

export function useMouseCapture({ userId, enabled = true } = {}) {
  const moves = useRef([]); // [{x, y, t}]
  const clicks = useRef([]); // [t]
  const timer = useRef(null);
  const [score, setScore] = useState(null);

  const flush = useCallback(async () => {
    if (moves.current.length < 5) return;
    // compute compact summary stats, then clear the raw window
    const m = moves.current;
    const speeds = [];
    let turns = 0;
    for (let i = 1; i < m.length; i++) {
      const dx = m[i].x - m[i - 1].x;
      const dy = m[i].y - m[i - 1].y;
      const dt = m[i].t - m[i - 1].t || 1;
      speeds.push(Math.sqrt(dx * dx + dy * dy) / dt);
      if (i >= 2) {
        // crude direction-change: sign flip in dx or dy
        const pdx = m[i - 1].x - m[i - 2].x;
        const pdy = m[i - 1].y - m[i - 2].y;
        if (Math.sign(dx) !== Math.sign(pdx) || Math.sign(dy) !== Math.sign(pdy)) turns++;
      }
    }
    const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
    const payload = {
      userId: userId || "anon",
      moveCount: m.length,
      meanSpeed: +mean(speeds).toFixed(3),
      turnRate: +(turns / Math.max(1, m.length)).toFixed(3),
      cadence: +(m.length / ((m[m.length - 1].t - m[0].t) / 1000 || 1)).toFixed(2),
      clickCount: clicks.current.length,
      clickIntervals: clicks.current.slice(-12),
    };
    moves.current = [];
    clicks.current = [];
    try {
      const res = await fetch("/api/biometric/mouse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.text();
      if (!body) return;
      const j = JSON.parse(body);
      if (j && typeof j.mouse_score === "number") setScore(j.mouse_score);
    } catch {
      /* keep capturing silently */
    }
  }, [userId]);

  useEffect(() => {
    if (!enabled) return;
    const onMove = (e) => {
      moves.current.push({ x: e.clientX, y: e.clientY, t: performance.now() });
      if (moves.current.length > MAX_POINTS) moves.current.shift();
      // Reset timer.current when the timeout fires so the next move can schedule
      // another flush — otherwise the stale (fired) id keeps the guard truthy and
      // only one flush ever happens for the lifetime of the hook.
      if (!timer.current) timer.current = setTimeout(() => { timer.current = null; flush(); }, FLUSH_MS);
    };
    const onDown = () => clicks.current.push(performance.now());
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mousedown", onDown);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mousedown", onDown);
      if (timer.current) clearTimeout(timer.current);
      flush();
    };
  }, [enabled, flush]);

  return { score, flush };
}
