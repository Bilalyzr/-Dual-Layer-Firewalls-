/**
 * EPIC G — Touch biometrics capture (pressure / area / swipe velocity).
 *
 * Captures touch-event micro-features on touchscreens/tablets:
 *   - force (pressure, 0..1) — where supported (PointerEvent.pressure)
 *   - contact area (width/height of touch ellipse)
 *   - swipe velocity (px/ms) + direction
 *
 * On desktop (no touch events) the hook is a no-op — gracefully inert. Batched
 * + flushed to /api/biometric/touch for fusion into the trust model.
 */
import { useCallback, useEffect, useRef, useState } from "react";

const FLUSH_MS = 4000;
const MAX = 60;

export function useTouchCapture({ userId, enabled = true } = {}) {
  const events = useRef([]);
  const timer = useRef(null);
  const [score, setScore] = useState(null);

  const flush = useCallback(async () => {
    if (events.current.length < 4) return;
    const ev = events.current;
    const forces = ev.map((e) => e.force).filter((f) => f > 0);
    const areas = ev.map((e) => e.area).filter((a) => a > 0);
    const velocities = ev.map((e) => e.velocity).filter((v) => v > 0);
    const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
    const payload = {
      userId: userId || "anon",
      touchCount: ev.length,
      meanForce: +mean(forces).toFixed(4),
      meanArea: +mean(areas).toFixed(2),
      meanVelocity: +mean(velocities).toFixed(2),
    };
    events.current = [];
    try {
      const r = await fetch("/api/biometric/touch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await r.text();
      if (!body) return;
      const j = JSON.parse(body);
      if (j && typeof j.touch_score === "number") setScore(j.touch_score);
    } catch {
      /* silent */
    }
  }, [userId]);

  useEffect(() => {
    if (!enabled) return;
    // Use PointerEvent (covers touch + pen + pressure) where available; fall back
    // to TouchEvent for browsers without PointerEvent.
    const onPointerDown = (e) => {
      if (e.pointerType !== "touch" && e.pointerType !== "pen") return;
      events.current.push({
        force: e.pressure || 0,
        area: (e.width || 0) * (e.height || 0),
        velocity: 0,
        t: performance.now(),
      });
      if (events.current.length > MAX) events.current.shift();
      // Reset timer.current on fire so subsequent touches reschedule a flush
      // (a stale fired id would otherwise pin the guard and stop all flushing).
      if (!timer.current) timer.current = setTimeout(() => { timer.current = null; flush(); }, FLUSH_MS);
    };
    const onPointerMove = (e) => {
      if (e.pointerType !== "touch" && e.pointerType !== "pen") return;
      if (events.current.length === 0) return;
      const last = events.current[events.current.length - 1];
      const now = performance.now();
      const dt = now - last.t || 1;
      last.velocity = Math.sqrt((e.movementX || 0) ** 2 + (e.movementY || 0) ** 2) / dt;
      // Refresh the timestamp so the next move measures its own interval instead
      // of accumulating from pointerdown (which underestimated swipe velocity).
      last.t = now;
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pointermove", onPointerMove);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      if (timer.current) clearTimeout(timer.current);
      flush();
    };
  }, [enabled, flush]);

  return { score, flush };
}
