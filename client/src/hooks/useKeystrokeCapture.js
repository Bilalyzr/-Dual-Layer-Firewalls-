/**
 * useKeystrokeCapture — Keystroke Dynamics telemetry hook (Req 3.1).
 *
 * Captures:
 *   dwell time  = keyup - keydown        (key held duration)
 *   flight time = keydown[N+1] - keyup[N] (gap to next key)
 *
 * Uses performance.now() for sub-ms client resolution, then batches compact
 * arrays and POSTs them to /api/biometric/batch. The PRD notes timer precision
 * varies by OS/browser — we report what we measure, no uniformity assumed.
 *
 * Attach the returned `ref` to the input element you want to monitor.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../lib/api";

const BATCH_SIZE = 6;            // flush after this many events (responsive gauge)
const FLUSH_MS = 1500;           // …or after this idle window (was 4s — felt laggy)
const API = "/api/biometric/batch";

export function useKeystrokeCapture({ userId, enabled = true } = {}) {
  const ref = useRef(null);
  const events = useRef([]);            // [{d, f}]
  const lastKeyUp = useRef(null);       // {key, ts}
  const timer = useRef(null);
  const lastResult = useRef(null);
  const [trust, setTrust] = useState({ trust_score: 100, cold_start: true, reason: "waiting…" });

  const flush = useCallback(async () => {
    if (events.current.length === 0) return;
    const batch = events.current.splice(0, events.current.length).map((ev) => ({ d: ev.d, f: ev.f }));
    try {
      const res = await apiFetch(API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: userId || "anon", events: batch }),
      }, userId);
      const body = await res.text();
      if (!body) return; // empty response (proxy down / timeout) — keep collecting
      let j;
      try { j = JSON.parse(body); } catch { return; }
      if (j && typeof j.trust_score === "number") {
        lastResult.current = j;
        setTrust(j);
      }
    } catch (err) {
      // network error — keep collecting; proxy may be briefly unavailable
    }
  }, [userId]);

  const scheduleFlush = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(flush, FLUSH_MS);
  }, [flush]);

  // Attach listeners to the bound element.
  useEffect(() => {
    const el = ref.current;
    if (!el || !enabled) return;

    const onKeyDown = (e) => {
      // Ignore pure modifier keys; they distort flight timing.
      if (e.key === "Shift" || e.key === "Control" || e.key === "Alt" || e.key === "Meta") return;
      const now = performance.now();
      // Flight time from previous keyup to this keydown.
      if (lastKeyUp.current) {
        const flight = now - lastKeyUp.current.ts;
        // dwell placeholder; filled on keyup with same key
        events.current.push({ d: 0, f: Math.round(flight * 100) / 100, _down: now, _key: e.key });
      } else {
        events.current.push({ d: 0, f: 0, _down: now, _key: e.key });
      }
      lastKeyUp.current = null;
      if (events.current.length >= BATCH_SIZE) flush();
      else scheduleFlush();
    };

    const onKeyUp = (e) => {
      if (e.key === "Shift" || e.key === "Control" || e.key === "Alt" || e.key === "Meta") return;
      const now = performance.now();
      // Find the most recent keydown without a dwell value for this key.
      for (let i = events.current.length - 1; i >= 0; i--) {
        const ev = events.current[i];
        if (ev._key === e.key && ev.d === 0) {
          ev.d = Math.round((now - ev._down) * 100) / 100;
          break;
        }
      }
      lastKeyUp.current = { key: e.key, ts: now };
    };

    el.addEventListener("keydown", onKeyDown);
    el.addEventListener("keyup", onKeyUp);
    return () => {
      el.removeEventListener("keydown", onKeyDown);
      el.removeEventListener("keyup", onKeyUp);
      if (timer.current) clearTimeout(timer.current);
      flush();
    };
  }, [enabled, flush, scheduleFlush]);

  // Clean internal fields before exposing.
  const sanitize = (ev) => ({ d: ev.d, f: ev.f });

  return { ref, trust, flush, pending: events.current };
}
