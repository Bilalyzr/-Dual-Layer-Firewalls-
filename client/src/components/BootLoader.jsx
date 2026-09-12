/**
 * BootLoader — "Dual-Layer Gate" power-on intro.
 *
 * A ~2s hero animation that performs the product: the Orthrus shield draws
 * itself, two firewall layers slide in and lock, glowing packets stream
 * through both layers — one flashes red and is deflected (blocked) — while
 * a step ticker + progress bar track the boot. Any click or key skips.
 * Honours prefers-reduced-motion with a static composition + fast steps.
 */
import { useEffect, useRef, useState } from "react";

const STEPS = ["sanitize", "semantic", "cascade", "behavior", "decision", "ready"];

export default function BootLoader({ onDone }) {
  const [done, setDone] = useState(0);
  const [leaving, setLeaving] = useState(false);
  const timers = useRef([]);
  const skipped = useRef(false);
  const skipRef = useRef(() => {});

  useEffect(() => {
    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const stepMs = reduced ? 40 : 270;

    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setDone(i);
      if (i >= STEPS.length) {
        clearInterval(id);
        timers.current.push(setTimeout(() => setLeaving(true), reduced ? 120 : 640));
        timers.current.push(setTimeout(() => onDone?.(), reduced ? 400 : 1090));
      }
    }, stepMs);

    const skip = () => {
      if (skipped.current) return;
      skipped.current = true;
      clearInterval(id);
      timers.current.forEach(clearTimeout);
      setDone(STEPS.length);
      setLeaving(true);
      timers.current.push(setTimeout(() => onDone?.(), 320));
    };
    skipRef.current = skip;
    window.addEventListener("keydown", skip);

    return () => {
      clearInterval(id);
      window.removeEventListener("keydown", skip);
      timers.current.forEach(clearTimeout);
    };
  }, [onDone]);

  const pct = Math.round((Math.min(done, STEPS.length) / STEPS.length) * 100);
  const ready = done >= STEPS.length;

  return (
    <div
      className={`boot ${leaving ? "boot-leave" : ""}`}
      role="status"
      aria-label="Loading dashboard — click to skip"
      onClick={() => skipRef.current()}
    >
      <div className="boot-center">
        <div className="gate-visual" aria-hidden="true">
          <div className="gate-track" />
          <div className="gate-layer gate-layer-1" />
          <div className="gate-layer gate-layer-2" />
          <span className="gate-flash gate-flash-1" />
          <span className="gate-flash gate-flash-2" />
          <svg className="gate-shield" viewBox="0 0 64 64">
            <defs>
              <linearGradient id="gateGrad" x1="32" y1="6" x2="32" y2="58" gradientUnits="userSpaceOnUse">
                <stop offset="0" stopColor="#7dd3fc" />
                <stop offset="0.55" stopColor="#3b82f6" />
                <stop offset="1" stopColor="#1d4ed8" />
              </linearGradient>
            </defs>
            <path
              className="draw"
              d="M32 4 L56 12 V30 C56 44 46 54 32 60 C18 54 8 44 8 30 V12 Z"
              fill="rgba(13, 19, 34, 0.85)"
              stroke="url(#gateGrad)"
              strokeWidth="2.5"
              pathLength="100"
            />
            <g className="heads">
              <path d="M22 11 L29 11 L30.5 19 L27 21 L9 25.5 L26 31 L29 33 L27 45 L21.5 39 Z" fill="url(#gateGrad)" />
              <path d="M42 11 L35 11 L33.5 19 L37 21 L55 25.5 L38 31 L35 33 L37 45 L42.5 39 Z" fill="url(#gateGrad)" />
            </g>
            <g className="eyes">
              <circle cx="23.5" cy="20.5" r="1.7" fill="#e6eaf2" />
              <circle cx="40.5" cy="20.5" r="1.7" fill="#e6eaf2" />
            </g>
          </svg>
          {[0, 1, 2, 3, 5].map((i) => (
            <span key={i} className="gate-packet" style={{ "--i": i }} />
          ))}
          <span className="gate-packet gate-packet-bad" style={{ "--i": 4 }} />
        </div>

        <div className={`gate-readout${ready ? " gate-ready" : ""}`}>
          <span>
            {ready ? "ALL LAYERS NOMINAL — " : "inspecting · "}
            <b>{ready ? "ready" : STEPS[Math.min(done, STEPS.length - 1)]}</b>
          </span>
          <span className="gate-pct">{pct}%</span>
        </div>
        <div className="boot-bar"><span style={{ width: `${pct}%` }} /></div>

        <div className="boot-title">
          ORTHRUS <span>AI FIREWALL</span>
        </div>
        <div className="gate-skiphint">click or press any key to skip</div>
      </div>
    </div>
  );
}
