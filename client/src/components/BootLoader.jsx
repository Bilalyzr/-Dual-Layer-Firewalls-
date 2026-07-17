/**
 * BootLoader — one-shot SecOps "power-on" intro.
 *
 * Plays a HUD boot sequence on first load: the 3D shield spins up inside an
 * energy ring, system-check lines resolve to `ok` one by one, and a progress
 * bar fills. When the sequence completes it fades out and calls onDone so the
 * dashboard takes over. Honours prefers-reduced-motion by skipping fast.
 */
import { useEffect, useState } from "react";
import Logo from "./Logo.jsx";

const STEPS = [
  "INITIALIZING FIREWALL CORE",
  "LOADING SEMANTIC CLASSIFIER",
  "CALIBRATING KEYSTROKE BIOMETRICS",
  "LINKING NODE PROXY · MONGODB",
  "SYSTEM READY",
];

export default function BootLoader({ onDone }) {
  const [done, setDone] = useState(0); // number of completed steps
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const stepMs = reduced ? 90 : 480;

    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setDone(i);
      if (i >= STEPS.length) {
        clearInterval(id);
        setTimeout(() => setLeaving(true), reduced ? 120 : 520);
        setTimeout(() => onDone?.(), reduced ? 400 : 1120);
      }
    }, stepMs);
    return () => clearInterval(id);
  }, [onDone]);

  const pct = Math.round((done / STEPS.length) * 100);

  return (
    <div className={`boot ${leaving ? "boot-leave" : ""}`} role="status" aria-label="Loading dashboard">
      <div className="boot-center">
        <div className="boot-logo">
          <span className="boot-ring" />
          <span className="boot-ring boot-ring-2" />
          <Logo idPrefix="boot" />
        </div>

        <div className="boot-title">
          DUAL-LAYER <span>AI FIREWALL</span>
        </div>
        <div className="boot-sub">
          SEMANTIC PROMPT-INJECTION DEFENSE · BEHAVIORAL KEYSTROKE AUTH
        </div>

        <ul className="boot-log">
          {STEPS.map((s, idx) => {
            if (idx > done) return null;
            const isDone = idx < done;
            const isLast = idx === STEPS.length - 1;
            return (
              <li key={s} className={isDone ? "on" : "active"}>
                <span className="boot-caret">&gt;</span>
                <span className="boot-step">{s}</span>
                <span className="boot-dots" />
                <span className="boot-ok">
                  {isDone ? (isLast ? "online" : "ok") : <span className="boot-cursor">▋</span>}
                </span>
              </li>
            );
          })}
        </ul>

        <div className="boot-bar">
          <span style={{ width: `${pct}%` }} />
        </div>
        <div className="boot-pct">{pct}%</div>
      </div>
    </div>
  );
}
