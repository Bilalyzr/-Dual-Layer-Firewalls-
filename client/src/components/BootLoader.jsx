/**
 * BootLoader — one-shot terminal "power-on" intro.
 *
 * Plays a scan-log boot sequence on first load: a terminal window types out
 * each firewall layer as it comes online — dim timestamp, module, dot leader,
 * green [ OK ] tag — with a blinking block cursor on the active line. When
 * the log completes the overlay fades and onDone hands over to the dashboard.
 * Honours prefers-reduced-motion by stepping fast.
 */
import { useEffect, useState } from "react";
import { IconShield } from "./Icons.jsx";

// [module, status] — the dot leader + timing are generated per line.
const STEPS = [
  ["core", "firewall pipeline", "online"],
  ["sanitizer", "layer 1/7", "armed"],
  ["sentiment", "layer 2/7", "armed"],
  ["cascade", "tf-idf + minilm-xgb", "armed"],
  ["attack-memory", "qdrant vectors", "linked"],
  ["behavioral", "redis event bus", "streaming"],
  ["rag-guard", "poisoning checks", "active"],
  ["decision", "policy fusion", "enforce"],
  ["llm-router", "glm → qwen → offline", "hedged"],
  ["audit", "postgres timeline", "recording"],
];
const FINAL = "ALL LAYERS NOMINAL — entering dashboard";

export default function BootLoader({ onDone }) {
  const [done, setDone] = useState(0); // completed lines (0..STEPS.length+1)
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    const total = STEPS.length + 1; // steps + final line
    const stepMs = reduced ? 40 : 165;

    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setDone(i);
      if (i >= total) {
        clearInterval(id);
        setTimeout(() => setLeaving(true), reduced ? 100 : 480);
        setTimeout(() => onDone?.(), reduced ? 350 : 1050);
      }
    }, stepMs);
    return () => clearInterval(id);
  }, [onDone]);

  const pct = Math.round((done / (STEPS.length + 1)) * 100);

  return (
    <div className={`boot ${leaving ? "boot-leave" : ""}`} role="status" aria-label="Loading dashboard">
      <div className="boot-center">
        <div className="boot-term">
          <div className="boot-term-bar">
            <span className="bt-dot" /><span className="bt-dot" /><span className="bt-dot" />
            <span className="bt-title"><IconShield size={11} /> orthrus — secure boot</span>
            <span className="bt-pct">{pct}%</span>
          </div>
          <div className="boot-term-body">
            <div className="bt-cmd">$ dlf-boot --secure</div>
            {STEPS.map(([mod, what, status], idx) => {
              if (idx > done) return null;
              const isDone = idx < done;
              return (
                <div key={mod} className={`bt-line${isDone ? "" : " bt-active"}`}>
                  <span className="bt-ts">[{(0.001 + idx * 0.037).toFixed(3)}]</span>
                  <span className="bt-mod">{mod.padEnd(13, " ")}</span>
                  <span className="bt-what">{what}</span>
                  <span className="bt-dots" />
                  {isDone
                    ? <span className="bt-ok">[ OK ] {status}</span>
                    : <span className="bt-cursor">█</span>}
                </div>
              );
            })}
            {done > STEPS.length && (
              <div className="bt-line bt-final">
                <span className="bt-ts">[{(0.001 + STEPS.length * 0.037).toFixed(3)}]</span>
                <span className="bt-final-txt">{FINAL}</span>
                <span className="bt-cursor">█</span>
              </div>
            )}
            {done <= STEPS.length && done < STEPS.length && (
              <div className="bt-line"><span className="bt-cursor">█</span></div>
            )}
          </div>
          <div className="boot-bar"><span style={{ width: `${pct}%` }} /></div>
        </div>
        <div className="boot-title">
          ORTHRUS <span>AI FIREWALL</span>
        </div>
      </div>
    </div>
  );
}
