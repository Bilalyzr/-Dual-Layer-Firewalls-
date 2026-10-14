/**
 * ThoughtLine — the react-bits "thought-line" micro component, ported
 * dependency-free for Orthrus (no motion/hugeicons: CSS transitions and our
 * own vector icons). Behavior preserved:
 *
 *   working:  breathing glyph + shimmering label + live clock, with a
 *             collapsible reasoning-trace of steps (tick = done, pulse = active)
 *   settled:  label crossfades to "Thought for X.Xs", the clock glides up
 *             beside it, the trace folds into the single line
 *
 * The 7-layer pipeline feeds `steps` + `activeIndex` while a prompt is being
 * inspected; the assistant message header reuses the settled state.
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { IconCheck, IconChevronDown, IconStarburst } from "./Icons.jsx";
import "./ThoughtLine.css";

const fmt = (ds) =>
  ds < 600 ? `${(ds / 10).toFixed(1)}s` : `${Math.floor(ds / 600)}m ${((ds % 600) / 10).toFixed(1)}s`;

export default function ThoughtLine({
  label = "Thinking…",
  doneLabel = "",
  steps = [],
  activeIndex = steps.length, // steps before this index are done while working
  working = true,
  elapsed = null, // seconds; overrides the live clock (settled messages)
  collapsible = true,
  fontSize = 16,
  showTimer = true,
  onSettle,
  className = "",
  style,
}) {
  const [open, setOpen] = useState(true);
  const isWorking = working;
  const doneText = doneLabel || (showTimer ? "Thought for" : "Done thinking");
  const hasTrace = steps.length > 0;

  const glyphRef = useRef(null);
  const stackRef = useRef(null);
  const timerRef = useRef(null);
  const workRef = useRef(null);
  const doneRef = useRef(null);
  const dsRef = useRef(0);
  const settledRef = useRef(false);

  useEffect(() => {
    if (isWorking) setOpen(true);
    else if (collapsible) setOpen(false);
  }, [isWorking, collapsible]);

  // live clock (or the recorded elapsed on settled messages)
  useLayoutEffect(() => {
    const t = timerRef.current;
    if (!t) return undefined;
    const paint = (ds) => {
      dsRef.current = ds;
      t.textContent = fmt(ds);
    };
    if (elapsed != null) {
      paint(Math.round(elapsed * 10));
      return undefined;
    }
    if (!isWorking) return undefined;
    const startedAt = performance.now();
    paint(0);
    const id = setInterval(() => paint(Math.floor((performance.now() - startedAt) / 100)), 100);
    return () => clearInterval(id);
  }, [isWorking, elapsed]);

  // glide the clock beside whichever label is active (the two texts share a
  // grid cell; the timer rides the width difference, react-bits' trick)
  useLayoutEffect(() => {
    const t = timerRef.current;
    const stack = stackRef.current;
    if (!t || !stack) return undefined;
    const place = () => {
      const active = isWorking ? workRef.current : doneRef.current;
      if (!active) return;
      t.style.transform = `translateX(${active.offsetWidth - stack.offsetWidth}px)`;
    };
    place();
    const ro = new ResizeObserver(place);
    if (workRef.current) ro.observe(workRef.current);
    if (doneRef.current) ro.observe(doneRef.current);
    return () => ro.disconnect();
  }, [isWorking, label, doneText, fontSize, showTimer]);

  // settle callback fires once, with the final seconds
  useEffect(() => {
    if (isWorking) {
      settledRef.current = false;
      return;
    }
    if (!settledRef.current) {
      settledRef.current = true;
      onSettle?.(elapsed != null ? elapsed : dsRef.current / 10);
    }
  }, [isWorking, elapsed, onSettle]);

  const toggle = hasTrace && collapsible;

  return (
    <div
      className={`thought-line${className ? ` ${className}` : ""}`}
      data-working={isWorking ? "" : undefined}
      data-open={open && hasTrace ? "" : undefined}
      style={{ "--tl-font": `${fontSize}px`, ...style }}
    >
      <div
        className="thought-line__head"
        role={toggle ? "button" : undefined}
        tabIndex={toggle ? 0 : -1}
        aria-expanded={toggle ? open : undefined}
        onClick={() => toggle && setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (toggle && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); setOpen((v) => !v); }
        }}
      >
        <span ref={glyphRef} className="thought-line__glyph" aria-hidden="true">
          <IconStarburst size="100%" />
        </span>
        <span ref={stackRef} className="thought-line__label" aria-hidden="true">
          <span ref={workRef} className="thought-line__text" data-active={isWorking ? "" : undefined}>
            <span className="thought-line__breath" data-shimmer={isWorking ? "" : undefined}>
              {label}
            </span>
          </span>
          <span
            ref={doneRef}
            className="thought-line__text thought-line__text--done"
            data-active={isWorking ? undefined : ""}
          >
            {doneText}
          </span>
        </span>
        {showTimer ? (
          <span ref={timerRef} className="thought-line__timer" data-done={isWorking ? undefined : ""} aria-hidden="true">
            0.0s
          </span>
        ) : null}
        {collapsible ? (
          <span className="thought-line__chevron" data-on={hasTrace ? "" : undefined} aria-hidden="true">
            <IconChevronDown size="1em" />
          </span>
        ) : null}
      </div>

      {hasTrace ? (
        <div className="thought-line__trace" data-open={open ? "" : undefined}>
          <div className="thought-line__fold">
            <div className="thought-line__steps">
              {steps.map((text, i) => {
                const done = !isWorking || i < activeIndex;
                const active = isWorking && i === activeIndex;
                return (
                  <div key={`${i}-${text}`} className="thought-line__step" data-done={done ? "" : undefined}>
                    <span className="thought-line__mark" aria-hidden="true">
                      {done ? <IconCheck size="1em" /> : active ? <i className="thought-line__pulse" /> : <i className="thought-line__pulse" data-idle="" />}
                    </span>
                    <span className="thought-line__step-text">{text}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
