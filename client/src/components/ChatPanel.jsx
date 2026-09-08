/**
 * ChatPanel — the LLM chat surface that sits behind the firewall.
 * Send posts to /api/chat, which runs the full Layer-1 pipeline; blocked
 * responses are surfaced distinctly.
 */
import { useEffect, useRef, useState } from "react";
import { apiFetch } from "../lib/api";
import StepUpModal from "./StepUpModal";
import { IconCheck, IconShieldCheck, MSG_ICONS } from "./Icons";

const LLM_LABELS = {
  "local-fallback": "Local Qwen",
  "hosted-fallback": "Hosted fallback",
  offline: "Offline",
};
// Primary answers show a clean "AI" tag — the provider/model identity is
// internal routing detail, not something to surface to visitors.
const llmBadgeLabel = (llm, simulated) => {
  if (simulated && !llm?.via) return "offline";
  if (!llm?.via || llm.via === "primary") return "AI";
  return LLM_LABELS[llm.via] || llm.via;
};

/**
 * Render prompt text with the firewall's word-level verdicts highlighted
 * IN PLACE: negative terms in red (intensity by weight), positive in green.
 * Terms come from the blocked message that follows this user message.
 */
function highlightTerms(text, ws) {
  const neg = (ws?.negative_terms || []).map((t) => ({ ...t, k: "n" }));
  const pos = (ws?.positive_terms || []).map((t) => ({ ...t, k: "p" }));
  const terms = [...neg, ...pos].filter((t) => t.term && t.term.length > 1);
  if (!terms.length) return text;
  const byTerm = new Map(terms.map((t) => [t.term.toLowerCase(), t]));
  const re = new RegExp(
    `(${terms.map((t) => t.term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`,
    "gi"
  );
  return String(text)
    .split(re)
    .map((p, j) => {
      const t = byTerm.get(p.toLowerCase());
      if (!t) return p;
      const lvl = t.weight >= 3 ? 3 : t.weight >= 2 ? 2 : 1;
      return (
        <mark key={j} className={`hl-${t.k}${lvl}`} title={`${t.k === "n" ? "negative" : "positive"} weight ${t.k === "n" ? "−" : "+"}${t.weight}`}>
          {p}
        </mark>
      );
    });
}

// The inspection chain a prompt really travels (7 layers + the LLM answer);
// the loading indicator lights these up in order while the request is in flight.
const PIPELINE = ["sanitize", "sentiment", "cascade", "memory", "behavior", "rag", "decision", "llm"];

export default function ChatPanel({ userId }) {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([]);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState(0);
  const [stepUp, setStepUp] = useState(false);
  const [pendingPrompt, setPendingPrompt] = useState(null);
  const logRef = useRef(null);

  // Keep the newest message in view — without this the log stays scrolled to
  // the top and new replies arrive invisibly below the fold.
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  // Pipeline-scan indicator: advance one layer at a time while the request
  // runs, dwell on "answering", then loop (the LLM fallback can take a while).
  useEffect(() => {
    if (!busy) return;
    setStage(0);
    const t = setInterval(
      () => setStage((s) => (s > PIPELINE.length ? 0 : s + 1)),
      620
    );
    return () => clearInterval(t);
  }, [busy]);

  const send = async (override, _isRetry = false) => {
    const text = (typeof override === "string" ? override : input).trim();
    if (!text || busy) return;
    setBusy(true);
    if (!_isRetry && text !== pendingPrompt) setMessages((m) => [...m, { role: "user", text }]);
    setInput("");
    let scheduleRetry = false;
    try {
      const res = await apiFetch(
        "/api/chat",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt: text, userId }),
        },
        userId
      );
      // EPIC B: session frozen until a WebAuthn assertion clears step-up.
      if (res.status === 401) {
        const body = await res.json().catch(() => ({}));
        if (body.reason === "step_up_required") {
          setPendingPrompt(text);
          setStepUp(true);
          setMessages((m) => [
            ...m,
            { role: "system", text: "Step-up authentication required — verify your passkey to continue.", icon: "lock", blocked: true },
          ]);
          return;
        }
      }
      // Guard: empty / non-JSON / non-OK responses (timeout, proxy drop, 500)
      // previously surfaced as "Unexpected end of JSON input". Handle cleanly.
      const textBody = await res.text();
      let data;
      try {
        data = textBody ? JSON.parse(textBody) : {};
      } catch {
        setMessages((m) => [
          ...m,
          { role: "system", text: `server returned HTTP ${res.status} (no JSON). The proxy may be down or the LLM timed out.`,
            icon: "alert", },
        ]);
        return;
      }
      if (!res.ok && !data.error && !data.blocked) {
        setMessages((m) => [
          ...m,
          { role: "system", text: `server error HTTP ${res.status}. Is the proxy running on :4001?`,
            icon: "alert", },
        ]);
        return;
      }
      if (data.blocked) {
        const prob = data.verdict?.classifier?.threatProbability;
        setMessages((m) => [
          ...m,
          {
            role: "system",
            text: `BLOCKED by AI Firewall — ${data.categoryTitle || "Policy"} (${data.category})`
              + (data.blockReason ? `\nReason: ${data.blockReason}` : "")
              + (prob != null ? `\nRisk score: ${Math.round(prob * 100)}/100` : "")
              + (data.wordScores?.weightage != null ? ` · Word weightage: ${Math.round(data.wordScores.weightage * 100)}%` : ""),
            icon: "block",
            blocked: true,
            verdict: data.verdict,
            wordScores: data.wordScores,
          },
        ]);
      } else if (data.error) {
        // Friendly rendering of the common LLM errors.
        const detail = String(data.detail || "");
        const isTimeout = /timeout|aborted|ETIMEDOUT/i.test(detail);
        const isUnreachable = /ECONNREFUSED|ENOTFOUND|fetch failed/i.test(detail);
        const isRateLimited = /rate.?limit|429|LLM_RATE/i.test(detail + data.error);
        const msg = isRateLimited
          ? `GLM rate limit hit — wait a few seconds between messages. (Free tier limits: ~5 requests/min)`
          : isTimeout
          ? `The LLM took too long to respond (timed out). Try again — the model is occasionally slow.`
          : isUnreachable
          ? `Could not reach the LLM provider (${data.error}). Check your network or API key.`
          : `${data.error}: ${detail.slice(0, 120) || "no detail"}`;
        setMessages((m) => [...m, { role: "system", text: msg, icon: "alert" }]);
      } else {
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            text: data.answer || "(empty response)",
            verdict: data.verdict,
            simulated: data.simulated,
            llm: data.llm || null,
            totalMs: data.latencyMs ?? null,
          },
        ]);
      }
    } catch (err) {
      // Cold-start tolerance: if the API was asleep (free-tier hosting wakes
      // on first hit), the request fails at network level — retry ONCE after
      // a beat instead of surfacing an error to the user.
      const networkLevel = !(err instanceof Error) || /fetch|network|Failed to fetch/i.test(err.message || "");
      if (networkLevel && !_isRetry) scheduleRetry = true;
      else setMessages((m) => [...m, { role: "system", text: `network error: ${err.message}`, icon: "alert" }]);
    } finally {
      if (!scheduleRetry) setBusy(false);
    }
    if (scheduleRetry) {
      setMessages((m) => [...m, { role: "system", text: "Waking the API — retrying…", icon: "clock" }]);
      setTimeout(() => send(text, true), 2500);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  // After a verified step-up assertion, close the modal and retry the prompt
  // that was frozen.
  const onStepUpVerified = () => {
    setStepUp(false);
    const retry = pendingPrompt;
    setPendingPrompt(null);
    setMessages((m) => [...m, { role: "system", text: "Identity re-verified — resuming.", icon: "check" }]);
    if (retry) send(retry);
  };

  return (
    <section className="panel chat-panel">
      <StepUpModal
        open={stepUp}
        onVerified={onStepUpVerified}
        onCancel={() => setStepUp(false)}
      />
      <div className="panel-head">
        <h2>LLM Chat <small>(behind AI Firewall)</small></h2>
      </div>

      <div className="chat-log" ref={logRef}>
        {messages.length === 0 && (
          <div className="chat-empty">
            <div className="chat-empty-icon"><IconShieldCheck size={44} /></div>
            <div className="chat-empty-title">Firewall chat ready</div>
          </div>
        )}
        {messages.map((m, i) => {
          const Ico = m.icon ? MSG_ICONS[m.icon] : null;
          // The blocked message right after a user bubble carries the word
          // verdicts for that prompt — highlight them inside the prompt itself.
          const next = messages[i + 1];
          const hlWs = m.role === "user" && next?.blocked ? next.wordScores : null;
          // Firewall-vs-LLM split for assistant replies (both real, measured).
          const pipeMs = m.role === "assistant" && m.totalMs != null && m.llm?.latencyMs != null
            ? Math.max(0, m.totalMs - m.llm.latencyMs) : null;
          return (
          <div key={i} className={`msg msg-${m.role}${m.blocked ? " msg-blocked" : ""}`}>
            <div className="msg-role">
              {m.role}
              {m.role === "assistant" && m.llm && (
                <span
                  className="llm-badge"
                  title={`answered${m.llm.latencyMs != null ? ` in ${(m.llm.latencyMs / 1000).toFixed(1)}s` : ""}`}
                >
                  {llmBadgeLabel(m.llm, m.simulated)}
                  {m.llm.latencyMs != null ? ` · ${(m.llm.latencyMs / 1000).toFixed(1)}s` : ""}
                </span>
              )}
            </div>
            <div className="msg-text">
              {Ico && <span className="msg-ico"><Ico size={13} /></span>}
              {hlWs ? highlightTerms(m.text, hlWs) : m.text}
            </div>
            {m.wordScores && (m.wordScores.negative_terms?.length > 0 || m.wordScores.positive_terms?.length > 0) && (
              <div className="word-scores">
                {m.wordScores.negative_terms?.slice(0, 10).map((t, j) => (
                  <span key={`n${j}`} className="word-chip word-chip-neg" title={`negative weight −${t.weight}`}>
                    {t.term} <b>−{t.weight}</b>
                  </span>
                ))}
                {m.wordScores.positive_terms?.slice(0, 6).map((t, j) => (
                  <span key={`p${j}`} className="word-chip word-chip-pos" title={`positive weight +${t.weight}`}>
                    {t.term} <b>+{t.weight}</b>
                  </span>
                ))}
              </div>
            )}
            {m.verdict && (
              <div className="msg-meta">
                heuristic {(m.verdict.heuristic?.latencyMs ?? 0).toFixed(2)}ms ·
                {" "}ml p={(m.verdict.classifier?.threatProbability ?? 0).toFixed(2)} ·
                {" "}mode {m.verdict.mode}
                {m.simulated ? " · simulated LLM" : ""}
              </div>
            )}
            {m.role === "assistant" && pipeMs != null && m.totalMs > 0 && (
              <div className="lat-split" title={`firewall ${pipeMs.toFixed(0)}ms · LLM ${(m.llm.latencyMs / 1000).toFixed(1)}s`}>
                <i className="lat-fw" style={{ width: `${Math.min(100, (pipeMs / m.totalMs) * 100).toFixed(1)}%` }} />
                <i className="lat-llm" style={{ width: `${Math.min(100, (m.llm.latencyMs / m.totalMs) * 100).toFixed(1)}%` }} />
                <span className="lat-txt">
                  firewall {pipeMs.toFixed(0)}ms · LLM {(m.llm.latencyMs / 1000).toFixed(1)}s
                </span>
              </div>
            )}
          </div>
          );
        })}
        {busy && (
          <div className="msg msg-assistant">
            <div className="msg-role">assistant</div>
            <div className="chat-pipeline" role="status" aria-label="inspecting prompt through firewall layers">
              <div className="pl-track">
                {PIPELINE.map((name, i) => (
                  <span
                    key={name}
                    className={`pl-chip${i < stage ? " done" : ""}${i === stage ? " active" : ""}`}
                  >
                    {name}{i < stage ? <> <IconCheck size={9} /></> : null}
                  </span>
                ))}
              </div>
              <div className="pl-bar"><i className="pl-scan" /></div>
              <div className="pl-label">
                {stage < PIPELINE.length - 1
                  ? <>inspecting · <b>{PIPELINE[Math.min(stage, PIPELINE.length - 1)]}</b></>
                  : "answering"}
                <span className="pl-dots"><i /><i /><i /></span>
              </div>
            </div>
          </div>
        )}
      </div>

      <textarea
        className="chat-input"
        placeholder="Type a prompt…"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={onKeyDown}
        rows={3}
      />
      <div className="chat-actions">
        <button className="btn" onClick={send} disabled={busy || !input.trim()}>
          {busy ? "Sending…" : "Send →"}
        </button>
      </div>
    </section>
  );
}
