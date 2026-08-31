/**
 * ChatPanel — the LLM chat surface that sits behind the firewall.
 * Send posts to /api/chat, which runs the full Layer-1 pipeline; blocked
 * responses are surfaced distinctly.
 */
import { useEffect, useRef, useState } from "react";
import { apiFetch } from "../lib/api";
import StepUpModal from "./StepUpModal";

export default function ChatPanel({ userId }) {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([]);
  const [busy, setBusy] = useState(false);
  const [stepUp, setStepUp] = useState(false);
  const [pendingPrompt, setPendingPrompt] = useState(null);
  const logRef = useRef(null);

  // Keep the newest message in view — without this the log stays scrolled to
  // the top and new replies arrive invisibly below the fold.
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const send = async (override) => {
    const text = (typeof override === "string" ? override : input).trim();
    if (!text || busy) return;
    setBusy(true);
    if (text !== pendingPrompt) setMessages((m) => [...m, { role: "user", text }]);
    setInput("");
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
            { role: "system", text: "🔐 Step-up authentication required — verify your passkey to continue.", blocked: true },
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
          { role: "system", text: `⚠ server returned HTTP ${res.status} (no JSON). The proxy may be down or the LLM timed out.` },
        ]);
        return;
      }
      if (!res.ok && !data.error && !data.blocked) {
        setMessages((m) => [
          ...m,
          { role: "system", text: `⚠ server error HTTP ${res.status}. Is the proxy running on :4001?` },
        ]);
        return;
      }
      if (data.blocked) {
        const prob = data.verdict?.classifier?.threatProbability;
        setMessages((m) => [
          ...m,
          {
            role: "system",
            text: `⛔ BLOCKED by AI Firewall — ${data.categoryTitle || "Policy"} (${data.category})`
              + (data.blockReason ? `\nReason: ${data.blockReason}` : "")
              + (prob != null ? `\nRisk score: ${Math.round(prob * 100)}/100` : "")
              + (data.wordScores?.weightage != null ? ` · Word weightage: ${Math.round(data.wordScores.weightage * 100)}%` : ""),
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
          ? `⏳ GLM rate limit hit — wait a few seconds between messages. (Free tier limits: ~5 requests/min)`
          : isTimeout
          ? `⏳ The LLM took too long to respond (timed out). Try again — the model is occasionally slow.`
          : isUnreachable
          ? `🌐 Could not reach the LLM provider (${data.error}). Check your network or API key.`
          : `⚠ ${data.error}: ${detail.slice(0, 120) || "no detail"}`;
        setMessages((m) => [...m, { role: "system", text: msg }]);
      } else {
        setMessages((m) => [
          ...m,
          {
            role: "assistant",
            text: data.answer || "(empty response)",
            verdict: data.verdict,
            simulated: data.simulated,
          },
        ]);
      }
    } catch (err) {
      setMessages((m) => [...m, { role: "system", text: `network error: ${err.message}` }]);
    } finally {
      setBusy(false);
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
    setMessages((m) => [...m, { role: "system", text: "✓ Identity re-verified — resuming." }]);
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
            <div className="chat-empty-icon">🛡️</div>
            <div className="chat-empty-title">Firewall chat ready</div>
            <div className="chat-empty-sub">
              Send a prompt to test the 7-layer pipeline — or try an attack
              like <code>“ignore all previous instructions”</code> and watch it
              get blocked with full evidence.
            </div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`msg msg-${m.role}${m.blocked ? " msg-blocked" : ""}`}>
            <div className="msg-role">{m.role}</div>
            <div className="msg-text">{m.text}</div>
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
          </div>
        ))}
        {busy && (
          <div className="msg msg-assistant">
            <div className="msg-role">assistant</div>
            <div className="chat-typing"><i /><i /><i /> inspecting &amp; answering…</div>
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
