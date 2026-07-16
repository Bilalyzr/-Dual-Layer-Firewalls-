/**
 * App — SecOps dashboard shell.
 *
 * Layout: left = LLM chat behind the firewall (with keystroke capture);
 * right = live threat feed, biometric monitor, metrics, agent audit trail.
 * Top status bar shows operational modes + service health.
 */
import { useState } from "react";
import StatusBar from "./components/StatusBar.jsx";
import ChatPanel from "./components/ChatPanel.jsx";
import ThreatFeed from "./components/ThreatFeed.jsx";
import BiometricMonitor from "./components/BiometricMonitor.jsx";
import MetricsPanel from "./components/MetricsPanel.jsx";
import AgentAuditTrail from "./components/AgentAuditTrail.jsx";

export default function App() {
  const [userId] = useState(() => {
    const key = "dlf.userId";
    let id = localStorage.getItem(key);
    if (!id) {
      id = "user-" + Math.random().toString(36).slice(2, 7);
      localStorage.setItem(key, id);
    }
    return id;
  });

  return (
    <>
      <header className="topbar">
        <div className="brand">
          <span className="logo">🛡️</span>
          <div className="brand-text">
            <h1>Dual-Layer <span className="accent">AI Firewall</span></h1>
            <div className="sub">
              SEMANTIC PROMPT-INJECTION DEFENSE · BEHAVIORAL KEYSTROKE AUTHENTICATION
            </div>
          </div>
        </div>
        <div className="user">SESSION <code>{userId}</code></div>
      </header>

      <StatusBar />

      <main className="grid">
        <div className="col col-left">
          <ChatPanel userId={userId} />
          <MetricsPanel />
        </div>
        <div className="col col-right">
          <ThreatFeed />
          <BiometricMonitor userId={userId} />
          <AgentAuditTrail />
        </div>
      </main>

      <footer className="footer">
        TIER 1 MVP · IMPLEMENTATION PLAN PHASES 1–3 · STACK: REACT → NODE.JS PROXY → PYTHON (SCIKIT-LEARN) → MONGODB
      </footer>
    </>
  );
}
