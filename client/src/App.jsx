/**
 * App — SecOps dashboard shell.
 *
 * Layout: left = LLM chat behind the firewall (with keystroke capture);
 * right = live threat feed, biometric monitor, metrics, agent audit trail.
 * Top status bar shows operational modes + service health.
 */
import { useState } from "react";
import Logo from "./components/Logo.jsx";
import BootLoader from "./components/BootLoader.jsx";
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

  const [booting, setBooting] = useState(true);

  return (
    <>
      {booting && <BootLoader onDone={() => setBooting(false)} />}
      <header className="topbar">
        <div className="brand">
          <Logo idPrefix="hdr" />
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
        TIER 1 + TIER 2 · IMPLEMENTATION PLAN PHASES 1–5 · STACK: REACT → NODE.JS PROXY → PYTHON (SCIKIT-LEARN + LSTM) → MONGODB
      </footer>
    </>
  );
}
