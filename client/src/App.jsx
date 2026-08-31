/**
 * App — SecOps dashboard shell.
 *
 * Layer 2 = AI-Driven Continuous Behavioral Risk Analysis (context-centric):
 *   identity + device + location + time + resource + activity → One-Class SVM → RF → LOW/MEDIUM/HIGH
 * The old keystroke/mouse/touch biometric system is removed from the live UI
 * (files preserved on disk for tests + future Phase 4 optional signals).
 */
import { useState, useEffect } from "react";
import { ensureSession } from "./lib/api";
import { collectFingerprint, sendFingerprint } from "./lib/fingerprint";
import { hasConsent, loadConsent } from "./lib/consent";
import { resolvePublicIp } from "./lib/publicIp";
import Logo from "./components/Logo.jsx";
import BootLoader from "./components/BootLoader.jsx";
import StatusBar from "./components/StatusBar.jsx";
import ChatPanel from "./components/ChatPanel.jsx";
import ThreatFeed from "./components/ThreatFeed.jsx";
import MetricsPanel from "./components/MetricsPanel.jsx";
import SlaPanel from "./components/SlaPanel.jsx";
import LoginScreen from "./components/LoginScreen.jsx";
import BehavioralRiskDashboard from "./components/BehavioralRiskDashboard.jsx";
import RiskSummary from "./components/RiskSummary.jsx";
import RiskTable from "./components/RiskTable.jsx";
import FaceAuthModal from "./components/FaceAuthModal.jsx";

export default function App() {
  const [authUser, setAuthUser] = useState(() => {
    const saved = localStorage.getItem("dlf.authUser");
    return saved ? JSON.parse(saved) : null;
  });

  const [userId, setUserId] = useState(() => localStorage.getItem("dlf.userId") || "");

  // ALL hooks must be called BEFORE any early return (React rules of hooks).
  const [booting, setBooting] = useState(true);
  const [faceModal, setFaceModal] = useState(null); // null | "enroll" | "verify"

  useEffect(() => {
    if (!authUser) return;
    ensureSession(userId).catch(() => {});
    resolvePublicIp().catch(() => {});
  }, [userId, authUser]);

  useEffect(() => {
    if (!authUser) return;
    let alive = true;
    (async () => {
      // Sync the consent mirror from the server, then capture ONLY if the
      // user granted the "fingerprint" category (ConsentBanner). Without
      // this gate the server correctly answers 403 consent_required.
      await loadConsent(userId).catch(() => {});
      if (!alive || !hasConsent("fingerprint")) return;
      const fp = await collectFingerprint(true);
      if (alive) await sendFingerprint(fp, userId);
    })();
    return () => { alive = false; };
  }, [userId, authUser]);

  const handleLogin = (data) => {
    localStorage.setItem("dlf.authUser", JSON.stringify(data.user));
    localStorage.setItem("dlf.userId", data.user.username);
    setAuthUser(data.user);
    setUserId(data.user.username);
  };

  const handleLogout = () => {
    localStorage.removeItem("dlf.authUser");
    setAuthUser(null);
  };

  // Show login screen if not authenticated — AFTER all hooks.
  if (!authUser) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return (
    <>
      {booting && <BootLoader onDone={() => setBooting(false)} />}
      <header className="topbar">
        <div className="brand">
          <Logo idPrefix="hdr" />
          <div className="brand-text">
            <h1>Dual-Layer <span className="accent">AI Firewall</span></h1>
            <div className="sub">
              SEMANTIC PROMPT-INJECTION DEFENSE · BEHAVIORAL RISK ANALYSIS
            </div>
          </div>
        </div>
        <div className="user">
          <span style={{ color: "var(--cyan)" }}>{authUser?.role || "user"}</span>
          {" "}<code>{userId}</code>
          {/* Face auth temporarily disabled — re-enable by uncommenting the buttons below */}
          {/* <button onClick={() => setFaceModal("enroll")} style={{ marginLeft: 10, background: "none", border: "1px solid var(--panel-edge)", color: "var(--cyan)", borderRadius: 4, padding: "2px 8px", cursor: "pointer", fontSize: 10 }}>👤 ENROLL FACE</button>
          <button onClick={() => setFaceModal("verify")} style={{ marginLeft: 6, background: "none", border: "1px solid var(--panel-edge)", color: "var(--ok)", borderRadius: 4, padding: "2px 8px", cursor: "pointer", fontSize: 10 }}>🔐 VERIFY FACE</button> */}
          <button onClick={handleLogout} style={{ marginLeft: 10, background: "none", border: "1px solid var(--panel-edge)", color: "var(--muted)", borderRadius: 4, padding: "2px 8px", cursor: "pointer", fontSize: 10 }}>LOGOUT</button>
        </div>
      </header>

      <StatusBar />

      <main className="grid">
        {/* Row 1 — fleet KPI strip (full width) */}
        <div className="row-full">
          <RiskSummary />
        </div>

        {/* Row 2 — interaction column (left) · flagship analysis column (right) */}
        <div className="col col-left">
          <ChatPanel userId={userId} />
          <ThreatFeed />
          <RiskTable />
        </div>
        <div className="col col-right">
          <BehavioralRiskDashboard userId={userId} />
          <MetricsPanel />
          <SlaPanel />
        </div>
      </main>

      <footer className="footer">
        DUAL-LAYER AI FIREWALL
      </footer>

      {faceModal && (
        <FaceAuthModal
          mode={faceModal}
          userId={userId}
          onVerified={() => setFaceModal(null)}
          onCancel={() => setFaceModal(null)}
        />
      )}
    </>
  );
}
