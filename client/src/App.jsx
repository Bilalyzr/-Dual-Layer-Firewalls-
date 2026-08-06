/**
 * App — SecOps dashboard shell.
 *
 * Layout: left = LLM chat behind the firewall (with keystroke capture);
 * right = live threat feed, biometric monitor, metrics, agent audit trail.
 * Top status bar shows operational modes + service health.
 *
 * Behavioral capture beyond keystroke (mouse / touch / device fingerprint) is
 * gated behind explicit per-category consent (Epic I) — the ConsentBanner drives
 * the `consent` map and nothing captures until the matching toggle is on.
 */
import { useState, useEffect } from "react";
import { ensureSession } from "./lib/api";
import { collectFingerprint, sendFingerprint } from "./lib/fingerprint";
import { resolvePublicIp } from "./lib/publicIp";
import { hasConsent } from "./lib/consent";
import { useMouseCapture } from "./hooks/useMouseCapture";
import { useTouchCapture } from "./hooks/useTouchCapture";
import Logo from "./components/Logo.jsx";
import BootLoader from "./components/BootLoader.jsx";
import StatusBar from "./components/StatusBar.jsx";
import ChatPanel from "./components/ChatPanel.jsx";
import ThreatFeed from "./components/ThreatFeed.jsx";
import BiometricMonitor from "./components/BiometricMonitor.jsx";
import MetricsPanel from "./components/MetricsPanel.jsx";
import AgentAuditTrail from "./components/AgentAuditTrail.jsx";
import ConsentBanner from "./components/ConsentBanner.jsx";
import SlaPanel from "./components/SlaPanel.jsx";

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
  // Per-category consent grants (Epic I). Seeded from the local mirror so gating
  // is correct on first paint; ConsentBanner re-syncs from the server + updates.
  const [consent, setConsent] = useState(() => ({
    mouse: hasConsent("mouse"),
    touch: hasConsent("touch"),
    fingerprint: hasConsent("fingerprint"),
  }));

  // Capture hooks only run when their consent toggle is on — the `enabled` flag
  // fully attaches/detaches the underlying listeners.
  useMouseCapture({ userId, enabled: Boolean(consent.mouse) });
  useTouchCapture({ userId, enabled: Boolean(consent.touch) });

  // Bootstrap a signed session token on first load (Tier 2 EPIC A), binding it
  // to the persisted userId so existing keystroke baselines carry over.
  useEffect(() => {
    ensureSession(userId).catch(() => {});
    // Warm public-IP discovery so the first detection already carries a real
    // source IP (local-dev demo; inert in prod — see lib/publicIp.js).
    resolvePublicIp().catch(() => {});
  }, [userId]);

  // Device fingerprint is one-shot: collect + send once when consent is granted.
  useEffect(() => {
    if (!consent.fingerprint) return;
    let alive = true;
    (async () => {
      const fp = await collectFingerprint(true);
      if (alive) await sendFingerprint(fp, userId);
    })();
    return () => { alive = false; };
  }, [consent.fingerprint, userId]);

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
          <SlaPanel />
          <AgentAuditTrail />
        </div>
      </main>

      <ConsentBanner userId={userId} onChange={setConsent} />

      <footer className="footer">
        DUAL-LAYER AI FIREWALL
      </footer>
    </>
  );
}
