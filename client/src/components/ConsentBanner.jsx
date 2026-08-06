/**
 * ConsentBanner — the Epic I consent gate UI.
 *
 * First run: a banner explaining the behavioral-biometric categories and asking
 * the user to opt in per-category. After a decision it collapses to a small
 * "Privacy" chip that reopens a settings panel to change grants at any time.
 *
 * Grants drive whether App activates mouse/touch/fingerprint capture — nothing
 * runs until the corresponding toggle is on. Calls `onChange(grants)` whenever a
 * toggle flips so the parent can enable/disable hooks live.
 */
import { useEffect, useState } from "react";
import { CONSENT_CATEGORIES, loadConsent, setConsent, hasDecided } from "../lib/consent";

export default function ConsentBanner({ userId, onChange }) {
  const [grants, setGrants] = useState({});
  const [open, setOpen] = useState(!hasDecided());
  const [decided, setDecided] = useState(hasDecided());

  useEffect(() => {
    let alive = true;
    loadConsent(userId).then((g) => {
      if (!alive) return;
      setGrants(g);
      onChange?.(g);
    });
    return () => { alive = false; };
  }, [userId]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggle = async (key) => {
    const next = !grants[key];
    const updated = { ...grants, [key]: next };
    setGrants(updated);
    onChange?.(updated);
    await setConsent(userId, key, next);
  };

  const acceptAll = async () => {
    const updated = { ...grants };
    for (const c of CONSENT_CATEGORIES) updated[c.key] = true;
    setGrants(updated);
    onChange?.(updated);
    await Promise.all(CONSENT_CATEGORIES.map((c) => setConsent(userId, c.key, true)));
    finish();
  };

  const declineAll = async () => {
    const updated = { ...grants };
    for (const c of CONSENT_CATEGORIES) updated[c.key] = false;
    setGrants(updated);
    onChange?.(updated);
    await Promise.all(CONSENT_CATEGORIES.map((c) => setConsent(userId, c.key, false)));
    finish();
  };

  const finish = () => {
    setDecided(true);
    setOpen(false);
  };

  // Collapsed chip once a decision exists and the panel is closed.
  if (decided && !open) {
    const activeCount = CONSENT_CATEGORIES.filter((c) => grants[c.key]).length;
    return (
      <button className="consent-chip" onClick={() => setOpen(true)} title="Privacy & consent settings">
        🛡 Privacy <span className="consent-chip-count">{activeCount}/{CONSENT_CATEGORIES.length}</span>
      </button>
    );
  }

  return (
    <div className="consent-overlay" role="dialog" aria-label="Privacy consent">
      <div className="consent-card panel">
        <div className="panel-head">
          <h2>Behavioral biometrics — your consent</h2>
          {decided && (
            <button className="consent-x" onClick={() => setOpen(false)} aria-label="Close">✕</button>
          )}
        </div>
        <p className="small muted consent-intro">
          This demo can capture behavioral signals to strengthen continuous authentication.
          These are <strong>off by default</strong> and processed only with your explicit,
          per-category consent (GDPR). Keystroke timing on the chat box runs
          separately for the core demo.
        </p>

        <ul className="consent-list">
          {CONSENT_CATEGORIES.map((c) => (
            <li key={c.key} className="consent-row">
              <label className="consent-toggle">
                <input
                  type="checkbox"
                  checked={Boolean(grants[c.key])}
                  onChange={() => toggle(c.key)}
                />
                <span className="consent-slider" />
              </label>
              <div className="consent-copy">
                <div className="consent-label">{c.label}</div>
                <div className="small muted">{c.desc}</div>
              </div>
            </li>
          ))}
        </ul>

        <div className="consent-actions">
          <button className="btn btn-ghost" onClick={declineAll}>Decline all</button>
          <button className="btn" onClick={acceptAll}>Accept all</button>
          {decided && (
            <button className="btn btn-ghost" onClick={() => setOpen(false)}>Save & close</button>
          )}
        </div>
      </div>
    </div>
  );
}
