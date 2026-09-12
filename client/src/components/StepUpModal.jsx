/**
 * StepUpModal — FIDO2 / WebAuthn step-up MFA (Tier 2 · EPIC B).
 *
 * Shown when /api/chat returns 401 { reason: "step_up_required" }: the session's
 * keystroke trust collapsed and the user must re-assert identity with a passkey /
 * security key before chat resumes. If the user has no registered credential yet,
 * a one-time registration flow is offered first.
 */
import { useState } from "react";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import { apiFetch } from "../lib/api";
import { IconAlert, IconCheck, IconLock } from "./Icons.jsx";

async function postJSON(url, body) {
  const res = await apiFetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  return { res, data };
}

export default function StepUpModal({ open, onVerified, onCancel }) {
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState(null);

  if (!open) return null;

  const register = async () => {
    setError(null);
    setStatus("registering");
    try {
      const { data: options } = await postJSON("/api/auth/webauthn/register/options");
      const attResp = await startRegistration({ optionsJSON: options });
      const { data } = await postJSON("/api/auth/webauthn/register/verify", { response: attResp });
      if (!data.verified) throw new Error("registration not verified");
      setStatus("registered");
    } catch (err) {
      setError(err.message || String(err));
      setStatus("idle");
    }
  };

  const authenticate = async () => {
    setError(null);
    setStatus("authenticating");
    try {
      const { res, data: options } = await postJSON("/api/auth/webauthn/authenticate/options");
      if (res.status === 409) {
        // No credential registered yet — fall back to registration.
        setError("No passkey registered yet. Register one first.");
        setStatus("idle");
        return;
      }
      const asserted = await startAuthentication({ optionsJSON: options });
      const { data } = await postJSON("/api/auth/webauthn/authenticate/verify", { response: asserted });
      if (!data.verified) throw new Error("assertion not verified");
      // Staged hand-off: let the verify → verified → resume narrative play
      // out before the modal closes and the frozen prompt retries.
      setStatus("verified");
      setTimeout(() => setStatus("resuming"), 800);
      setTimeout(() => onVerified?.(), 1500);
    } catch (err) {
      setError(err.message || String(err));
      setStatus("idle");
    }
  };

  // Stage tracker state: 0 = verify (active while authenticating),
  // 1 = verified, 2 = resume. Each finishes green as the flow advances.
  const stageDone = status === "verified" || status === "resuming" ? 0 : -1;
  const stageOn =
    status === "authenticating" ? 0 :
    status === "verified" ? 1 :
    status === "resuming" ? 2 : -1;
  const busy = status === "authenticating" || status === "verified" || status === "resuming";

  return (
    <div className="modal-backdrop">
      <div className="modal stepup-modal">
        <h2 style={{ display: "flex", alignItems: "center", gap: 8 }}><IconLock size={16} /> Step-Up Authentication Required</h2>
        <p className="muted">
          Your keystroke trust score collapsed below the enforcement threshold.
          Re-verify with your passkey or security key to continue.
        </p>
        <div className="stepup-stages" aria-live="polite">
          <span className={`stepup-stage${stageOn === 0 ? " on" : ""}${stageDone >= 0 ? " done" : ""}`}><i />verify</span>
          <span className="stepup-arrow">→</span>
          <span className={`stepup-stage${stageOn === 1 ? " on" : ""}${stageOn >= 2 ? " done" : ""}`}><i />verified</span>
          <span className="stepup-arrow">→</span>
          <span className={`stepup-stage${stageOn === 2 ? " on" : ""}`}><i />resume</span>
        </div>
        {error && <div className="stepup-error"><IconAlert size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} /> {error}</div>}
        <div className="stepup-actions">
          <button
            className="btn"
            onClick={authenticate}
            disabled={busy}
          >
            {status === "authenticating" ? "Waiting for authenticator…" : "Verify with passkey →"}
          </button>
          <button
            className="btn btn-ghost"
            onClick={register}
            disabled={status === "registering" || busy}
          >
            {status === "registering" ? "Registering…" : "Register a new passkey"}
          </button>
          {onCancel && (
            <button className="btn btn-ghost" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
          )}
        </div>
        {status === "registered" && (
          <div className="stepup-ok"><IconCheck size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} /> Passkey registered — now click “Verify with passkey”.</div>
        )}
      </div>
    </div>
  );
}
