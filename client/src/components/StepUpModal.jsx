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
      setStatus("verified");
      onVerified?.();
    } catch (err) {
      setError(err.message || String(err));
      setStatus("idle");
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal stepup-modal">
        <h2>🔐 Step-Up Authentication Required</h2>
        <p className="muted">
          Your keystroke trust score collapsed below the enforcement threshold.
          Re-verify with your passkey or security key to continue.
        </p>
        {error && <div className="stepup-error">⚠ {error}</div>}
        <div className="stepup-actions">
          <button
            className="btn"
            onClick={authenticate}
            disabled={status === "authenticating"}
          >
            {status === "authenticating" ? "Waiting for authenticator…" : "Verify with passkey →"}
          </button>
          <button
            className="btn btn-ghost"
            onClick={register}
            disabled={status === "registering"}
          >
            {status === "registering" ? "Registering…" : "Register a new passkey"}
          </button>
          {onCancel && (
            <button className="btn btn-ghost" onClick={onCancel}>
              Cancel
            </button>
          )}
        </div>
        {status === "registered" && (
          <div className="stepup-ok">✓ Passkey registered — now click “Verify with passkey”.</div>
        )}
      </div>
    </div>
  );
}
