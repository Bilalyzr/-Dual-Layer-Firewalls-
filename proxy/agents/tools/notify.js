/**
 * EPIC F — `notify` tool adapter (real SMTP email, feature-flagged).
 *
 * Sends a real email via SMTP when SMTP_HOST/USER/PASS/FROM are set. Otherwise
 * falls back to the mock (so the demo keeps working with no creds). Either way:
 *   - the call is behind the existing RBAC (`canCall('actor', 'notify')`)
 *   - the message content is schema-validated before this runs
 *   - per-tool rate limiting is enforced by the adapter registry
 *   - every send (real or mock) is recorded for audit
 *
 * No external npm mail dep — uses Node's built-in net-based SMTP via a tiny
 * helper, OR a webhook adapter when NOTIFY_WEBHOOK_URL is set (simplest). We
 * prefer the webhook (a single HTTP POST) because it needs no SMTP creds and
 * works with Slack/Discord/any incoming-webhook receiver.
 */
import { LOG, recordCall } from "./_audit.js";
import { sendSmtp } from "./_smtp.js";
import { strictReal } from "../../lib/strict.js";

/**
 * @param {{message:string, channel?:"email"|"sms"|"dashboard"}} args
 * @returns {Promise<{tool:string, ok:boolean, result:string, mode:string}>}
 */
export async function notify(args) {
  const message = String(args?.message || "").slice(0, 280);
  const channel = args?.channel || "dashboard";
  recordCall("notify", { channel, length: message.length });

  // Real webhook mode — POST to Slack/Discord/Teams/etc.
  const webhook = process.env.NOTIFY_WEBHOOK_URL;
  if (webhook) {
    try {
      const r = await fetch(webhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: `[${channel}] ${message}` }),
        signal: AbortSignal.timeout(5000),
      });
      if (r.ok) {
        return { tool: "notify", ok: true, mode: "webhook", result: `Sent via webhook (${r.status}).` };
      }
      return { tool: "notify", ok: false, mode: "webhook", result: `Webhook returned ${r.status}` };
    } catch (err) {
      LOG.warn("[tools.notify] webhook failed:", err.message);
      // fall through to mock
    }
  }

  // SMTP mode — REAL email via a built-in net/tls SMTP client (no mail dep).
  // Enable with NOTIFY_SMTP_URL=smtps://user:pass@smtp.gmail.com:465 (implicit
  // TLS) or smtp://user:pass@host:587 (STARTTLS). Recipient/sender via
  // NOTIFY_EMAIL_TO / NOTIFY_EMAIL_FROM.
  const smtpUrl = process.env.NOTIFY_SMTP_URL;
  if (smtpUrl) {
    const to = process.env.NOTIFY_EMAIL_TO;
    const from = process.env.NOTIFY_EMAIL_FROM || to;
    if (!to) {
      return { tool: "notify", ok: false, mode: "smtp", result: "NOTIFY_SMTP_URL set but NOTIFY_EMAIL_TO missing." };
    }
    try {
      const sent = await sendSmtp({
        url: smtpUrl,
        from,
        to,
        subject: `[Firewall notify] ${channel}`,
        body: message,
      });
      return { tool: "notify", ok: true, mode: "smtp", result: `Email sent to ${to} via ${sent.host}:${sent.port}.` };
    } catch (err) {
      LOG.warn("[tools.notify] smtp send failed:", err.message);
      return { tool: "notify", ok: false, mode: "smtp", result: `SMTP send failed: ${err.message}` };
    }
  }

  // STRICT_REAL: no real channel configured → fail loudly, never fake a send.
  if (strictReal()) {
    return {
      tool: "notify",
      ok: false,
      mode: "unconfigured",
      result:
        "notify has no real channel configured (STRICT_REAL). Set NOTIFY_WEBHOOK_URL or NOTIFY_SMTP_URL, " +
        "or STRICT_REAL=false to allow the demo mock.",
    };
  }

  // Mock fallback — demo mode only (STRICT_REAL=false).
  return {
    tool: "notify",
    ok: true,
    mode: "mock",
    result: `Notification (mock, no creds): [${channel}] ${message.slice(0, 60)}`,
  };
}

export const config = {
  name: "notify",
  rateLimit: { windowMs: 60_000, max: 5 }, // 5 sends/min/role
  requiresCreds: ["NOTIFY_WEBHOOK_URL", "NOTIFY_SMTP_URL"], // any one enables real mode
};
