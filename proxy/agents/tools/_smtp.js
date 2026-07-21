/**
 * Minimal real SMTP sender — no external mail dependency (Node net/tls only).
 *
 * Replaces the previous `notify` SMTP *stub* (which pretended to send). This
 * actually delivers an email, speaking enough of RFC 5321 to work with real
 * providers:
 *   - smtps://user:pass@host:465   implicit TLS (Gmail, most providers)
 *   - smtp://user:pass@host:587    STARTTLS upgrade (advertised by the server)
 *   - smtp://host:25               plain (local relay / test server)
 *
 * STARTTLS is used only when the server advertises it in the EHLO reply, so a
 * plain local server still works. Bounded by a per-step timeout so a wedged
 * server can never hang the Actor. This is a compact MTA client — sufficient for
 * transactional notifications, not a hardened mail stack.
 */
import net from "net";
import tls from "tls";

/** Buffer socket data and hand back one full SMTP reply per next() call. */
function createReader(getSock, timeoutMs) {
  let buffer = "";
  let waiter = null;

  function pump() {
    if (!waiter) return;
    const lines = buffer.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      // A reply is complete on a line like "250 OK" (space after code);
      // "250-..." lines are continuations.
      if (/^\d{3} /.test(lines[i])) {
        const text = lines.slice(0, i + 1).join("\n");
        const code = parseInt(lines[i].slice(0, 3), 10);
        buffer = lines.slice(i + 1).join("\r\n");
        const w = waiter;
        waiter = null;
        clearTimeout(w.timer);
        w.resolve({ code, text });
        return;
      }
    }
  }

  function attach(sock) {
    sock.setEncoding("utf8");
    sock.on("data", (chunk) => {
      buffer += chunk;
      pump();
    });
  }
  attach(getSock());

  return {
    attach,
    next() {
      return new Promise((resolve, reject) => {
        waiter = {
          resolve,
          reject,
          timer: setTimeout(() => {
            waiter = null;
            reject(new Error("SMTP read timeout"));
          }, timeoutMs),
        };
        pump();
      });
    },
  };
}

function connect({ host, port, implicitTls, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const sock = implicitTls
      ? tls.connect({ host, port, servername: host }, () => resolve(sock))
      : net.connect({ host, port }, () => resolve(sock));
    sock.setTimeout(timeoutMs, () => reject(new Error("SMTP connect timeout")));
    sock.once("error", reject);
  });
}

function upgradeTls(socket, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: host }, () => resolve(secure));
    secure.setTimeout(timeoutMs, () => reject(new Error("STARTTLS timeout")));
    secure.once("error", reject);
  });
}

const b64 = (s) => Buffer.from(String(s), "utf8").toString("base64");

/**
 * Send one email.
 * @param {{url:string, from:string, to:string, subject:string, body:string, timeoutMs?:number}} p
 * @returns {Promise<{host:string, port:number, accepted:true}>}
 */
export async function sendSmtp({ url, from, to, subject, body, timeoutMs = 8000 }) {
  const u = new URL(url);
  const implicitTls = u.protocol === "smtps:" || u.port === "465";
  const port = parseInt(u.port || (implicitTls ? "465" : "25"), 10);
  const host = u.hostname;
  const user = decodeURIComponent(u.username || "");
  const pass = decodeURIComponent(u.password || "");

  let sock = await connect({ host, port, implicitTls, timeoutMs });
  const reader = createReader(() => sock, timeoutMs);

  const cmd = async (line, expect) => {
    const p = reader.next();
    sock.write(line + "\r\n");
    const r = await p;
    if (expect && r.code !== expect) {
      throw new Error(`SMTP ${line.split(" ")[0]} → ${r.code} (expected ${expect}): ${r.text.slice(0, 120)}`);
    }
    return r;
  };

  try {
    const greeting = await reader.next(); // server 220 banner
    if (greeting.code !== 220) throw new Error(`SMTP banner ${greeting.code}`);

    let ehlo = await cmd("EHLO firewall.local", 250);

    if (!implicitTls && /STARTTLS/i.test(ehlo.text)) {
      await cmd("STARTTLS", 220);
      sock = await upgradeTls(sock, host, timeoutMs);
      reader.attach(sock);
      ehlo = await cmd("EHLO firewall.local", 250);
    }

    if (user) {
      await cmd("AUTH LOGIN", 334);
      await cmd(b64(user), 334);
      await cmd(b64(pass), 235);
    }

    await cmd(`MAIL FROM:<${from}>`, 250);
    await cmd(`RCPT TO:<${to}>`, 250);
    await cmd("DATA", 354);
    const headers =
      `From: ${from}\r\nTo: ${to}\r\nSubject: ${subject}\r\n` +
      `MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n`;
    // Dot-stuff any lines that begin with '.' per RFC 5321 §4.5.2.
    const safeBody = String(body).replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
    await cmd(`${headers}\r\n${safeBody}\r\n.`, 250);
    await cmd("QUIT").catch(() => {});
    return { host, port, accepted: true };
  } finally {
    try {
      sock.end();
      sock.destroy();
    } catch {
      /* ignore */
    }
  }
}
