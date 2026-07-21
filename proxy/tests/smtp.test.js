/**
 * Real SMTP client test — drives the built-in net/tls SMTP sender against an
 * in-process fake SMTP server (plaintext), proving it actually speaks the
 * protocol (EHLO → AUTH LOGIN → MAIL/RCPT/DATA) and dot-stuffs the body.
 */
import { describe, it, expect } from "vitest";
import net from "net";
import { sendSmtp } from "../agents/tools/_smtp.js";

function fakeSmtpServer() {
  const received = { auth: [], data: "" };
  const server = net.createServer((sock) => {
    sock.setEncoding("utf8");
    let inData = false;
    let buf = "";
    sock.write("220 fake ESMTP\r\n");
    sock.on("data", (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            sock.write("250 queued\r\n");
          } else {
            received.data += line + "\n";
          }
          continue;
        }
        const up = line.toUpperCase();
        if (up.startsWith("EHLO") || up.startsWith("HELO")) sock.write("250-fake\r\n250 OK\r\n");
        else if (up === "AUTH LOGIN") sock.write("334 VXNlcm5hbWU6\r\n");
        else if (up.startsWith("MAIL FROM")) sock.write("250 OK\r\n");
        else if (up.startsWith("RCPT TO")) sock.write("250 OK\r\n");
        else if (up === "DATA") {
          inData = true;
          sock.write("354 end with .\r\n");
        } else if (up === "QUIT") {
          sock.write("221 bye\r\n");
          sock.end();
        } else if (received.auth.length === 0) {
          received.auth.push(line); // base64 username
          sock.write("334 UGFzc3dvcmQ6\r\n");
        } else if (received.auth.length === 1) {
          received.auth.push(line); // base64 password
          sock.write("235 auth ok\r\n");
        } else {
          sock.write("250 OK\r\n");
        }
      }
    });
  });
  server._received = received;
  return server;
}

describe("real SMTP client", () => {
  it("delivers a message a real SMTP server would accept", async () => {
    const server = fakeSmtpServer();
    await new Promise((res) => server.listen(0, "127.0.0.1", res));
    const port = server.address().port;
    try {
      const sent = await sendSmtp({
        url: `smtp://user:pass@127.0.0.1:${port}`,
        from: "fw@local",
        to: "soc@local",
        subject: "Test Alert",
        body: "line1\n.hidden\nline3",
      });
      expect(sent.accepted).toBe(true);
      expect(sent.port).toBe(port);
      // headers + body reached the server
      expect(server._received.data).toContain("Subject: Test Alert");
      expect(server._received.data).toContain("line1");
      // AUTH LOGIN actually happened (username + password sent)
      expect(server._received.auth.length).toBe(2);
      // dot-stuffing: a body line starting with '.' is sent as '..'
      expect(server._received.data).toContain("..hidden");
    } finally {
      server.close();
    }
  });
});
