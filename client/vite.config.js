import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The proxy target is configurable. Default matches the local dev ports in
// .env.local (proxy on 4001). Docker sets PROXY_URL=http://proxy:4000.
const target = process.env.PROXY_URL || "http://localhost:4001";
// Match the dashboard port in .env.local / README (5174); overridable via env.
const port = parseInt(process.env.CLIENT_PORT || "5174", 10);

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port,
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        // When the proxy backend (:4001) is down, http-proxy raises ECONNREFUSED
        // and Vite would surface an opaque 500. Return a clean 502 JSON instead
        // so the dashboard shows "backend unreachable" rather than crashing on a
        // non-JSON body, and print a one-line hint in the Vite terminal.
        configure: (proxyServer) => {
          let warned = false;
          proxyServer.on("error", (err, _req, res) => {
            if (!warned) {
              warned = true;
              console.warn(
                `\n[vite] cannot reach proxy at ${target} (${err.code}). ` +
                `Start the backend: node scripts/runner.js (or the "Start ALL" task).\n`
              );
            }
            if (res && !res.headersSent && typeof res.writeHead === "function") {
              res.writeHead(502, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "proxy_unreachable", target, code: err.code }));
            } else if (res && typeof res.end === "function") {
              res.end();
            }
          });
        },
      },
    },
  },
});
