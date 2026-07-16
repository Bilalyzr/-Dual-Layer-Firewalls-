import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The proxy target is configurable: in docker it's http://proxy:4000,
// locally it's http://localhost:4000.
const target = process.env.PROXY_URL || "http://localhost:4000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
      },
    },
  },
});
