import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The Go backend embeds web/dist and serves the SPA (with an index.html
// fallback for client routes). In dev, /api is proxied to the backend.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        configure: (proxy) => {
          // Server-Sent Events: ask the backend for an uncompressed stream (a
          // gzip writer would hold events back) and tell any intermediary not
          // to buffer. The proxy itself pipes chunks through as they arrive.
          proxy.on("proxyReq", (proxyReq, req) => {
            if (req.url?.startsWith("/api/stream")) {
              proxyReq.setHeader("accept-encoding", "identity");
            }
          });
          proxy.on("proxyRes", (proxyRes) => {
            if (proxyRes.headers["content-type"]?.startsWith("text/event-stream")) {
              proxyRes.headers["cache-control"] = "no-cache, no-transform";
              proxyRes.headers["x-accel-buffering"] = "no";
            }
          });
        },
      },
    },
  },
});
