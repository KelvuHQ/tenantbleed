import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The SPA lives in ui/ and builds to dist/ui, which the local server serves as static files.
// A relative base keeps it working under the token URL. In dev, /api is proxied to a running
// `tenantbleed ui` server on 7171.
export default defineConfig({
  root: "ui",
  base: "./",
  plugins: [react()],
  build: {
    outDir: "../dist/ui",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:7171",
    },
  },
});
