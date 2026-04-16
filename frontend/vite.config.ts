import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Ant Design pulls a large single chunk; avoid noisy Rollup size warnings on clean builds.
    chunkSizeWarningLimit: 1200,
  },
  server: {
    // Distinct from other Vite apps that default to 5173
    port: 5180,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
});
