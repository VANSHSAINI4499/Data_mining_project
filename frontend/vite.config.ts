import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// The repository-root .env is shared with the backend. Only VITE_* variables are exposed to
// browser code; CTI_BACKEND_PROXY_TARGET is read here (Node side) for the dev proxy.
const repoRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, repoRoot, ["CTI_BACKEND_PROXY_TARGET"]), ...process.env };
  return {
    envDir: repoRoot,
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target: env.CTI_BACKEND_PROXY_TARGET ?? "http://localhost:8000",
          changeOrigin: false,
        },
      },
    },
  };
});
