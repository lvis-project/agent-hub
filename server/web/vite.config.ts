import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const HUB_API_TARGET = process.env.VITE_HUB_API_TARGET ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true,
    proxy: {
      "/api": { target: HUB_API_TARGET, changeOrigin: true },
    },
  },
});
