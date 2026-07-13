import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: {
      server: "src/mcp/server.ts",
      stdio: "src/mcp/stdio.ts",
    },
    clean: true,
    format: ["esm"],
    platform: "node",
    target: "node20",
    sourcemap: true,
  },
  {
    entry: { "agent-hub-app": "src/mcp/app.ts" },
    clean: false,
    platform: "browser",
    target: "es2022",
    format: ["iife"],
  },
]);
