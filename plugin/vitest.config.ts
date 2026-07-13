import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "test/**/*.test.ts",
      "src/mcp/**/*.test.ts",
    ],
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text"],
    },
  },
});
