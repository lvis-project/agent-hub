import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const deploymentFile = (name: string) => new URL(`../deploy/${name}`, import.meta.url);

describe("deployment contract", () => {
  it("keeps exactly one matching Compose database DSN and password placeholder", async () => {
    const environment = await readFile(deploymentFile(".env.example"), "utf8");
    const values = Object.fromEntries(environment.split("\n")
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => line.split("=", 2)));

    expect(Object.keys(values).filter((key) => key === "AGENT_HUB_DB_URL")).toHaveLength(1);
    expect(values.AGENT_HUB_DB_URL).toContain(`:${values.POSTGRES_PASSWORD}@postgres:`);
  });

  it("requires the public edge to sanitize client IP headers before the inner proxy preserves them", async () => {
    const [inner, outer] = await Promise.all([
      readFile(deploymentFile("nginx.conf"), "utf8"),
      readFile(deploymentFile("outer-proxy.nginx.example.conf"), "utf8"),
    ]);

    expect(inner).toContain("proxy_set_header X-Forwarded-For $http_x_forwarded_for;");
    expect(inner).not.toContain("proxy_set_header X-Forwarded-For $remote_addr;");
    expect(inner).not.toContain("$proxy_add_x_forwarded_for");
    expect(outer).toContain("proxy_set_header X-Forwarded-For $remote_addr;");
    expect(outer).not.toContain("$proxy_add_x_forwarded_for");
  });
});
