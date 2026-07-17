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

  it("limits Cloudflare Tunnel client-IP normalization to a loopback connector", async () => {
    const tunnel = await readFile(deploymentFile("outer-proxy.cloudflare-tunnel.nginx.example.conf"), "utf8");
    const directives = tunnel
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));

    expect(directives.filter((line) => line.startsWith("listen "))).toEqual([
      "listen 127.0.0.1:18082;",
    ]);
    expect(directives.filter((line) => line.startsWith("set_real_ip_from "))).toEqual([
      "set_real_ip_from 127.0.0.1;",
    ]);
    expect(directives.filter((line) => line.startsWith("real_ip_header "))).toEqual([
      "real_ip_header CF-Connecting-IP;",
    ]);
    expect(directives.filter((line) => line.startsWith("real_ip_recursive "))).toEqual([
      "real_ip_recursive off;",
    ]);
    expect(directives.filter((line) => line.startsWith("proxy_set_header "))).toEqual([
      "proxy_set_header Host $host;",
      "proxy_set_header X-Real-IP $remote_addr;",
      "proxy_set_header X-Forwarded-For $remote_addr;",
      "proxy_set_header X-Forwarded-Proto https;",
      'proxy_set_header CF-Connecting-IP "";',
    ]);
    expect(tunnel).not.toContain("$http_x_forwarded_for");
    expect(tunnel).not.toContain("$proxy_add_x_forwarded_for");
    expect(tunnel).not.toContain("0.0.0.0/0");
    expect(tunnel).not.toContain("listen 0.0.0.0:");
  });
});
