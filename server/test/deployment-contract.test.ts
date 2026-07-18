import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const deploymentFile = (name: string) => new URL(`../deploy/${name}`, import.meta.url);
const execFileAsync = promisify(execFile);

const directiveStatements = (config: string, name: string): string[] => [
  ...config
    .replace(/^\s*#.*$/gm, "")
    .matchAll(new RegExp(`\\b${name}\\s+([^;]+);`, "g")),
].map(([, value]) => {
  if (!value) {
    throw new Error(`${name} directive must include a value`);
  }
  return `${name} ${value.trim().replace(/\s+/g, " ")};`;
});

const validateTunnelPeer = (peer: string) => execFileAsync(
  "sh",
  [fileURLToPath(deploymentFile("10-validate-cloudflared-tunnel-peer.sh"))],
  {
    env: { ...process.env, CLOUDFLARED_TUNNEL_PEER_IP: peer },
  },
);

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

    expect(directiveStatements(tunnel, "listen")).toEqual([
      "listen 127.0.0.1:18082;",
    ]);
    expect(directiveStatements(tunnel, "set_real_ip_from")).toEqual([
      "set_real_ip_from 127.0.0.1;",
    ]);
    expect(directiveStatements(tunnel, "real_ip_header")).toEqual([
      "real_ip_header CF-Connecting-IP;",
    ]);
    expect(directiveStatements(tunnel, "real_ip_recursive")).toEqual([
      "real_ip_recursive off;",
    ]);
    expect(directiveStatements(tunnel, "proxy_set_header")).toEqual([
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

  it("locks the optional Docker bridge Tunnel edge to one validated peer", async () => {
    const [dockerfile, overlay, edge, ignored] = await Promise.all([
      readFile(deploymentFile("Dockerfile.cloudflare-tunnel-edge"), "utf8"),
      readFile(deploymentFile("docker-compose.cloudflare-tunnel-edge.yml"), "utf8"),
      readFile(deploymentFile("nginx.cloudflare-tunnel-edge.conf.template"), "utf8"),
      readFile(new URL("../.gitignore", import.meta.url), "utf8"),
    ]);

    expect(dockerfile).toContain("nginx.cloudflare-tunnel-edge.conf.template");
    expect(dockerfile).toContain("10-validate-cloudflared-tunnel-peer.sh");
    expect(overlay).toContain("profiles: [cloudflare-tunnel-edge]");
    expect(overlay).toContain('"127.0.0.1:18082:80"');
    expect(overlay).toContain(
      "CLOUDFLARED_TUNNEL_PEER_IP: ${CLOUDFLARED_TUNNEL_PEER_IP:?set a verified single Docker bridge gateway address}",
    );
    expect(overlay).toContain("networks: [agent_hub_private]");
    expect(overlay).not.toContain("network_mode: host");
    expect(overlay).not.toContain("0.0.0.0:");
    expect(overlay).not.toMatch(/^\s*cloudflared:/m);
    expect(ignored).toContain("deploy/cloudflare-tunnel-edge.env");
    expect(directiveStatements(edge, "listen")).toEqual([
      "listen 80 default_server;",
    ]);
    expect(directiveStatements(edge, "set_real_ip_from")).toEqual([
      "set_real_ip_from ${CLOUDFLARED_TUNNEL_PEER_IP};",
    ]);
    expect(directiveStatements(edge, "real_ip_header")).toEqual([
      "real_ip_header CF-Connecting-IP;",
    ]);
    expect(directiveStatements(edge, "real_ip_recursive")).toEqual([
      "real_ip_recursive off;",
    ]);
    expect(directiveStatements(edge, "proxy_pass")).toEqual([
      "proxy_pass http://web:80;",
    ]);
    expect(directiveStatements(edge, "proxy_set_header")).toEqual([
      "proxy_set_header Host $host;",
      "proxy_set_header X-Real-IP $remote_addr;",
      "proxy_set_header X-Forwarded-For $remote_addr;",
      "proxy_set_header X-Forwarded-Proto https;",
      'proxy_set_header CF-Connecting-IP "";',
    ]);
    expect(edge).not.toContain("$http_x_forwarded_for");
    expect(edge).not.toContain("$proxy_add_x_forwarded_for");
    expect(edge).not.toContain("0.0.0.0/0");
  });

  it.skipIf(process.platform === "win32")("rejects unsafe Docker bridge peers before nginx starts", async () => {
    await expect(validateTunnelPeer("172.30.0.1")).resolves.toBeDefined();
    await expect(validateTunnelPeer("10.0.0.1")).resolves.toBeDefined();
    await expect(validateTunnelPeer("192.168.0.1")).resolves.toBeDefined();
    await expect(validateTunnelPeer("")).rejects.toBeDefined();
    await expect(validateTunnelPeer("172.30.0.0/24")).rejects.toBeDefined();
    await expect(validateTunnelPeer("edge.example.test")).rejects.toBeDefined();
    await expect(validateTunnelPeer("999.30.0.1")).rejects.toBeDefined();
    await expect(validateTunnelPeer("8.8.8.8")).rejects.toBeDefined();
    await expect(validateTunnelPeer("127.0.0.1")).rejects.toBeDefined();
    await expect(validateTunnelPeer("0.0.0.0")).rejects.toBeDefined();
  });
});
