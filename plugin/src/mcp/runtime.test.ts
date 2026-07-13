import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { loadIdentity, loadOrCreateIdentity, saveIdentity } from "../identity.js";
import { AgentHubMcpRuntime } from "./runtime.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function identityPathForTest(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "agent-hub-runtime-"));
  temporaryDirectories.push(directory);
  return join(directory, "identity.json");
}

function profileResponse(): Response {
  return new Response(JSON.stringify({
    employee_code: "AGENT-TEST", name: "Test agent", email: "agent@example.test",
    department: { code: "AGENTS", name: "Agents", path: "/AGENTS" }, job_level: 1,
    manager_chain: [], role: "employee", unread_count: 0, public_address: "ah1_test", contribution_tokens: "0",
  }), { status: 200 });
}

describe("Agent Hub MCP runtime", () => {
  it("does not create an identity or register an account from a read-only request", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-hub-runtime-"));
    temporaryDirectories.push(directory);
    const identityPath = join(directory, "identity.json");
    const fetchSpy = vi.fn();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({
        hubServerUrl: "http://127.0.0.1:8123",
        identityPath,
      });

      await expect(runtime.profile()).rejects.toThrow("로그인이 필요합니다");
      await expect(readFile(identityPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("validates and retains a valid identity-file Bearer even with stale local expiry metadata", async () => {
    const identityPath = await identityPathForTest();
    const identity = await loadOrCreateIdentity(identityPath);
    await saveIdentity(identityPath, { ...identity, bearerToken: "agh_valid_identity", bearerExpiresAt: "2000-01-01T00:00:00.000Z" });
    const fetchSpy = vi.fn().mockResolvedValue(profileResponse());
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({ hubServerUrl: "http://127.0.0.1:8123", identityPath });
      await expect(runtime.register()).resolves.toMatchObject({ registered: false, bearerTokenSource: "identity-file", public_address: identity.publicAddress });
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(String(fetchSpy.mock.calls[0]?.[0])).toBe("http://127.0.0.1:8123/api/v1/me");
      expect(new Headers(fetchSpy.mock.calls[0]?.[1]?.headers).get("authorization")).toBe("Bearer agh_valid_identity");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("re-enrolls a revoked identity-file Bearer only after the explicit registration validation fails", async () => {
    const identityPath = await identityPathForTest();
    const identity = await loadOrCreateIdentity(identityPath);
    await saveIdentity(identityPath, { ...identity, bearerToken: "agh_revoked_identity", bearerExpiresAt: "2031-01-01T00:00:00.000Z" });
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce(new Response("revoked", { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ challenge_id: "signup-challenge", message: "server-signature-message", expires_at: "2031-01-01T00:00:00.000Z" }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ public_address: identity.publicAddress, employee_code: "AGENT-TEST", access_token: "agh_reissued_identity", token_type: "bearer", expires_at: "2031-01-01T00:00:00.000Z", registered: false }), { status: 201 }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({ hubServerUrl: "http://127.0.0.1:8123", identityPath });
      await expect(runtime.register("Recovery agent")).resolves.toMatchObject({ bearerTokenSource: "ecdsa-signup", public_address: identity.publicAddress });
      expect(fetchSpy).toHaveBeenCalledTimes(3);
      expect(String(fetchSpy.mock.calls[0]?.[0])).toBe("http://127.0.0.1:8123/api/v1/me");
      expect(new Headers(fetchSpy.mock.calls[0]?.[1]?.headers).get("authorization")).toBe("Bearer agh_revoked_identity");
      expect(String(fetchSpy.mock.calls[1]?.[0])).toBe("http://127.0.0.1:8123/api/v1/auth/signup/challenge");
      expect(String(fetchSpy.mock.calls[2]?.[0])).toBe("http://127.0.0.1:8123/api/v1/auth/signup");
      expect((await loadIdentity(identityPath))?.bearerToken).toBe("agh_reissued_identity");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not re-enroll an explicitly configured Bearer token", async () => {
    const identityPath = await identityPathForTest();
    const fetchSpy = vi.fn();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({ hubServerUrl: "http://127.0.0.1:8123", token: "agh_operator_token", identityPath });
      await expect(runtime.register()).resolves.toEqual({ registered: false, bearerTokenSource: "existing" });
      expect(fetchSpy).not.toHaveBeenCalled();
      await expect(readFile(identityPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not rotate an identity-file Bearer when validation is unavailable", async () => {
    const identityPath = await identityPathForTest();
    const identity = await loadOrCreateIdentity(identityPath);
    await saveIdentity(identityPath, { ...identity, bearerToken: "agh_unknown_identity", bearerExpiresAt: "2031-01-01T00:00:00.000Z" });
    const fetchSpy = vi.fn().mockResolvedValue(new Response("upstream unavailable", { status: 503 }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({ hubServerUrl: "http://127.0.0.1:8123", identityPath });
      await expect(runtime.register()).rejects.toThrow("503");
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect((await loadIdentity(identityPath))?.bearerToken).toBe("agh_unknown_identity");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("does not rotate an identity-file Bearer when validation cannot reach the server", async () => {
    const identityPath = await identityPathForTest();
    const identity = await loadOrCreateIdentity(identityPath);
    await saveIdentity(identityPath, { ...identity, bearerToken: "agh_network_identity", bearerExpiresAt: "2031-01-01T00:00:00.000Z" });
    const fetchSpy = vi.fn().mockRejectedValue(new TypeError("network unavailable"));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchSpy as typeof fetch;
    try {
      const runtime = new AgentHubMcpRuntime({ hubServerUrl: "http://127.0.0.1:8123", identityPath });
      await expect(runtime.register()).rejects.toThrow("network unavailable");
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect((await loadIdentity(identityPath))?.bearerToken).toBe("agh_network_identity");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
