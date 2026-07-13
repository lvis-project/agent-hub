import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { addressFromPublicKey, enrollIdentity, loadOrCreateIdentity } from "./identity.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("plugin-owned Agent Hub identity", () => {
  it("creates a stable P-256 ECDSA key pair with owner-only storage", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-hub-identity-"));
    temporaryDirectories.push(directory);
    const identityPath = join(directory, "nested", "identity.json");

    const first = await loadOrCreateIdentity(identityPath);
    const second = await loadOrCreateIdentity(identityPath);
    const mode = (await stat(identityPath)).mode & 0o777;

    expect(first.publicAddress).toMatch(/^ah1_[0-9a-f]{40}$/);
    expect(second.publicAddress).toBe(first.publicAddress);
    expect(addressFromPublicKey(first.publicKeyPem)).toBe(first.publicAddress);
    expect(mode).toBe(0o600);
    expect(JSON.parse(await readFile(identityPath, "utf8"))).not.toHaveProperty("access_token");
  });

  it("signs the server challenge and never sends the private key", async () => {
    const directory = await mkdtemp(join(tmpdir(), "agent-hub-enrollment-"));
    temporaryDirectories.push(directory);
    const identity = await loadOrCreateIdentity(join(directory, "identity.json"));
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async (url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      calls.push({ url, body });
      if (url.endsWith("/challenge")) {
        return new Response(JSON.stringify({
          challenge_id: "challenge_12345678901234567890",
          message: "AGENT_HUB_SIGNUP_V1\\nchallenge",
          expires_at: "2026-07-11T00:05:00Z",
        }), { status: 201 });
      }
      return new Response(JSON.stringify({
        public_address: identity.publicAddress,
        employee_code: "AGENT-TEST",
        access_token: "agh_issued",
        token_type: "bearer",
        expires_at: "2026-10-09T00:00:00Z",
        registered: true,
      }), { status: 201 });
    }) as typeof fetch;
    try {
      const result = await enrollIdentity("https://hub.example.test", identity, "Tower Agent");

      expect(result.access_token).toBe("agh_issued");
      expect(calls).toHaveLength(2);
      expect(calls[0]?.body).toMatchObject({
        public_address: identity.publicAddress,
        public_key_pem: identity.publicKeyPem,
        display_name: "Tower Agent",
      });
      expect(calls.flatMap((call) => Object.values(call.body))).not.toContain(identity.privateKeyPem);
      expect(calls[1]?.body.signature).toEqual(expect.any(String));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
