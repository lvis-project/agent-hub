import { createPublicKey, verify, webcrypto } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createBrowserIdentity, signSignupMessage } from "../src/lib/browser-identity";

const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");

beforeEach(() => {
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: webcrypto });
});

afterEach(() => {
  if (originalCrypto) Object.defineProperty(globalThis, "crypto", originalCrypto);
  else Reflect.deleteProperty(globalThis, "crypto");
});

function fromBase64Url(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

describe("browser ECDSA identity", () => {
  it("derives an Agent Hub address and emits the server's DER signature format", async () => {
    const identity = await createBrowserIdentity();
    const message = "AGENT_HUB_SIGNUP_V1\nchallenge\nah1_example";
    const signature = await signSignupMessage(identity, message);

    expect(identity.privateKey.extractable).toBe(false);
    expect(identity.publicAddress).toMatch(/^ah1_[0-9a-f]{40}$/);
    expect(verify("sha256", Buffer.from(message), createPublicKey(identity.publicKeyPem), fromBase64Url(signature))).toBe(true);
  });
});
