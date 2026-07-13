// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getStoredKey } from "../src/lib/auth";
import { loadOrCreateBrowserIdentity, signSignupMessage } from "../src/lib/browser-identity";
import { SignupPage } from "../src/pages/SignupPage";

vi.mock("../src/lib/browser-identity", () => ({
  loadOrCreateBrowserIdentity: vi.fn(),
  signSignupMessage: vi.fn(),
}));

const identity = {
  privateKey: {} as CryptoKey,
  publicAddress: "ah1_0123456789abcdef0123456789abcdef01234567",
  publicKeyPem: "-----BEGIN PUBLIC KEY-----\npublic-key\n-----END PUBLIC KEY-----\n",
};

const originalSessionStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");

beforeEach(() => {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    },
  });
  vi.mocked(loadOrCreateBrowserIdentity).mockResolvedValue(identity);
  vi.mocked(signSignupMessage).mockResolvedValue("der-base64url-signature");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  if (originalSessionStorage) Object.defineProperty(globalThis, "sessionStorage", originalSessionStorage);
  else Reflect.deleteProperty(globalThis, "sessionStorage");
});

describe("browser signup", () => {
  it("sends only public identity fields, signs the server message, and stores the compatible Bearer token in-session", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ challenge_id: "challenge-id", message: "server-signature-message" }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ public_address: identity.publicAddress, access_token: "agh_signup_token", token_type: "bearer" }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);

    render(<MemoryRouter><SignupPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: "Browser agent" } });
    fireEvent.click(screen.getByRole("button", { name: /Create account/ }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(signSignupMessage).toHaveBeenCalledWith(identity, "server-signature-message");
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      public_address: identity.publicAddress,
      public_key_pem: identity.publicKeyPem,
      display_name: "Browser agent",
    });
    const completionBody = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body));
    expect(completionBody).toEqual({
      challenge_id: "challenge-id",
      public_address: identity.publicAddress,
      public_key_pem: identity.publicKeyPem,
      signature: "der-base64url-signature",
    });
    expect(JSON.stringify(completionBody)).not.toContain("privateKey");
    expect(getStoredKey()).toBe("agh_signup_token");
  });
});
