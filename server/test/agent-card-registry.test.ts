import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AgentCardAdmissionError,
  admitAgentCard,
  canonicalizeAgentCardPayload,
  type AgentCardAdmissionPolicy,
} from "../src/a2a/agent-card-registry.js";

interface TestSigner {
  readonly keyId: string;
  readonly algorithm: "ES256" | "EdDSA";
  readonly publicKeyPem: string;
  readonly signCard: (value: Record<string, unknown>, payload?: Buffer) => void;
}

const SPEC_CANONICAL_CARD =
  '{"capabilities":{"extendedAgentCard":false,"pushNotifications":false,"streaming":false},' +
  '"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],' +
  '"description":"A bounded remote work assistant.","name":"LVIS Work Assistant",' +
  '"securityRequirements":[{"schemes":{"bearerAuth":{}}}],' +
  '"securitySchemes":{"bearerAuth":{"httpAuthSecurityScheme":' +
  '{"bearerFormat":"opaque","scheme":"bearer"}}},' +
  '"skills":[{"description":"Run one bounded work item.","id":"delegate-work",' +
  '"inputModes":["text/plain"],"name":"Delegate work","outputModes":["text/plain"],' +
  '"tags":["delegation"]}],"supportedInterfaces":[{"protocolBinding":"JSONRPC",' +
  '"protocolVersion":"1.0","url":"https://agent.example.test/a2a"}],"version":"1.0.0"}';

const DEL_AND_C1_CONTROLS = [
  ["DEL U+007F", "\u007f"],
  ["C1 U+0080", "\u0080"],
  ["C1 U+009F", "\u009f"],
] as const;

function card(): Record<string, unknown> {
  return {
    name: "LVIS Work Assistant",
    description: "A bounded remote work assistant.",
    version: "1.0.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extendedAgentCard: false,
    },
    skills: [
      {
        id: "delegate-work",
        name: "Delegate work",
        description: "Run one bounded work item.",
        tags: ["delegation"],
        inputModes: ["text/plain"],
        outputModes: ["text/plain"],
      },
    ],
    supportedInterfaces: [
      {
        url: "https://agent.example.test/a2a",
        protocolBinding: "JSONRPC",
        protocolVersion: "1.0",
      },
    ],
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    securitySchemes: {
      bearerAuth: {
        httpAuthSecurityScheme: {
          scheme: "bearer",
          bearerFormat: "opaque",
        },
      },
    },
    securityRequirements: [{ schemes: { bearerAuth: { list: [] } } }],
  };
}

function es256Signer(keyId = "work-assistant-2026") {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    keyId,
    algorithm: "ES256" as const,
    publicKeyPem,
    signCard(value: Record<string, unknown>, payload = canonicalizeAgentCardPayload(value)) {
      const protectedHeader = Buffer.from(
        JSON.stringify({ alg: "ES256", kid: keyId, typ: "JOSE" }),
      ).toString("base64url");
      const encodedPayload = payload.toString("base64url");
      const signingInput = Buffer.from(`${protectedHeader}.${encodedPayload}`, "ascii");
      const signature = sign("sha256", signingInput, {
        key: pair.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64url");
      value.signatures = [{ protected: protectedHeader, signature }];
    },
  };
}

function eddsaSigner(keyId = "work-assistant-ed25519"): TestSigner {
  const pair = generateKeyPairSync("ed25519");
  const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    keyId,
    algorithm: "EdDSA",
    publicKeyPem,
    signCard(value, payload = canonicalizeAgentCardPayload(value)) {
      const protectedHeader = Buffer.from(
        JSON.stringify({ alg: "EdDSA", kid: keyId, typ: "JOSE" }),
      ).toString("base64url");
      const encodedPayload = payload.toString("base64url");
      const signingInput = Buffer.from(`${protectedHeader}.${encodedPayload}`, "ascii");
      value.signatures = [
        {
          protected: protectedHeader,
          signature: sign(null, signingInput, pair.privateKey).toString("base64url"),
        },
      ];
    },
  };
}

function policyFor(signer: TestSigner, active = true): AgentCardAdmissionPolicy {
  return policyForMany([[signer, active]]);
}

function policyForMany(entries: readonly (readonly [TestSigner, boolean])[]): AgentCardAdmissionPolicy {
  return {
    trustedKeys: entries.map(([signer, active]) => ({
      keyId: signer.keyId,
      algorithm: signer.algorithm,
      publicKeyPem: signer.publicKeyPem,
      active,
    })),
  };
}

function signatureFrom(signer: TestSigner, value: Record<string, unknown>): Record<string, unknown> {
  const copy = structuredClone(value);
  delete copy.signatures;
  signer.signCard(copy);
  return (copy.signatures as Record<string, unknown>[])[0]!;
}

function expectRejected(value: Record<string, unknown>, code: string) {
  try {
    admitAgentCard(value);
    throw new Error("expected Agent Card rejection");
  } catch (error) {
    expect(error).toBeInstanceOf(AgentCardAdmissionError);
    expect((error as AgentCardAdmissionError).code).toBe(code);
    expect((error as Error).message).toBe(code);
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
  }
}

describe("P4-1 Agent Card registry admission", () => {
  it("admits an unsigned card as discovered but never routable", () => {
    const result = admitAgentCard(card());

    expect(result.trustState).toBe("discovered");
    expect(result.verifiedKeyId).toBeNull();
    expect(result.routable).toBe(false);
    expect(result.payloadSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("promotes a valid trusted ES256 signature without enabling routing", () => {
    const signer = es256Signer();
    const value = card();
    signer.signCard(value);

    const result = admitAgentCard(value, policyFor(signer));

    expect(result.trustState).toBe("trusted");
    expect(result.verifiedKeyId).toBe(signer.keyId);
    expect(result.routable).toBe(false);
  });

  it("accepts a valid trust key PEM without a trailing newline", () => {
    const signer = es256Signer();
    const value = card();
    signer.signCard(value);
    const policy: AgentCardAdmissionPolicy = {
      trustedKeys: [
        {
          ...policyFor(signer).trustedKeys![0]!,
          publicKeyPem: signer.publicKeyPem.trimEnd(),
        },
      ],
    };

    expect(admitAgentCard(value, policy)).toMatchObject({
      trustState: "trusted",
      verifiedKeyId: signer.keyId,
      routable: false,
    });
  });

  it("accepts the case-insensitive HTTPS scheme required by URL syntax", () => {
    const signer = es256Signer();
    const value = card();
    (value.supportedInterfaces as Array<{ url: string }>)[0]!.url =
      "HTTPS://agent.example.test/a2a";
    signer.signCard(value);

    expect(admitAgentCard(value, policyFor(signer))).toMatchObject({
      trustState: "trusted",
      verifiedKeyId: signer.keyId,
      routable: false,
    });
  });

  it("accepts ordinary Unicode in text and a valid HTTPS URL", () => {
    const value = card();
    value.name = "LVIS 작업 도우미";
    value.description = "일반 Unicode 설명 — café와 협업 😀";
    (value.supportedInterfaces as Array<{ url: string }>)[0]!.url =
      "https://agent.example.test/업무/위임?mode=협업";

    expect(admitAgentCard(value)).toMatchObject({
      name: "LVIS 작업 도우미",
      preferredInterface: "https://agent.example.test/업무/위임?mode=협업",
      trustState: "discovered",
      routable: false,
    });
  });

  it.each(DEL_AND_C1_CONTROLS)("rejects %s in Agent Card text", (_label, control) => {
    const value = card();
    value.description = `before${control}after`;

    expectRejected(value, "text-invalid");
  });

  it.each(DEL_AND_C1_CONTROLS)("rejects %s in an interface URL", (_label, control) => {
    const value = card();
    (value.supportedInterfaces as Array<{ url: string }>)[0]!.url =
      `https://agent.example.test/a${control}b`;

    expectRejected(value, "interface-not-https");
  });

  it("matches an independent A2A presence/default canonicalization fixture", () => {
    const signer = es256Signer();
    const value = card();
    const protoJsonValue = JSON.parse(SPEC_CANONICAL_CARD) as Record<string, unknown>;

    expect(canonicalizeAgentCardPayload(value).toString("utf8")).toBe(SPEC_CANONICAL_CARD);
    signer.signCard(value, Buffer.from(SPEC_CANONICAL_CARD, "utf8"));
    signer.signCard(protoJsonValue, Buffer.from(SPEC_CANONICAL_CARD, "utf8"));

    expect(admitAgentCard(value, policyFor(signer))).toMatchObject({
      trustState: "trusted",
      verifiedKeyId: signer.keyId,
      routable: false,
    });
    expect(admitAgentCard(protoJsonValue, policyFor(signer))).toMatchObject({
      trustState: "trusted",
      verifiedKeyId: signer.keyId,
      routable: false,
    });
  });

  it("rejects array index accessors without evaluating them", () => {
    const value = card();
    const skills = value.skills as Array<unknown>;
    const skill = skills[0];
    let getterCalls = 0;
    Object.defineProperty(skills, "0", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return skill;
      },
    });

    expectRejected(value, "invalid-json");
    expect(getterCalls).toBe(0);
  });

  it("supports an explicitly trusted EdDSA Agent Card key", () => {
    const signer = eddsaSigner();
    const value = card();
    signer.signCard(value);

    const result = admitAgentCard(value, policyFor(signer));

    expect(result.trustState).toBe("trusted");
    expect(result.verifiedKeyId).toBe(signer.keyId);
    expect(result.routable).toBe(false);
  });

  it("leaves a valid signature from an unknown key discovered", () => {
    const signer = es256Signer("unknown-provider");
    const value = card();
    signer.signCard(value);

    const result = admitAgentCard(value);

    expect(result.trustState).toBe("discovered");
    expect(result.verifiedKeyId).toBeNull();
  });

  it("rejects tampering after a known key signed the card", () => {
    const signer = es256Signer();
    const value = card();
    signer.signCard(value);
    value.description = "Tampered description";

    expect(() => admitAgentCard(value, policyFor(signer))).toThrowError(
      expect.objectContaining({ code: "signature-invalid" }),
    );
  });

  it("rejects a signature claiming a revoked key", () => {
    const signer = es256Signer("revoked-provider");
    const value = card();
    signer.signCard(value);

    expect(() => admitAgentCard(value, policyFor(signer, false))).toThrowError(
      expect.objectContaining({ code: "signature-key-revoked" }),
    );
  });

  it("rejects a revoked known key even after an earlier signature verifies", () => {
    const validSigner = es256Signer("active-provider");
    const revokedSigner = es256Signer("revoked-provider");
    const value = card();
    value.signatures = [
      signatureFrom(validSigner, value),
      signatureFrom(revokedSigner, value),
    ];

    expect(() =>
      admitAgentCard(
        value,
        policyForMany([
          [validSigner, true],
          [revokedSigner, false],
        ]),
      ),
    ).toThrowError(expect.objectContaining({ code: "signature-key-revoked" }));
  });

  it.each(["invalid-first", "invalid-last"])(
    "rejects an invalid known signature regardless of order (%s)",
    (order) => {
      const validSigner = es256Signer("valid-provider");
      const invalidSigner = es256Signer("invalid-provider");
      const value = card();
      const valid = signatureFrom(validSigner, value);
      const invalid = signatureFrom(invalidSigner, value);
      const original = invalid.signature as string;
      invalid.signature = `${original[0] === "A" ? "B" : "A"}${original.slice(1)}`;
      value.signatures = order === "invalid-first" ? [invalid, valid] : [valid, invalid];

      expect(() =>
        admitAgentCard(
          value,
          policyForMany([
            [validSigner, true],
            [invalidSigner, true],
          ]),
        ),
      ).toThrowError(expect.objectContaining({ code: "signature-invalid" }));
    },
  );

  it.each([
    [
      (value: any) => (value.supportedInterfaces[0].url = "http://agent.test/a2a"),
      "interface-not-https",
    ],
    [
      (value: any) => (value.supportedInterfaces[0].url = "https://agent.test/a2a "),
      "interface-not-https",
    ],
    [(value: any) => delete value.securitySchemes, "validation-failed"],
    [(value: any) => delete value.securityRequirements, "validation-failed"],
    [
      (value: any) => (value.securityRequirements[0].schemes.missing = { list: [] }),
      "security-scheme-unknown",
    ],
    [
      (value: any) => (value.securityRequirements[0].schemes.toString = { list: [] }),
      "security-scheme-unknown",
    ],
    [(value: any) => value.skills.push({ ...value.skills[0] }), "skill-id-duplicate"],
    [
      (value: any) => value.supportedInterfaces.push({ ...value.supportedInterfaces[0] }),
      "interface-duplicate",
    ],
    [
      (value: any) => (value.supportedInterfaces[0].protocolBinding = "GRPC"),
      "interface-binding-unsupported",
    ],
    [
      (value: any) => (value.supportedInterfaces[0].protocolVersion = "2.0"),
      "interface-version-unsupported",
    ],
    [
      (value: any) =>
        (value.securitySchemes.bearerAuth.httpAuthSecurityScheme.scheme = "basic"),
      "security-scheme-unsupported",
    ],
    [(value: any) => (value.provider = { organization: "unexpected" }), "validation-failed"],
  ])("fails closed for invalid cards", (mutate, code) => {
    const value = card();
    mutate(value);
    expectRejected(value, code);
  });

  it("rejects malformed protected headers", () => {
    const value = card();
    value.signatures = [{ protected: "not+base64url", signature: "AA" }];

    expectRejected(value, "signature-malformed");
  });

  it("rejects a malformed ES256 signature even when its key is unknown", () => {
    const value = card();
    const protectedHeader = Buffer.from(
      JSON.stringify({ alg: "ES256", kid: "unknown-provider", typ: "JOSE" }),
    ).toString("base64url");
    value.signatures = [{ protected: protectedHeader, signature: "AA" }];

    expectRejected(value, "signature-malformed");
  });

  it("rejects unsupported algorithms even when their key is unknown", () => {
    const value = card();
    const protectedHeader = Buffer.from(
      JSON.stringify({ alg: "none", kid: "unknown-provider", typ: "JOSE" }),
    ).toString("base64url");
    value.signatures = [{ protected: protectedHeader, signature: "A".repeat(86) }];

    expectRejected(value, "signature-algorithm-unsupported");
  });

  it("rejects duplicate protected-header fields", () => {
    const value = card();
    const protectedHeader = Buffer.from(
      '{"alg":"ES256","kid":"first","kid":"second","typ":"JOSE"}',
    ).toString("base64url");
    value.signatures = [{ protected: protectedHeader, signature: "AA" }];

    expectRejected(value, "signature-header-duplicate");
  });

  it("does not fetch jku and requires it to use HTTPS", () => {
    const value = card();
    const protectedHeader = Buffer.from(
      JSON.stringify({
        alg: "ES256",
        kid: "unknown-provider",
        typ: "JOSE",
        jku: "http://keys.example.test/jwks.json",
      }),
    ).toString("base64url");
    value.signatures = [{ protected: protectedHeader, signature: "AA" }];

    expectRejected(value, "signature-jku-not-https");
  });

  it.each(DEL_AND_C1_CONTROLS)("rejects %s in a protected jku", (_label, control) => {
    const value = card();
    const protectedHeader = Buffer.from(
      JSON.stringify({
        alg: "ES256",
        kid: "unknown-provider",
        typ: "JOSE",
        jku: `https://keys.example.test/a${control}b`,
      }),
    ).toString("base64url");
    value.signatures = [{ protected: protectedHeader, signature: "A".repeat(86) }];

    expectRejected(value, "signature-jku-not-https");
  });

  it("requires an unprotected jku to use HTTPS too", () => {
    const signer = es256Signer("unknown-provider");
    const value = card();
    const signature = signatureFrom(signer, value);
    signature.header = { jku: "http://keys.example.test/jwks.json" };
    value.signatures = [signature];

    expectRejected(value, "signature-jku-not-https");
  });

  it.each(DEL_AND_C1_CONTROLS)("rejects %s in an unprotected jku", (_label, control) => {
    const signer = es256Signer("unknown-provider");
    const value = card();
    const signature = signatureFrom(signer, value);
    signature.header = { jku: `https://keys.example.test/a${control}b` };
    value.signatures = [signature];

    expectRejected(value, "signature-jku-not-https");
  });

  it("canonicalizes independently of key order and excludes signatures", () => {
    const value = card();
    const reordered = Object.fromEntries(Object.entries(value).reverse());
    reordered.signatures = [{ protected: "AA", signature: "AA" }];

    expect(canonicalizeAgentCardPayload(value)).toEqual(
      canonicalizeAgentCardPayload(reordered),
    );
  });

  it("rejects policy attempts to widen the reviewed protocol set", () => {
    expect(() =>
      admitAgentCard(card(), { supportedProtocolVersions: ["2.0"] }),
    ).toThrowError(expect.objectContaining({ code: "policy-version-unsupported" }));
  });

  it("rejects malformed runtime trust policy values with a stable code", () => {
    expect(() =>
      admitAgentCard(card(), { trustedKeys: [null] } as unknown as AgentCardAdmissionPolicy),
    ).toThrowError(expect.objectContaining({ code: "policy-key-invalid" }));
  });

  it("rejects oversized cards before schema validation", () => {
    const value = card();
    value.description = "x".repeat(64 * 1024);

    expectRejected(value, "card-too-large");
  });
});
