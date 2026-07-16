import { createHash, createPublicKey, type JsonWebKey } from "node:crypto";
import type { AgentCardProtectedSignatureHint, AgentCardSignatureAlgorithm, TrustedAgentCardKey } from "./agent-card-registry.js";
import { DiscoveryBoundaryError } from "./discovery-egress.js";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_JWKS_KEYS = 32;
const PRIVATE_OR_SECRET_FIELDS = new Set(["d", "k", "p", "q", "dp", "dq", "qi", "oth"]);

export interface ObservedJwksKey {
  readonly keyId: string;
  readonly algorithm: AgentCardSignatureAlgorithm;
  readonly publicKeyPem: string;
  readonly fingerprintSha256: string;
  readonly trustedDefinition: TrustedAgentCardKey;
}

export class MissingObservedJwksKeyError extends DiscoveryBoundaryError {
  constructor() {
    super("jwks-rejected", 502);
    this.name = "MissingObservedJwksKeyError";
  }
}

function invalid(): never {
  throw new DiscoveryBoundaryError("jwks-rejected", 502);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key) || PRIVATE_OR_SECRET_FIELDS.has(key)) invalid();
  }
}

function requiredString(value: Record<string, unknown>, key: string): string {
  const result = value[key];
  if (typeof result !== "string") invalid();
  return result;
}

function decodedCoordinate(value: unknown): string {
  if (typeof value !== "string" || !BASE64URL.test(value)) invalid();
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    invalid();
  }
  if (decoded.length !== 32 || decoded.toString("base64url") !== value) invalid();
  return value;
}

function validateUseAndOperations(value: Record<string, unknown>): void {
  if (value.use !== undefined && value.use !== "sig") invalid();
  if (value.key_ops !== undefined) {
    if (!Array.isArray(value.key_ops) || value.key_ops.length !== 1 || value.key_ops[0] !== "verify") invalid();
  }
}

function canonicalKey(value: Record<string, unknown>): ObservedJwksKey {
  const keyId = requiredString(value, "kid");
  if (!KEY_ID.test(keyId)) invalid();
  const kty = requiredString(value, "kty");
  let algorithm: AgentCardSignatureAlgorithm;
  let jwk: JsonWebKey;
  if (kty === "EC") {
    exactKeys(value, new Set(["kty", "crv", "x", "y", "kid", "use", "key_ops", "alg"]));
    if (requiredString(value, "crv") !== "P-256") invalid();
    if (value.alg !== undefined && value.alg !== "ES256") invalid();
    validateUseAndOperations(value);
    algorithm = "ES256";
    jwk = {
      kty: "EC",
      crv: "P-256",
      x: decodedCoordinate(value.x),
      y: decodedCoordinate(value.y),
      kid: keyId,
      use: "sig",
      key_ops: ["verify"],
      alg: "ES256",
    };
  } else if (kty === "OKP") {
    exactKeys(value, new Set(["kty", "crv", "x", "kid", "use", "key_ops", "alg"]));
    if (requiredString(value, "crv") !== "Ed25519") invalid();
    if (value.alg !== undefined && value.alg !== "EdDSA") invalid();
    validateUseAndOperations(value);
    algorithm = "EdDSA";
    jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: decodedCoordinate(value.x),
      kid: keyId,
      use: "sig",
      key_ops: ["verify"],
      alg: "EdDSA",
    };
  } else {
    invalid();
  }

  try {
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const fingerprintSha256 = createHash("sha256")
      .update(publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    return Object.freeze({
      keyId,
      algorithm,
      publicKeyPem,
      fingerprintSha256,
      trustedDefinition: Object.freeze({ keyId, algorithm, publicKeyPem, active: true }),
    });
  } catch {
    return invalid();
  }
}

export function parseObservedJwks(value: unknown): readonly ObservedJwksKey[] {
  const root = record(value);
  exactKeys(root, new Set(["keys"]));
  if (!Array.isArray(root.keys) || root.keys.length < 1 || root.keys.length > MAX_JWKS_KEYS) invalid();
  const seenKeyIds = new Set<string>();
  const keys = root.keys.map((candidate) => {
    const key = canonicalKey(record(candidate));
    if (seenKeyIds.has(key.keyId)) invalid();
    seenKeyIds.add(key.keyId);
    return key;
  });
  return Object.freeze(keys);
}

export function requiredObservedKeys(
  keys: readonly ObservedJwksKey[],
  hints: readonly AgentCardProtectedSignatureHint[],
): readonly ObservedJwksKey[] {
  const required = new Map<string, ObservedJwksKey>();
  for (const hint of hints) {
    if (hint.jku === null) continue;
    const key = keys.find((candidate) => candidate.keyId === hint.keyId);
    if (key === undefined || key.algorithm !== hint.algorithm) throw new MissingObservedJwksKeyError();
    required.set(`${key.keyId}:${key.fingerprintSha256}`, key);
  }
  if (hints.some((hint) => hint.jku !== null) && required.size === 0) invalid();
  return Object.freeze([...required.values()]);
}
