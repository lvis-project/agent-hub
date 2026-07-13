import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

export const ADDRESS_PREFIX = "ah1_";

export class IdentityValidationError extends Error {}

export function canonicalPublicKeyPem(publicKeyPem: string): string {
  try {
    const publicKey = createPublicKey(publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ec" || publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new IdentityValidationError("Public key must use the P-256 ECDSA curve.");
    }
    return publicKey.export({ type: "spki", format: "pem" }).toString();
  } catch (error) {
    if (error instanceof IdentityValidationError) throw error;
    throw new IdentityValidationError("Public key must be a PEM-encoded P-256 ECDSA key.");
  }
}

export function publicKeyDer(publicKeyPem: string): Buffer {
  return createPublicKey(canonicalPublicKeyPem(publicKeyPem)).export({ type: "spki", format: "der" });
}

export function publicKeyFingerprint(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyDer(publicKeyPem)).digest("hex");
}

export function addressFromPublicKeyPem(publicKeyPem: string): string {
  return `${ADDRESS_PREFIX}${publicKeyFingerprint(publicKeyPem).slice(0, 40)}`;
}

export function requireMatchingAddress(publicAddress: string, publicKeyPem: string): string {
  const expected = addressFromPublicKeyPem(publicKeyPem);
  if (publicAddress !== expected) {
    throw new IdentityValidationError("Public address does not match the supplied public key.");
  }
  return expected;
}

export function signupMessage(input: {
  challengeId: string;
  publicAddress: string;
  publicKeyPem: string;
  displayName: string;
  expiresAt: string;
}): Buffer {
  return Buffer.from([
    "AGENT_HUB_SIGNUP_V1",
    input.challengeId,
    input.publicAddress,
    publicKeyFingerprint(input.publicKeyPem),
    input.displayName,
    input.expiresAt,
  ].join("\n"), "utf8");
}

export function verifySignupSignature(publicKeyPem: string, message: Buffer, signature: string): void {
  try {
    const valid = verify("sha256", message, createPublicKey(canonicalPublicKeyPem(publicKeyPem)), Buffer.from(signature, "base64url"));
    if (!valid) throw new IdentityValidationError("Signature verification failed.");
  } catch (error) {
    if (error instanceof IdentityValidationError) throw error;
    throw new IdentityValidationError("Signature is not valid base64url.");
  }
}

export function newBearerToken(): string {
  return `agh_${randomBytes(32).toString("base64url")}`;
}

export function newChallengeId(): string {
  return randomBytes(24).toString("base64url");
}
