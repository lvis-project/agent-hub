import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export interface AgentIdentity {
  privateKeyPem: string;
  publicKeyPem: string;
  publicAddress: string;
  bearerToken?: string;
  bearerExpiresAt?: string;
}

export interface AgentEnrollment {
  public_address: string;
  employee_code: string;
  access_token: string;
  token_type: "bearer";
  expires_at: string;
  registered: boolean;
}

interface SignupChallenge {
  challenge_id: string;
  message: string;
  expires_at: string;
}

const IDENTITY_VERSION = 1;

export function defaultIdentityPath(): string {
  return join(homedir(), ".agent-hub", "identity.json");
}

export function addressFromPublicKey(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return `ah1_${createHash("sha256").update(der).digest("hex").slice(0, 40)}`;
}

function validateIdentity(candidate: AgentIdentity): AgentIdentity {
  const derivedPublicKey = createPublicKey(createPrivateKey(candidate.privateKeyPem))
    .export({ type: "spki", format: "pem" })
    .toString();
  const expectedAddress = addressFromPublicKey(derivedPublicKey);
  if (candidate.publicKeyPem !== derivedPublicKey || candidate.publicAddress !== expectedAddress) {
    throw new Error("Agent Hub identity file does not contain a matching P-256 ECDSA key pair.");
  }
  return { ...candidate, publicKeyPem: derivedPublicKey };
}

function createIdentity(): AgentIdentity {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return {
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
    publicAddress: addressFromPublicKey(publicKey),
  };
}

export async function saveIdentity(identityPath: string, identity: AgentIdentity): Promise<void> {
  await mkdir(dirname(identityPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${identityPath}.${process.pid}.${Date.now()}.tmp`;
  const payload = JSON.stringify({ version: IDENTITY_VERSION, ...identity }, null, 2);
  await writeFile(temporaryPath, payload, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, identityPath);
  await chmod(identityPath, 0o600);
}

export async function loadIdentity(identityPath = defaultIdentityPath()): Promise<AgentIdentity | null> {
  try {
    const parsed = JSON.parse(await readFile(identityPath, "utf8")) as {
      version?: unknown;
    } & Partial<AgentIdentity>;
    if (
      parsed.version !== IDENTITY_VERSION
      || typeof parsed.privateKeyPem !== "string"
      || typeof parsed.publicKeyPem !== "string"
      || typeof parsed.publicAddress !== "string"
      || (parsed.bearerToken !== undefined && typeof parsed.bearerToken !== "string")
      || (parsed.bearerExpiresAt !== undefined && typeof parsed.bearerExpiresAt !== "string")
    ) {
      throw new Error("Agent Hub identity file has an unsupported format.");
    }
    return validateIdentity({
      privateKeyPem: parsed.privateKeyPem,
      publicKeyPem: parsed.publicKeyPem,
      publicAddress: parsed.publicAddress,
      bearerToken: parsed.bearerToken,
      bearerExpiresAt: parsed.bearerExpiresAt,
    });
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }

}

export async function loadOrCreateIdentity(identityPath = defaultIdentityPath()): Promise<AgentIdentity> {
  const existing = await loadIdentity(identityPath);
  if (existing) return existing;
  const identity = createIdentity();
  await saveIdentity(identityPath, identity);
  return identity;
}

function signatureFor(privateKeyPem: string, message: string): string {
  return sign("sha256", Buffer.from(message, "utf8"), {
    key: privateKeyPem,
    dsaEncoding: "der",
  }).toString("base64url");
}

async function requestJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Agent Hub registration failed (${response.status}): ${detail || response.statusText}`);
  }
  return await response.json() as T;
}

export async function enrollIdentity(
  serverUrl: string,
  identity: AgentIdentity,
  displayName: string,
): Promise<AgentEnrollment> {
  const challenge = await requestJson<SignupChallenge>(`${serverUrl}/api/v1/auth/signup/challenge`, {
    public_address: identity.publicAddress,
    public_key_pem: identity.publicKeyPem,
    display_name: displayName,
  });
  return await requestJson<AgentEnrollment>(`${serverUrl}/api/v1/auth/signup`, {
    challenge_id: challenge.challenge_id,
    public_address: identity.publicAddress,
    public_key_pem: identity.publicKeyPem,
    signature: signatureFor(identity.privateKeyPem, challenge.message),
  });
}
