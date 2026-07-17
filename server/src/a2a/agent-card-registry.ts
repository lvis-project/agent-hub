import {
  createHash,
  createPublicKey,
  type KeyObject,
  verify as verifySignature,
} from "node:crypto";
import { TextDecoder } from "node:util";
import { z } from "zod";

const MAX_AGENT_CARD_BYTES = 64 * 1024;
const REVIEWED_PROTOCOL_VERSIONS = new Set(["1.0"]);
const REVIEWED_PROTOCOL_BINDINGS = new Set(["JSONRPC"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SCHEME_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const SKILL_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
// Unicode reserves C0, DEL, and C1 as control codes. Agent Card text and URL
// inputs are displayable/auditable protocol metadata, so raw instances of all
// three ranges are rejected while ordinary Unicode scalar values remain valid.
const FORBIDDEN_CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;
const DANGEROUS_EXTENSION_MEMBER_NAMES = new Set(["__proto__", "prototype", "constructor"]);
const MAX_EXTENSION_PARAMS_BYTES = 4_096;
const MAX_EXTENSION_PARAMS_DEPTH = 4;
const MAX_EXTENSION_PARAMS_VALUES = 64;
const MAX_EXTENSION_COLLECTION_ITEMS = 32;

export const EXACT_SEND_REPLAY_EXTENSION_URI = "urn:uuid:383a1d70-5c3b-42d9-a65d-9f084b7a1a44";
export const EXACT_SEND_REPLAY_EXTENSION_DESCRIPTION =
  "Durable exact replay for ambiguous non-streaming SendMessage responses.";

export class AgentCardAdmissionError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "AgentCardAdmissionError";
    this.code = code;
  }
}

export type AgentCardTrustState = "discovered" | "trusted";
export type AgentCardSignatureAlgorithm = "ES256" | "EdDSA";

export interface TrustedAgentCardKey {
  readonly keyId: string;
  readonly algorithm: AgentCardSignatureAlgorithm;
  readonly publicKeyPem: string;
  readonly active: boolean;
}

export interface AgentCardAdmissionPolicy {
  readonly trustedKeys?: readonly TrustedAgentCardKey[];
  readonly supportedProtocolVersions?: readonly string[];
}

export interface AdmittedAgentCard {
  readonly name: string;
  readonly version: string;
  readonly preferredInterface: string;
  readonly payloadSha256: string;
  readonly trustState: AgentCardTrustState;
  readonly verifiedKeyId: string | null;
  readonly routable: false;
}

export interface PreparedAgentCardAdmission {
  readonly admitted: AdmittedAgentCard;
  readonly documentJson: string;
  readonly documentSha256: string;
  readonly payloadJson: string;
  readonly payloadSha256: string;
}

export interface PreparedAgentCardDocument {
  readonly documentJson: string;
  readonly documentSha256: string;
  readonly payloadJson: string;
  readonly payloadSha256: string;
  readonly name: string;
  readonly version: string;
  readonly preferredInterface: string;
}

const preparedDocumentInternals = new WeakMap<PreparedAgentCardDocument, {
  readonly card: AgentCard;
  readonly payload: Buffer;
}>();

const extensionSchema = z.strictObject({
  uri: z.string().min(1),
  description: z.string().optional(),
  required: z.boolean().optional(),
  params: z.record(z.string(), z.unknown()).optional(),
});

const capabilitiesSchema = z.strictObject({
  streaming: z.boolean().optional(),
  pushNotifications: z.boolean().optional(),
  extendedAgentCard: z.boolean().optional(),
  extensions: z.array(extensionSchema).max(16).optional(),
});

const interfaceSchema = z.strictObject({
  url: z.string().min(1).max(2048),
  protocolBinding: z.string().min(1).max(32),
  protocolVersion: z.string().min(1).max(32),
  tenant: z.string().min(1).max(128).optional(),
});

const skillSchema = z.strictObject({
  id: z.string().min(1).max(128),
  name: z.string().min(1).max(128),
  description: z.string().min(1).max(2048),
  tags: z.array(z.string().min(1).max(128)).min(1).max(32),
  examples: z.array(z.string().min(1).max(2048)).max(16).optional(),
  inputModes: z.array(z.string().min(1).max(128)).min(1).max(16).optional(),
  outputModes: z.array(z.string().min(1).max(128)).min(1).max(16).optional(),
});

const httpAuthSchemeSchema = z.strictObject({
  scheme: z.string().min(1).max(32),
  description: z.string().min(1).max(512).optional(),
  bearerFormat: z.string().min(1).max(64).optional(),
});

const securitySchemeSchema = z.strictObject({
  httpAuthSecurityScheme: httpAuthSchemeSchema,
});

const securityRequirementValueSchema = z.strictObject({
  list: z.array(z.string().min(1).max(128)).max(16).default([]),
});

const securityRequirementSchema = z.strictObject({
  schemes: z.record(z.string(), securityRequirementValueSchema),
});

const unprotectedHeaderValueSchema = z.union([z.string(), z.boolean()]);
const signatureSchema = z.strictObject({
  protected: z.string().min(1).max(4096),
  signature: z.string().min(1).max(4096),
  header: z.record(z.string(), unprotectedHeaderValueSchema).optional(),
});

const agentCardSchema = z.strictObject({
  name: z.string().min(1).max(128),
  description: z.string().min(1).max(2048),
  version: z.string().min(1).max(64),
  capabilities: capabilitiesSchema,
  skills: z.array(skillSchema).min(1).max(64),
  supportedInterfaces: z.array(interfaceSchema).min(1).max(16),
  defaultInputModes: z.array(z.string().min(1).max(128)).min(1).max(16),
  defaultOutputModes: z.array(z.string().min(1).max(128)).min(1).max(16),
  securitySchemes: z.record(z.string(), securitySchemeSchema),
  securityRequirements: z.array(securityRequirementSchema).min(1).max(16),
  signatures: z.array(signatureSchema).max(16).optional(),
});

type AgentCard = z.infer<typeof agentCardSchema>;
type AgentCardSignature = z.infer<typeof signatureSchema>;

interface CompiledTrustKey {
  readonly definition: TrustedAgentCardKey;
  readonly publicKey: KeyObject;
}

interface CompiledPolicy {
  readonly trustedKeys: ReadonlyMap<string, CompiledTrustKey>;
  readonly supportedProtocolVersions: ReadonlySet<string>;
}

interface ProtectedHeader {
  readonly alg: string;
  readonly kid: string;
  readonly typ: "JOSE";
  readonly jku?: string;
}

export interface AgentCardProtectedSignatureHint {
  readonly algorithm: AgentCardSignatureAlgorithm;
  readonly keyId: string;
  readonly jku: string | null;
}

function reject(code: string): never {
  throw new AgentCardAdmissionError(code);
}

function assertValidUnicode(value: string, code: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) reject(code);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      reject(code);
    }
  }
}

function assertSupportedJson(value: unknown, seen = new WeakSet<object>()): void {
  if (typeof value === "string") {
    assertValidUnicode(value, "canonicalization-invalid-unicode");
    return;
  }
  if (typeof value === "boolean") return;
  if (value === null) return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) reject("canonicalization-unsupported-value");
    return;
  }
  if (typeof value !== "object") {
    reject("canonicalization-unsupported-value");
  }
  if (seen.has(value)) reject("invalid-json");
  seen.add(value);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) reject("invalid-json");
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      typeof lengthDescriptor.value !== "number" ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0
    ) {
      reject("invalid-json");
    }
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1) reject("invalid-json");
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
        reject("invalid-json");
      }
      assertSupportedJson(descriptor.value, seen);
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) reject("invalid-json");
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") reject("invalid-json");
      assertValidUnicode(key, "canonicalization-invalid-unicode");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
        reject("invalid-json");
      }
      assertSupportedJson(descriptor.value, seen);
    }
  }
  seen.delete(value);
}

function boundedJsonSnapshot(rawCard: unknown): Record<string, unknown> {
  try {
    assertSupportedJson(rawCard);
  } catch (error) {
    if (error instanceof AgentCardAdmissionError) throw error;
    reject("invalid-json");
  }
  if (Array.isArray(rawCard) || rawCard === null || typeof rawCard !== "object") {
    reject("invalid-json");
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(rawCard);
  } catch {
    reject("invalid-json");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_AGENT_CARD_BYTES) reject("card-too-large");
  return JSON.parse(serialized) as Record<string, unknown>;
}

function canonicalJson(value: unknown): string {
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  }
  return reject("canonicalization-unsupported-value");
}

function removeEmptyRepeatedField(record: Record<string, unknown>, field: string): void {
  const value = record[field];
  if (Array.isArray(value) && value.length === 0) delete record[field];
}

function stripProtocolDefaults(payload: Record<string, unknown>): void {
  delete payload.signatures;
  removeEmptyRepeatedField(payload, "securityRequirements");
  const capabilities = payload.capabilities;
  if (capabilities !== null && typeof capabilities === "object" && !Array.isArray(capabilities)) {
    // The three boolean fields use proto `optional`, so an explicitly present
    // false is presence-bearing and MUST remain. Only the non-optional repeated
    // extensions field has an empty default that is stripped.
    removeEmptyRepeatedField(capabilities as Record<string, unknown>, "extensions");
  }
  const skills = payload.skills;
  if (Array.isArray(skills)) {
    for (const skill of skills) {
      if (skill === null || typeof skill !== "object" || Array.isArray(skill)) continue;
      const skillRecord = skill as Record<string, unknown>;
      removeEmptyRepeatedField(skillRecord, "examples");
      removeEmptyRepeatedField(skillRecord, "inputModes");
      removeEmptyRepeatedField(skillRecord, "outputModes");
      removeEmptyRepeatedField(skillRecord, "securityRequirements");
    }
  }
  const securityRequirements = payload.securityRequirements;
  if (Array.isArray(securityRequirements)) {
    for (const requirement of securityRequirements) {
      if (requirement === null || typeof requirement !== "object" || Array.isArray(requirement)) {
        continue;
      }
      const schemes = (requirement as Record<string, unknown>).schemes;
      if (schemes === null || typeof schemes !== "object" || Array.isArray(schemes)) continue;
      for (const value of Object.values(schemes)) {
        if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
        removeEmptyRepeatedField(value as Record<string, unknown>, "list");
      }
    }
  }
}

export function canonicalizeAgentCardPayload(card: Record<string, unknown>): Buffer {
  assertSupportedJson(card);
  const payload = JSON.parse(JSON.stringify(card)) as Record<string, unknown>;
  stripProtocolDefaults(payload);
  return Buffer.from(canonicalJson(payload), "utf8");
}

function canonicalizeSnapshotPayload(documentJson: string): Buffer {
  const payload = JSON.parse(documentJson) as Record<string, unknown>;
  stripProtocolDefaults(payload);
  return Buffer.from(canonicalJson(payload), "utf8");
}

function validateText(value: string, code: string): void {
  if (value !== value.trim() || FORBIDDEN_CONTROL_CHARACTER.test(value)) reject(code);
}

function validateUniqueStrings(values: readonly string[], code: string): void {
  if (new Set(values).size !== values.length) reject(code);
  for (const value of values) validateText(value, code);
}

function validateHttpsUrl(value: string, code: string): void {
  if (
    !/^https:\/\//i.test(value) ||
    /\s/u.test(value) ||
    value.includes("\\") ||
    FORBIDDEN_CONTROL_CHARACTER.test(value)
  ) {
    reject(code);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    reject(code);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.length === 0 ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.hash.length > 0
  ) {
    reject(code);
  }
}

export function canonicalizeAgentExtensionUri(value: string): string {
  if (Buffer.byteLength(value, "utf8") > 2_048) reject("extension-uri-too-large");
  // The reviewed exact-replay profile uses a domain-free, version-specific URN.
  // All other extension identifiers retain the stricter public HTTPS boundary.
  if (value === EXACT_SEND_REPLAY_EXTENSION_URI) return value;
  validateHttpsUrl(value, "extension-uri-not-https");
  const parsed = new URL(value);
  return parsed.href;
}

function validateExtensionParams(params: Record<string, unknown>): void {
  let totalValues = 0;
  const visit = (value: unknown, depth: number): void => {
    totalValues += 1;
    if (totalValues > MAX_EXTENSION_PARAMS_VALUES) reject("extension-params-too-many-values");
    if (depth > MAX_EXTENSION_PARAMS_DEPTH) reject("extension-params-too-deep");
    if (typeof value === "string") {
      if (Buffer.byteLength(value, "utf8") > 2_048) reject("extension-params-string-too-large");
      assertValidUnicode(value, "extension-params-invalid-unicode");
      if (FORBIDDEN_CONTROL_CHARACTER.test(value)) reject("extension-params-control-character");
      return;
    }
    if (typeof value === "boolean") return;
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) reject("extension-params-invalid-container");
      if (value.length > MAX_EXTENSION_COLLECTION_ITEMS) reject("extension-params-array-too-large");
      for (const item of value) visit(item, depth + 1);
      return;
    }
    if (value === null || typeof value !== "object") reject("extension-params-unsupported-value");
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) reject("extension-params-invalid-container");
    const entries = Object.entries(value);
    if (entries.length > MAX_EXTENSION_COLLECTION_ITEMS) reject("extension-params-object-too-large");
    for (const [key, child] of entries) {
      assertValidUnicode(key, "extension-params-invalid-unicode");
      if (
        Buffer.byteLength(key, "utf8") > 128 ||
        FORBIDDEN_CONTROL_CHARACTER.test(key) ||
        DANGEROUS_EXTENSION_MEMBER_NAMES.has(key)
      ) {
        reject("extension-params-member-invalid");
      }
      visit(child, depth + 1);
    }
  };
  visit(params, 1);
  if (Buffer.byteLength(canonicalJson(params), "utf8") > MAX_EXTENSION_PARAMS_BYTES) {
    reject("extension-params-too-large");
  }
}

function validateExtensions(extensions: readonly z.infer<typeof extensionSchema>[] | undefined): void {
  if (extensions === undefined) return;
  const canonicalUris = new Set<string>();
  for (const extension of extensions) {
    const canonicalUri = canonicalizeAgentExtensionUri(extension.uri);
    if (canonicalUris.has(canonicalUri)) reject("extension-uri-duplicate");
    canonicalUris.add(canonicalUri);
    if (extension.description !== undefined) {
      assertValidUnicode(extension.description, "extension-description-invalid");
      if (
        Buffer.byteLength(extension.description, "utf8") > 512 ||
        FORBIDDEN_CONTROL_CHARACTER.test(extension.description)
      ) {
        reject("extension-description-invalid");
      }
    }
    if (extension.params !== undefined) validateExtensionParams(extension.params);
  }
}

function compilePolicy(policy: AgentCardAdmissionPolicy | undefined): CompiledPolicy {
  if (
    policy?.supportedProtocolVersions !== undefined &&
    !Array.isArray(policy.supportedProtocolVersions)
  ) {
    reject("policy-version-unsupported");
  }
  if (policy?.trustedKeys !== undefined && !Array.isArray(policy.trustedKeys)) {
    reject("policy-key-invalid");
  }
  const versions = new Set(policy?.supportedProtocolVersions ?? REVIEWED_PROTOCOL_VERSIONS);
  if (versions.size === 0) reject("policy-version-unsupported");
  for (const version of versions) {
    if (!REVIEWED_PROTOCOL_VERSIONS.has(version)) reject("policy-version-unsupported");
  }

  const keys = new Map<string, CompiledTrustKey>();
  for (const definition of policy?.trustedKeys ?? []) {
    if (
      definition === null ||
      typeof definition !== "object" ||
      typeof definition.keyId !== "string" ||
      !KEY_ID.test(definition.keyId) ||
      keys.has(definition.keyId) ||
      (definition.algorithm !== "ES256" && definition.algorithm !== "EdDSA") ||
      typeof definition.active !== "boolean" ||
      typeof definition.publicKeyPem !== "string" ||
      definition.publicKeyPem.length > 8192
    ) {
      reject("policy-key-invalid");
    }
    const publicKeyPem = definition.publicKeyPem.endsWith("\n")
      ? definition.publicKeyPem
      : `${definition.publicKeyPem}\n`;
    if (
      publicKeyPem !== `${definition.publicKeyPem.trimEnd()}\n` ||
      definition.publicKeyPem !== definition.publicKeyPem.trimStart() ||
      !publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")
    ) {
      reject("policy-key-invalid");
    }
    let publicKey: KeyObject;
    try {
      publicKey = createPublicKey(publicKeyPem);
    } catch {
      reject("policy-key-invalid");
    }
    if (
      (definition.algorithm === "ES256" &&
        (publicKey.asymmetricKeyType !== "ec" ||
          publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1")) ||
      (definition.algorithm === "EdDSA" && publicKey.asymmetricKeyType !== "ed25519")
    ) {
      reject("policy-key-invalid");
    }
    keys.set(definition.keyId, {
      definition: { ...definition, publicKeyPem },
      publicKey,
    });
  }
  return { trustedKeys: keys, supportedProtocolVersions: versions };
}

function validateCard(card: AgentCard, policy: CompiledPolicy): void {
  for (const value of [card.name, card.description, card.version]) {
    validateText(value, "text-invalid");
  }
  validateUniqueStrings(card.defaultInputModes, "input-mode-invalid");
  validateUniqueStrings(card.defaultOutputModes, "output-mode-invalid");
  validateExtensions(card.capabilities.extensions);

  const interfaceUrls: string[] = [];
  for (const agentInterface of card.supportedInterfaces) {
    validateHttpsUrl(agentInterface.url, "interface-not-https");
    if (!REVIEWED_PROTOCOL_BINDINGS.has(agentInterface.protocolBinding)) {
      reject("interface-binding-unsupported");
    }
    if (!policy.supportedProtocolVersions.has(agentInterface.protocolVersion)) {
      reject("interface-version-unsupported");
    }
    if (agentInterface.tenant !== undefined) validateText(agentInterface.tenant, "tenant-invalid");
    interfaceUrls.push(agentInterface.url);
  }
  if (new Set(interfaceUrls).size !== interfaceUrls.length) reject("interface-duplicate");

  const skillIds: string[] = [];
  for (const skill of card.skills) {
    if (!SKILL_ID.test(skill.id)) reject("skill-id-invalid");
    validateText(skill.name, "skill-text-invalid");
    validateText(skill.description, "skill-text-invalid");
    validateUniqueStrings(skill.tags, "skill-tag-invalid");
    if (skill.examples !== undefined) validateUniqueStrings(skill.examples, "skill-example-invalid");
    if (skill.inputModes !== undefined) {
      validateUniqueStrings(skill.inputModes, "skill-input-mode-invalid");
    }
    if (skill.outputModes !== undefined) {
      validateUniqueStrings(skill.outputModes, "skill-output-mode-invalid");
    }
    skillIds.push(skill.id);
  }
  if (new Set(skillIds).size !== skillIds.length) reject("skill-id-duplicate");

  const schemeEntries = Object.entries(card.securitySchemes);
  if (schemeEntries.length === 0 || schemeEntries.length > 16) reject("validation-failed");
  for (const [name, scheme] of schemeEntries) {
    if (!SCHEME_NAME.test(name)) reject("security-scheme-name-invalid");
    if (scheme.httpAuthSecurityScheme.scheme !== "bearer") {
      reject("security-scheme-unsupported");
    }
    if (scheme.httpAuthSecurityScheme.description !== undefined) {
      validateText(scheme.httpAuthSecurityScheme.description, "security-scheme-text-invalid");
    }
    if (scheme.httpAuthSecurityScheme.bearerFormat !== undefined) {
      validateText(scheme.httpAuthSecurityScheme.bearerFormat, "security-scheme-text-invalid");
    }
  }
  for (const requirement of card.securityRequirements) {
    const requirementEntries = Object.entries(requirement.schemes);
    if (requirementEntries.length === 0 || requirementEntries.length > 16) {
      reject("validation-failed");
    }
    for (const [name, value] of requirementEntries) {
      if (!Object.hasOwn(card.securitySchemes, name)) reject("security-scheme-unknown");
      validateUniqueStrings(value.list, "security-scope-invalid");
    }
  }
}

function decodeBase64url(value: string): Buffer {
  if (!BASE64URL.test(value)) reject("signature-malformed");
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    reject("signature-malformed");
  }
  if (decoded.toString("base64url") !== value) reject("signature-malformed");
  return decoded;
}

function parseJsonString(source: string, cursor: { index: number }): string {
  if (source[cursor.index] !== '"') reject("signature-malformed");
  const start = cursor.index;
  cursor.index += 1;
  while (cursor.index < source.length) {
    const character = source[cursor.index];
    if (character === '"') {
      cursor.index += 1;
      let value: unknown;
      try {
        value = JSON.parse(source.slice(start, cursor.index));
      } catch {
        reject("signature-malformed");
      }
      if (typeof value !== "string") reject("signature-malformed");
      assertValidUnicode(value, "signature-malformed");
      return value;
    }
    if (character === "\\") {
      cursor.index += 1;
      const escape = source[cursor.index];
      if (escape === "u") {
        const hex = source.slice(cursor.index + 1, cursor.index + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) reject("signature-malformed");
        cursor.index += 4;
      } else if (escape === undefined || !'"\\/bfnrt'.includes(escape)) {
        reject("signature-malformed");
      }
    } else if (character === undefined || character.charCodeAt(0) < 0x20) {
      reject("signature-malformed");
    }
    cursor.index += 1;
  }
  return reject("signature-malformed");
}

function skipWhitespace(source: string, cursor: { index: number }): void {
  while (" \t\r\n".includes(source[cursor.index] ?? "\0")) cursor.index += 1;
}

function parseProtectedHeader(source: string): Record<string, string> {
  const cursor = { index: 0 };
  const result = Object.create(null) as Record<string, string>;
  skipWhitespace(source, cursor);
  if (source[cursor.index] !== "{") reject("signature-malformed");
  cursor.index += 1;
  skipWhitespace(source, cursor);
  if (source[cursor.index] === "}") reject("signature-header-invalid");
  for (;;) {
    const key = parseJsonString(source, cursor);
    if (Object.hasOwn(result, key)) reject("signature-header-duplicate");
    skipWhitespace(source, cursor);
    if (source[cursor.index] !== ":") reject("signature-malformed");
    cursor.index += 1;
    skipWhitespace(source, cursor);
    result[key] = parseJsonString(source, cursor);
    skipWhitespace(source, cursor);
    const delimiter = source[cursor.index];
    cursor.index += 1;
    if (delimiter === "}") break;
    if (delimiter !== ",") reject("signature-malformed");
    skipWhitespace(source, cursor);
  }
  skipWhitespace(source, cursor);
  if (cursor.index !== source.length) reject("signature-malformed");
  return result;
}

function protectedHeader(signature: AgentCardSignature): ProtectedHeader {
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64url(signature.protected));
  } catch (error) {
    if (error instanceof AgentCardAdmissionError) throw error;
    reject("signature-malformed");
  }
  const header = parseProtectedHeader(decoded);
  if (Object.keys(header).some((key) => !["alg", "kid", "typ", "jku"].includes(key))) {
    reject("signature-header-unsupported");
  }
  if (!header.alg || !header.kid || !KEY_ID.test(header.kid) || header.typ !== "JOSE") {
    reject("signature-header-invalid");
  }
  if (header.jku !== undefined) validateHttpsUrl(header.jku, "signature-jku-not-https");
  const unprotected = signature.header ?? {};
  if (Object.keys(unprotected).length > 16) reject("signature-header-unsupported");
  for (const [key, value] of Object.entries(unprotected)) {
    validateText(key, "signature-header-invalid");
    if (["alg", "kid", "jku", "crit", "b64", "jwk", "x5u", "x5c", "x5t", "x5t#S256"].includes(key)) {
      reject("signature-header-unprotected-security-parameter");
    }
    if (typeof value === "string") {
      validateText(value, "signature-header-invalid");
    }
  }
  if (Object.keys(header).some((key) => Object.hasOwn(unprotected, key))) {
    reject("signature-header-conflict");
  }
  return {
    alg: header.alg,
    kid: header.kid,
    typ: "JOSE",
    ...(header.jku === undefined ? {} : { jku: header.jku }),
  };
}

function verifySignatures(
  signatures: readonly AgentCardSignature[],
  payload: Buffer,
  policy: CompiledPolicy,
): string | null {
  const verifiedKeyIds = new Set<string>();
  const encodedPayload = payload.toString("base64url");
  for (const signature of signatures) {
    const header = protectedHeader(signature);
    const signatureBytes = decodeBase64url(signature.signature);
    if (header.alg !== "ES256" && header.alg !== "EdDSA") {
      reject("signature-algorithm-unsupported");
    }
    if (signatureBytes.length !== 64) reject("signature-malformed");
    const trustedKey = policy.trustedKeys.get(header.kid);
    if (trustedKey === undefined) continue;
    if (!trustedKey.definition.active) reject("signature-key-revoked");
    if (header.alg !== trustedKey.definition.algorithm) {
      reject("signature-algorithm-unsupported");
    }
    const signingInput = Buffer.from(`${signature.protected}.${encodedPayload}`, "ascii");
    let valid: boolean;
    try {
      valid =
        header.alg === "ES256"
          ? verifySignature(
              "sha256",
              signingInput,
              { key: trustedKey.publicKey, dsaEncoding: "ieee-p1363" },
              signatureBytes,
            )
          : verifySignature(null, signingInput, trustedKey.publicKey, signatureBytes);
    } catch {
      reject("signature-invalid");
    }
    if (!valid) reject("signature-invalid");
    verifiedKeyIds.add(header.kid);
  }
  return [...verifiedKeyIds].sort()[0] ?? null;
}

export function admitAgentCard(
  rawCard: unknown,
  policy?: AgentCardAdmissionPolicy,
): AdmittedAgentCard {
  return prepareAgentCardAdmission(rawCard, policy).admitted;
}

export function prepareAgentCardAdmission(
  rawCard: unknown,
  policy?: AgentCardAdmissionPolicy,
): PreparedAgentCardAdmission {
  const compiledPolicy = compilePolicy(policy);
  const prepared = prepareAgentCardDocumentWithPolicy(rawCard, compiledPolicy);
  return admitPreparedAgentCardDocument(prepared, policy);
}

function prepareAgentCardDocumentWithPolicy(
  rawCard: unknown,
  compiledPolicy: CompiledPolicy,
): PreparedAgentCardDocument {
  const cardJson = boundedJsonSnapshot(rawCard);
  const parsed = agentCardSchema.safeParse(cardJson);
  if (!parsed.success) reject("validation-failed");
  validateCard(parsed.data, compiledPolicy);

  const documentJson = canonicalJson(cardJson);
  const payload = canonicalizeSnapshotPayload(documentJson);
  const payloadJson = payload.toString("utf8");
  const documentSha256 = createHash("sha256").update(documentJson, "utf8").digest("hex");
  const payloadSha256 = createHash("sha256").update(payload).digest("hex");
  const prepared = Object.freeze({
    documentJson,
    documentSha256,
    payloadJson,
    payloadSha256,
    name: parsed.data.name,
    version: parsed.data.version,
    preferredInterface: parsed.data.supportedInterfaces[0]!.url,
  });
  preparedDocumentInternals.set(prepared, { card: parsed.data, payload });
  return prepared;
}

export function prepareAgentCardDocument(rawCard: unknown): PreparedAgentCardDocument {
  return prepareAgentCardDocumentWithPolicy(rawCard, compilePolicy(undefined));
}

export function protectedAgentCardSignatureHints(
  prepared: PreparedAgentCardDocument,
): readonly AgentCardProtectedSignatureHint[] {
  const internal = preparedDocumentInternals.get(prepared);
  if (internal === undefined) reject("invalid-json");
  const hints = (internal.card.signatures ?? []).map((signature) => {
    const header = protectedHeader(signature);
    if (header.alg !== "ES256" && header.alg !== "EdDSA") {
      reject("signature-algorithm-unsupported");
    }
    return Object.freeze({
      algorithm: header.alg,
      keyId: header.kid,
      jku: header.jku ?? null,
    });
  });
  return Object.freeze(hints);
}

export function admitPreparedAgentCardDocument(
  prepared: PreparedAgentCardDocument,
  policy?: AgentCardAdmissionPolicy,
): PreparedAgentCardAdmission {
  const internal = preparedDocumentInternals.get(prepared);
  if (internal === undefined) reject("invalid-json");
  const compiledPolicy = compilePolicy(policy);
  validateCard(internal.card, compiledPolicy);
  const verifiedKeyId = verifySignatures(internal.card.signatures ?? [], internal.payload, compiledPolicy);
  const admitted = Object.freeze({
    name: prepared.name,
    version: prepared.version,
    preferredInterface: prepared.preferredInterface,
    payloadSha256: prepared.payloadSha256,
    trustState: verifiedKeyId === null ? "discovered" : "trusted",
    verifiedKeyId,
    routable: false,
  });
  return Object.freeze({
    admitted,
    documentJson: prepared.documentJson,
    documentSha256: prepared.documentSha256,
    payloadJson: prepared.payloadJson,
    payloadSha256: prepared.payloadSha256,
  });
}
