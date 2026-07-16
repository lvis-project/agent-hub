import { createHash, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { asNumber, asString, type SqlDatabase, type SqlRow } from "../db.js";
import {
  EXACT_SEND_REPLAY_EXTENSION_DESCRIPTION,
  EXACT_SEND_REPLAY_EXTENSION_URI,
} from "./agent-card-registry.js";
import {
  DiscoveryBoundaryError,
  probeBoundedHttpsReachability,
  type DiscoveryClock,
  type DiscoveryResolver,
  type DiscoveryTransport,
} from "./discovery-egress.js";

const SHA256 = /^[0-9a-f]{64}$/u;
const BOUNDED_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SNAPSHOT_TTL_MS = 30_000;

export type RouteOperationClass =
  | "initial_send"
  | "exact_initial_send_replay"
  | "get_task"
  | "continue_send"
  | "cancel_task"
  ;

export interface RouteActor {
  readonly id: number;
  readonly apiKeyId: number;
  readonly employeeCode: string;
}

export interface RouteProbeDependencies {
  readonly resolver?: DiscoveryResolver;
  readonly transport?: DiscoveryTransport;
  readonly clock?: DiscoveryClock;
}

export class RouteControlError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RouteControlError";
  }
}

function first<T>(rows: readonly T[], code: string, message: string): T {
  const row = rows[0];
  if (row === undefined) throw new RouteControlError(404, code, message);
  return row;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
      .join(",")}}`;
  }
  throw new RouteControlError(422, "invalid-request", "Request contains an unsupported value");
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function lockSuffix(db: SqlDatabase): string {
  return db.dialect === "postgres" ? " FOR UPDATE" : "";
}

function uniqueViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = "code" in error ? String(error.code) : "";
  if (code === "23505") return true;
  return code === "ERR_SQLITE_ERROR" && error instanceof Error && /^UNIQUE constraint failed:/u.test(error.message);
}

function canonicalInterfaceUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new RouteControlError(422, "interface-url-invalid", "interface_url must be an absolute URL");
  }
  if (
    parsed.protocol !== "https:" || parsed.port !== "" || parsed.username !== "" || parsed.password !== "" ||
    parsed.hash !== "" || parsed.hostname === "localhost" || isIP(parsed.hostname) !== 0 || parsed.href !== value
  ) {
    throw new RouteControlError(422, "interface-url-invalid", "interface_url must be canonical public HTTPS on port 443");
  }
  return parsed.href;
}

function assertDigest(value: string, field: string): void {
  if (!SHA256.test(value)) throw new RouteControlError(422, "digest-invalid", `${field} must be lowercase SHA-256`);
}

function assertBoundedId(value: string, field: string): void {
  if (!BOUNDED_ID.test(value)) throw new RouteControlError(422, "identifier-invalid", `${field} is invalid`);
}

function rejectPredecessor(): never {
  throw new RouteControlError(
    409,
    "predecessor-credential-revision-invalid",
    "The predecessor credential revision is not valid for this operation",
  );
}

function exactExtension(documentJson: string, expectedDigest: string): boolean {
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(documentJson) as Record<string, unknown>;
  } catch {
    return false;
  }
  const capabilities = document.capabilities;
  if (capabilities === null || typeof capabilities !== "object" || Array.isArray(capabilities)) return false;
  const extensions = (capabilities as Record<string, unknown>).extensions;
  if (!Array.isArray(extensions)) return false;
  const matches = extensions.filter((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
    return (entry as Record<string, unknown>).uri === EXACT_SEND_REPLAY_EXTENSION_URI;
  });
  if (matches.length !== 1) return false;
  const extension = matches[0] as Record<string, unknown>;
  const params = extension.params;
  if (params === null || typeof params !== "object" || Array.isArray(params)) return false;
  const expectedParams = {
    profile: "lvis-exact-send-replay",
    profileVersion: "1",
    requestBody: "exact-serialized-jsonrpc",
    resultRetentionSeconds: "604800",
    specDigestSha256: expectedDigest,
  };
  return extension.description === EXACT_SEND_REPLAY_EXTENSION_DESCRIPTION && extension.required === false &&
    stableJson(params) === stableJson(expectedParams);
}

function hasExactWireInterface(documentJson: string, interfaceUrl: string, schemeName: string): boolean {
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(documentJson) as Record<string, unknown>;
  } catch {
    return false;
  }
  const interfaces = document.supportedInterfaces;
  if (!Array.isArray(interfaces)) return false;
  const matches = interfaces.filter((entry) => entry !== null && typeof entry === "object" && !Array.isArray(entry) &&
    (entry as Record<string, unknown>).url === interfaceUrl &&
    (entry as Record<string, unknown>).protocolBinding === "JSONRPC" &&
    (entry as Record<string, unknown>).protocolVersion === "1.0");
  if (matches.length !== 1) return false;
  const schemes = document.securitySchemes;
  if (schemes === null || typeof schemes !== "object" || Array.isArray(schemes)) return false;
  const scheme = (schemes as Record<string, unknown>)[schemeName];
  if (scheme === null || typeof scheme !== "object" || Array.isArray(scheme)) return false;
  const http = (scheme as Record<string, unknown>).httpAuthSecurityScheme;
  const requirements = document.securityRequirements;
  const required = Array.isArray(requirements) && requirements.some((requirement) => {
    if (requirement === null || typeof requirement !== "object" || Array.isArray(requirement)) return false;
    const requirementSchemes = (requirement as Record<string, unknown>).schemes;
    return requirementSchemes !== null && typeof requirementSchemes === "object" &&
      !Array.isArray(requirementSchemes) && Object.hasOwn(requirementSchemes, schemeName);
  });
  return required && http !== null && typeof http === "object" && !Array.isArray(http) &&
    (http as Record<string, unknown>).scheme === "bearer";
}

async function insertAdminAudit(
  tx: SqlDatabase,
  actorId: number,
  action: string,
  targetKind: string,
  targetId: string,
  metadata: Record<string, unknown>,
  createdAt: string,
): Promise<void> {
  await tx.execute(`INSERT INTO a2a_route_admin_audit
    (actor_id, action, target_kind, target_id, metadata_json, created_at)
    VALUES ($1, $2, $3, $4, $5, $6)`, [actorId, action, targetKind, targetId, stableJson(metadata), createdAt]);
}

type MutationResult<T> = { readonly status: number; readonly body: T };

async function adminMutation<T>(
  db: SqlDatabase,
  actor: RouteActor,
  submissionId: string,
  operation: string,
  request: unknown,
  work: (tx: SqlDatabase, createdAt: string) => Promise<MutationResult<T>>,
): Promise<MutationResult<T>> {
  const requestHash = sha256(stableJson({ operation, request }));
  return db.transaction(async (tx) => {
    const createdAt = new Date().toISOString();
    const inserted = await tx.query<{ actor_id: unknown }>(`INSERT INTO a2a_mutation_submissions
      (actor_id, submission_id, operation, request_sha256, response_json, response_status, created_at)
      VALUES ($1, $2, $3, $4, NULL, NULL, $5)
      ON CONFLICT(actor_id, submission_id) DO NOTHING RETURNING actor_id`, [
      actor.id, submissionId, operation, requestHash, createdAt,
    ]);
    if (inserted.length === 0) {
      const replay = first(await tx.query<SqlRow>(`SELECT operation, request_sha256, response_json, response_status
        FROM a2a_mutation_submissions WHERE actor_id = $1 AND submission_id = $2${lockSuffix(tx)}`,
      [actor.id, submissionId]), "submission-not-found", "Submission was not found");
      if (asString(replay.operation) !== operation || asString(replay.request_sha256) !== requestHash) {
        throw new RouteControlError(409, "submission-mismatch", "submission_id was already used for a different request");
      }
      if (replay.response_json === null || replay.response_status === null) {
        throw new RouteControlError(409, "submission-in-progress", "Submission is still in progress");
      }
      return { status: asNumber(replay.response_status), body: JSON.parse(asString(replay.response_json)) as T };
    }
    const result = await work(tx, createdAt);
    await tx.execute(`UPDATE a2a_mutation_submissions SET response_json = $1, response_status = $2
      WHERE actor_id = $3 AND submission_id = $4`, [
      stableJson(result.body), result.status, actor.id, submissionId,
    ]);
    return result;
  });
}

function callerGenerationBody(row: SqlRow) {
  return {
    caller_generation_id: asString(row.id), employee_id: asNumber(row.employee_id),
    api_key_id: asNumber(row.api_key_id), host_id: asString(row.host_id),
    state: asString(row.state), row_version: asNumber(row.row_version), created_at: asString(row.created_at),
  };
}

export async function provisionCallerGeneration(
  db: SqlDatabase,
  actor: RouteActor,
  input: { submissionId: string; callerGenerationId: string; employeeId: number; apiKeyId: number; hostId: string },
) {
  assertBoundedId(input.callerGenerationId, "caller_generation_id");
  assertBoundedId(input.hostId, "host_id");
  return adminMutation(db, actor, input.submissionId, "route.caller-generation.provision", {
    caller_generation_id: input.callerGenerationId, employee_id: input.employeeId,
    api_key_id: input.apiKeyId, host_id: input.hostId,
  }, async (tx, createdAt) => {
    first(await tx.query(`SELECT k.id FROM api_keys k JOIN employees e ON e.id = k.employee_id
      WHERE e.id = $1 AND k.id = $2 AND k.revoked_at IS NULL
        AND (k.expires_at IS NULL OR k.expires_at > $3)`, [input.employeeId, input.apiKeyId, createdAt]),
    "caller-credential-not-active", "Active caller API key was not found for the employee");
    let row: SqlRow;
    try {
      row = first(await tx.query<SqlRow>(`INSERT INTO a2a_caller_generations
        (id, employee_id, api_key_id, host_id, state, row_version, created_by_employee_id, created_at,
          revoked_by_employee_id, revoked_at, revoke_reason)
        VALUES ($1, $2, $3, $4, 'active', 1, $5, $6, NULL, NULL, NULL) RETURNING *`, [
        input.callerGenerationId, input.employeeId, input.apiKeyId, input.hostId, actor.id, createdAt,
      ]), "caller-generation-not-created", "Caller generation was not created");
    } catch (error) {
      if (!uniqueViolation(error)) throw error;
      throw new RouteControlError(409, "caller-generation-conflict", "Caller generation already exists");
    }
    await insertAdminAudit(tx, actor.id, "caller-generation.provisioned", "caller_generation", input.callerGenerationId,
      { employee_id: input.employeeId, api_key_id: input.apiKeyId, host_id: input.hostId }, createdAt);
    return { status: 201, body: callerGenerationBody(row) };
  });
}

export async function revokeCallerGeneration(
  db: SqlDatabase,
  actor: RouteActor,
  callerGenerationId: string,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return adminMutation(db, actor, input.submissionId, "route.caller-generation.revoke", {
    caller_generation_id: callerGenerationId, expected_version: input.expectedVersion, reason: input.reason,
  }, async (tx, createdAt) => {
    const rows = await tx.query<SqlRow>(`UPDATE a2a_caller_generations SET state = 'revoked',
      row_version = row_version + 1, revoked_by_employee_id = $1, revoked_at = $2, revoke_reason = $3
      WHERE id = $4 AND state = 'active' AND row_version = $5 RETURNING *`, [
      actor.id, createdAt, input.reason, callerGenerationId, input.expectedVersion,
    ]);
    const row = first(rows, "caller-generation-not-active", "Active caller generation was not found at expected version");
    await insertAdminAudit(tx, actor.id, "caller-generation.revoked", "caller_generation", callerGenerationId,
      { reason: input.reason }, createdAt);
    return { status: 200, body: callerGenerationBody(row) };
  });
}

export async function listCallerGenerations(db: SqlDatabase, afterId: string, limit: number) {
  const rows = await db.query<SqlRow>(`SELECT * FROM a2a_caller_generations
    WHERE id > $1 ORDER BY id LIMIT $2`, [afterId, limit + 1]);
  return { items: rows.slice(0, limit).map(callerGenerationBody), next_after_id: rows.length > limit ? asString(rows[limit]!.id) : null };
}

function healthBody(row: SqlRow) {
  return {
    id: asNumber(row.id), advertised_interface_id: asNumber(row.advertised_interface_id),
    target_id: asNumber(row.target_id), card_registry_id: asNumber(row.card_registry_id),
    interface_url: asString(row.interface_url), reachability: asString(row.reachability),
    reason_code: asString(row.reason_code), evidence_sha256: asString(row.evidence_sha256),
    observed_at: asString(row.observed_at), expires_at: row.expires_at === null ? null : asString(row.expires_at),
  };
}

export async function probeInterfaceHealth(
  db: SqlDatabase,
  actor: RouteActor,
  input: {
    submissionId: string; targetId: number; cardRegistryId: number; interfaceUrl: string;
  },
  dependencies: RouteProbeDependencies = {},
) {
  const interfaceUrl = canonicalInterfaceUrl(input.interfaceUrl);
  const card = first(await db.query<SqlRow>(`SELECT t.state AS target_state, r.state AS card_state,
    d.document_json FROM a2a_discovery_targets t CROSS JOIN a2a_card_registry r
    JOIN a2a_card_documents d ON d.id = r.document_id
    WHERE t.id = $1 AND r.id = $2`, [input.targetId, input.cardRegistryId]),
  "route-subject-not-found", "Target or Agent Card was not found");
  if (asString(card.target_state) !== "active" || asString(card.card_state) !== "trusted") {
    throw new RouteControlError(409, "route-subject-inactive", "Target and Agent Card must be active and trusted");
  }
  const documentJson = asString(card.document_json);
  const document = JSON.parse(documentJson) as Record<string, unknown>;
  const interfaces = document.supportedInterfaces;
  if (!Array.isArray(interfaces) || !interfaces.some((entry) => entry !== null && typeof entry === "object" &&
    (entry as Record<string, unknown>).url === interfaceUrl &&
    (entry as Record<string, unknown>).protocolBinding === "JSONRPC" &&
    (entry as Record<string, unknown>).protocolVersion === "1.0")) {
    throw new RouteControlError(422, "interface-not-advertised", "Interface is not an exact advertised JSONRPC v1.0 interface");
  }
  let reachability: "healthy" | "unreachable";
  let reasonCode: string;
  let evidenceSha256: string;
  try {
    const probe = await probeBoundedHttpsReachability({ url: new URL(interfaceUrl), ...dependencies });
    reachability = "healthy";
    reasonCode = "interface-reachable";
    evidenceSha256 = probe.evidenceSha256;
  } catch (error) {
    reachability = "unreachable";
    reasonCode = error instanceof DiscoveryBoundaryError ? error.code : "connect-rejected";
    evidenceSha256 = sha256(stableJson({ interface_url: interfaceUrl, outcome: reasonCode }));
  }
  return adminMutation(db, actor, input.submissionId, "route.interface-health.observe", {
    target_id: input.targetId, card_registry_id: input.cardRegistryId, interface_url: interfaceUrl,
    probe_profile: "p4-3-public-https-v1",
  }, async (tx, createdAt) => {
    await tx.execute(`INSERT INTO a2a_advertised_interfaces
      (target_id, card_registry_id, interface_url, protocol_binding, protocol_version, auth_scheme, created_at)
      VALUES ($1, $2, $3, 'JSONRPC', '1.0', 'Bearer', $4)
      ON CONFLICT(target_id, card_registry_id, interface_url) DO NOTHING`, [
      input.targetId, input.cardRegistryId, interfaceUrl, createdAt,
    ]);
    const advertised = first(await tx.query<{ id: unknown }>(`SELECT id FROM a2a_advertised_interfaces
      WHERE target_id = $1 AND card_registry_id = $2 AND interface_url = $3${lockSuffix(tx)}`, [
      input.targetId, input.cardRegistryId, interfaceUrl,
    ]), "advertised-interface-not-found", "Advertised interface was not stored");
    const expiresAt = reachability === "healthy"
      ? new Date(Date.parse(createdAt) + 300_000).toISOString()
      : null;
    const row = first(await tx.query<SqlRow>(`INSERT INTO a2a_interface_health_observations
      (advertised_interface_id, target_id, card_registry_id, interface_url, reachability, reason_code, evidence_sha256,
        observed_at, expires_at, observed_by_employee_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`, [
      asNumber(advertised.id), input.targetId, input.cardRegistryId, interfaceUrl, reachability, reasonCode,
      evidenceSha256, createdAt, expiresAt, actor.id,
    ]), "health-not-created", "Interface health observation was not created");
    await insertAdminAudit(tx, actor.id, "interface-health.observed", "interface_health", String(asNumber(row.id)),
      { target_id: input.targetId, card_registry_id: input.cardRegistryId, interface_url: interfaceUrl,
        advertised_interface_id: asNumber(advertised.id), reachability }, createdAt);
    return { status: 201, body: healthBody(row) };
  });
}

export async function listInterfaceHealth(db: SqlDatabase, afterId: number, limit: number) {
  const rows = await db.query<SqlRow>(`SELECT * FROM a2a_interface_health_observations
    WHERE id > $1 ORDER BY id LIMIT $2`, [afterId, limit + 1]);
  return { items: rows.slice(0, limit).map(healthBody), next_after_id: rows.length > limit ? asNumber(rows[limit]!.id) : null };
}

function policyBody(row: SqlRow) {
  return {
    id: asNumber(row.id), target_id: asNumber(row.target_id), card_registry_id: asNumber(row.card_registry_id),
    managed_key_revision_id: asNumber(row.managed_key_revision_id), credential_binding_id: asNumber(row.credential_binding_id),
    caller_generation_id: asString(row.caller_generation_id), host_id: asString(row.host_id),
    operation_class: asString(row.operation_class), interface_url: asString(row.interface_url),
    extension_uri: asString(row.extension_uri), extension_spec_digest_sha256: asString(row.extension_spec_digest_sha256),
    wire_conformance_artifact_id: asString(row.wire_conformance_artifact_id),
    wire_conformance_artifact_digest_sha256: asString(row.wire_conformance_digest_sha256),
    route_policy_version: asNumber(row.policy_version), route_policy_digest_sha256: asString(row.policy_digest_sha256),
    state: asString(row.state), row_version: asNumber(row.row_version), created_at: asString(row.created_at),
  };
}

export async function provisionRoutePolicy(
  db: SqlDatabase,
  actor: RouteActor,
  input: {
    submissionId: string; targetId: number; cardRegistryId: number; managedKeyRevisionId: number;
    credentialBindingId: number; callerGenerationId: string; hostId: string; operationClass: RouteOperationClass;
    interfaceUrl: string; extensionSpecDigestSha256: string; wireConformanceArtifactId: string;
    wireConformanceDigestSha256: string; policyVersion: number;
  },
) {
  const interfaceUrl = canonicalInterfaceUrl(input.interfaceUrl);
  assertBoundedId(input.callerGenerationId, "caller_generation_id");
  assertBoundedId(input.hostId, "host_id");
  assertDigest(input.extensionSpecDigestSha256, "extension_spec_digest_sha256");
  assertBoundedId(input.wireConformanceArtifactId, "wire_conformance_artifact_id");
  assertDigest(input.wireConformanceDigestSha256, "wire_conformance_artifact_digest_sha256");
  const policyIdentity = {
    target_id: input.targetId, card_registry_id: input.cardRegistryId,
    managed_key_revision_id: input.managedKeyRevisionId, credential_binding_id: input.credentialBindingId,
    caller_generation_id: input.callerGenerationId, host_id: input.hostId,
    interface_url: interfaceUrl, extension_uri: EXACT_SEND_REPLAY_EXTENSION_URI,
    extension_spec_digest_sha256: input.extensionSpecDigestSha256,
    wire_conformance_artifact_id: input.wireConformanceArtifactId,
    wire_conformance_digest_sha256: input.wireConformanceDigestSha256, route_policy_version: input.policyVersion,
  };
  const policyDigest = sha256(stableJson(policyIdentity));
  return adminMutation(db, actor, input.submissionId, "route.policy.provision", {
    ...policyIdentity, operation_class: input.operationClass,
  },
    async (tx, createdAt) => {
      const subject = first(await tx.query<SqlRow>(`SELECT
        t.state AS target_state, r.state AS card_state, r.trusted_anchor_id, r.verified_key_id,
        d.document_json, d.document_sha256,
        k.state AS key_state, k.key_id, k.linked_trust_anchor_id, ks.target_id AS key_target_id,
        b.state AS credential_state, b.target_id AS credential_target_id, b.canonical_origin,
        b.scheme_name, cg.state AS caller_state, cg.host_id AS caller_host_id
        FROM a2a_discovery_targets t
        CROSS JOIN a2a_card_registry r JOIN a2a_card_documents d ON d.id = r.document_id
        CROSS JOIN a2a_managed_key_revisions k JOIN a2a_managed_key_sources ks ON ks.id = k.source_id
        CROSS JOIN a2a_credential_bindings b CROSS JOIN a2a_caller_generations cg
        WHERE t.id = $1 AND r.id = $2 AND k.id = $3 AND b.id = $4 AND cg.id = $5`, [
        input.targetId, input.cardRegistryId, input.managedKeyRevisionId, input.credentialBindingId,
        input.callerGenerationId,
      ]), "route-subject-not-found", "One or more route subjects were not found");
      if (
        asString(subject.target_state) !== "active" || asString(subject.card_state) !== "trusted" ||
        asString(subject.key_state) !== "active" || asNumber(subject.key_target_id) !== input.targetId ||
        asNumber(subject.linked_trust_anchor_id) !== asNumber(subject.trusted_anchor_id) ||
        asString(subject.key_id) !== asString(subject.verified_key_id) ||
        asString(subject.credential_state) !== "active" || asNumber(subject.credential_target_id) !== input.targetId ||
        asString(subject.caller_state) !== "active" || asString(subject.caller_host_id) !== input.hostId ||
        asString(subject.canonical_origin) !== new URL(interfaceUrl).origin
      ) {
        throw new RouteControlError(409, "route-subject-ineligible", "Route subjects are not exactly active and bound");
      }
      const documentJson = asString(subject.document_json);
      if (!hasExactWireInterface(documentJson, interfaceUrl, asString(subject.scheme_name))) {
        throw new RouteControlError(422, "wire-contract-ineligible", "Agent Card lacks the exact JSONRPC v1.0 Bearer interface");
      }
      if (!exactExtension(documentJson, input.extensionSpecDigestSha256)) {
        throw new RouteControlError(422, "extension-contract-ineligible", "Agent Card lacks the exact pinned replay extension");
      }
      let row: SqlRow;
      try {
        row = first(await tx.query<SqlRow>(`INSERT INTO a2a_route_policies
          (target_id, card_registry_id, managed_key_revision_id, credential_binding_id,
            caller_generation_id, host_id, operation_class, interface_url, extension_uri,
            extension_spec_digest_sha256, wire_conformance_artifact_id,
            wire_conformance_digest_sha256, policy_version,
            policy_digest_sha256, state, row_version, created_by_employee_id, created_at,
            revoked_by_employee_id, revoked_at, revoke_reason)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
            'active', 1, $15, $16, NULL, NULL, NULL) RETURNING *`, [
          input.targetId, input.cardRegistryId, input.managedKeyRevisionId, input.credentialBindingId,
          input.callerGenerationId, input.hostId, input.operationClass, interfaceUrl,
          EXACT_SEND_REPLAY_EXTENSION_URI, input.extensionSpecDigestSha256,
          input.wireConformanceArtifactId, input.wireConformanceDigestSha256,
          input.policyVersion, policyDigest, actor.id, createdAt,
        ]), "route-policy-not-created", "Route policy was not created");
      } catch (error) {
        if (!uniqueViolation(error)) throw error;
        throw new RouteControlError(409, "route-policy-conflict", "Route policy already exists");
      }
      await insertAdminAudit(tx, actor.id, "route-policy.provisioned", "route_policy", String(asNumber(row.id)),
        { ...policyIdentity, operation_class: input.operationClass, route_policy_digest_sha256: policyDigest }, createdAt);
      return { status: 201, body: policyBody(row) };
    });
}

export async function revokeRoutePolicy(
  db: SqlDatabase,
  actor: RouteActor,
  policyId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return adminMutation(db, actor, input.submissionId, "route.policy.revoke", {
    route_policy_id: policyId, expected_version: input.expectedVersion, reason: input.reason,
  }, async (tx, createdAt) => {
    const row = first(await tx.query<SqlRow>(`UPDATE a2a_route_policies SET state = 'revoked',
      row_version = row_version + 1, revoked_by_employee_id = $1, revoked_at = $2, revoke_reason = $3
      WHERE id = $4 AND state = 'active' AND row_version = $5 RETURNING *`, [
      actor.id, createdAt, input.reason, policyId, input.expectedVersion,
    ]), "route-policy-not-active", "Active route policy was not found at expected version");
    await insertAdminAudit(tx, actor.id, "route-policy.revoked", "route_policy", String(policyId),
      { reason: input.reason }, createdAt);
    return { status: 200, body: policyBody(row) };
  });
}

export async function listRoutePolicies(db: SqlDatabase, afterId: number, limit: number) {
  const rows = await db.query<SqlRow>(`SELECT * FROM a2a_route_policies WHERE id > $1 ORDER BY id LIMIT $2`,
    [afterId, limit + 1]);
  return { items: rows.slice(0, limit).map(policyBody), next_after_id: rows.length > limit ? asNumber(rows[limit]!.id) : null };
}

export interface RouteResolveInput {
  readonly operationId: string;
  readonly attemptId: string;
  readonly operationKind: RouteOperationClass;
  readonly a2aMethod: "SendMessage" | "GetTask" | "CancelTask";
  readonly targetAgentId: number;
  readonly interfaceUrl: string;
  readonly agentCardDigestSha256: string;
  readonly trustKeyId: number;
  readonly credentialBindingId: number;
  readonly callerGenerationId: string;
  readonly routePolicyVersion: number;
  readonly routePolicyDigestSha256: string;
  readonly extensionUri: string;
  readonly extensionSpecDigestSha256: string;
  readonly intendedCredentialRevisionId: number;
  readonly predecessorCredentialRevisionId?: number;
}

export interface RouteResolveDependencies {
  /** Test-only deterministic race seam; production routes never provide it. */
  readonly afterCandidateRead?: (tx: SqlDatabase, candidatePolicyId: number) => Promise<void>;
  /** Test-only signal immediately before the potentially blocking policy/interface lock. */
  readonly beforeEligibilityLockWait?: () => Promise<void>;
  /** Test-only seam representing completion of a blocking eligibility-lock acquisition. */
  readonly afterEligibilityLockWait?: () => Promise<void>;
  /** Test-only clock used to prove that an expired attempt cannot mint a replacement snapshot. */
  readonly now?: () => Date;
}

export async function resolveRouteSnapshot(
  db: SqlDatabase,
  actor: RouteActor,
  input: RouteResolveInput,
  dependencies: RouteResolveDependencies = {},
) {
  const interfaceUrl = canonicalInterfaceUrl(input.interfaceUrl);
  assertBoundedId(input.operationId, "operation_id");
  assertBoundedId(input.attemptId, "attempt_id");
  assertBoundedId(input.callerGenerationId, "caller_generation_id");
  assertDigest(input.agentCardDigestSha256, "agent_card_digest_sha256");
  assertDigest(input.routePolicyDigestSha256, "route_policy_digest_sha256");
  assertDigest(input.extensionSpecDigestSha256, "extension_spec_digest_sha256");
  if (input.extensionUri !== EXACT_SEND_REPLAY_EXTENSION_URI) {
    throw new RouteControlError(422, "extension-uri-invalid", "extension_uri is not the locked LVIS extension");
  }
  const expectedMethod = input.operationKind === "get_task"
    ? "GetTask"
    : input.operationKind === "cancel_task"
      ? "CancelTask"
      : "SendMessage";
  if (input.a2aMethod !== expectedMethod) {
    throw new RouteControlError(422, "operation-method-mismatch", "operation_kind and a2a_method do not match");
  }
  if (
    (input.operationKind === "exact_initial_send_replay" && input.predecessorCredentialRevisionId === undefined) ||
    (input.operationKind !== "exact_initial_send_replay" && input.predecessorCredentialRevisionId !== undefined)
  ) {
    rejectPredecessor();
  }
  const requestWire = {
    operation_id: input.operationId, attempt_id: input.attemptId,
    operation_kind: input.operationKind, a2a_method: input.a2aMethod,
    target_agent_id: input.targetAgentId,
    interface_url: interfaceUrl, agent_card_digest_sha256: input.agentCardDigestSha256,
    trust_key_id: input.trustKeyId, credential_binding_id: input.credentialBindingId,
    caller_generation_id: input.callerGenerationId, route_policy_version: input.routePolicyVersion,
    route_policy_digest_sha256: input.routePolicyDigestSha256,
    extension_uri: input.extensionUri,
    extension_spec_digest_sha256: input.extensionSpecDigestSha256,
    intended_credential_revision_id: input.intendedCredentialRevisionId,
    ...(input.predecessorCredentialRevisionId === undefined
      ? {}
      : { predecessor_credential_revision_id: input.predecessorCredentialRevisionId }),
  };
  const requestHash = sha256(stableJson(requestWire));
  return db.transaction(async (tx) => {
    if (tx.dialect === "postgres") {
      await tx.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0)) AS locked`, [
        stableJson([input.operationId]),
      ]);
    }
    const prior = await tx.query<SqlRow>(`SELECT actor_id, actor_api_key_id, request_sha256, response_json
      FROM a2a_route_snapshot_issuance_audit
      WHERE operation_id = $1 AND attempt_id = $2${lockSuffix(tx)}`, [input.operationId, input.attemptId]);
    if (prior.length > 0) {
      const replay = prior[0]!;
      if (
        asNumber(replay.actor_id) !== actor.id || asNumber(replay.actor_api_key_id) !== actor.apiKeyId ||
        asString(replay.request_sha256) !== requestHash
      ) {
        throw new RouteControlError(
          409,
          "route-attempt-conflict",
          "operation_id and attempt_id were already used for a different route request",
        );
      }
      return JSON.parse(asString(replay.response_json)) as Record<string, unknown>;
    }
    let predecessor: SqlRow | undefined;
    if (input.operationKind === "exact_initial_send_replay") {
      const predecessorRows = await tx.query<SqlRow>(`SELECT *
        FROM a2a_route_snapshot_issuance_audit
        WHERE actor_id = $1 AND actor_api_key_id = $2 AND caller_generation_id = $3
          AND operation_id = $4
        ORDER BY issuance_sequence DESC LIMIT 1${tx.dialect === "postgres" ? " FOR SHARE" : ""}`, [
        actor.id, actor.apiKeyId, input.callerGenerationId, input.operationId,
      ]);
      predecessor = predecessorRows[0];
      if (
        predecessor === undefined ||
        (asString(predecessor.operation_kind) !== "initial_send" &&
          asString(predecessor.operation_kind) !== "exact_initial_send_replay") ||
        asString(predecessor.a2a_method) !== "SendMessage" ||
        asNumber(predecessor.target_agent_id) !== input.targetAgentId ||
        asString(predecessor.interface_url) !== interfaceUrl ||
        asString(predecessor.agent_card_digest_sha256) !== input.agentCardDigestSha256 ||
        asNumber(predecessor.trust_key_id) !== input.trustKeyId ||
        asNumber(predecessor.credential_binding_id) !== input.credentialBindingId ||
        asNumber(predecessor.route_policy_version) !== input.routePolicyVersion ||
        asString(predecessor.route_policy_digest_sha256) !== input.routePolicyDigestSha256 ||
        asString(predecessor.extension_uri) !== input.extensionUri ||
        asString(predecessor.extension_spec_digest_sha256) !== input.extensionSpecDigestSha256 ||
        asNumber(predecessor.credential_revision_id) !== input.predecessorCredentialRevisionId
      ) {
        rejectPredecessor();
      }
    }
    const candidate = await tx.query<{ id: unknown }>(`SELECT id FROM a2a_route_policies
      WHERE state = 'active' AND operation_class = $1 AND target_id = $2 AND interface_url = $3
        AND caller_generation_id = $4 AND policy_version = $5 AND policy_digest_sha256 = $6
        AND extension_spec_digest_sha256 = $7`, [
      input.operationKind, input.targetAgentId, interfaceUrl, input.callerGenerationId,
      input.routePolicyVersion, input.routePolicyDigestSha256, input.extensionSpecDigestSha256,
    ]);
    if (candidate.length !== 1) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    await dependencies.afterCandidateRead?.(tx, asNumber(candidate[0]!.id));
    const eligibilityLock = tx.dialect === "postgres"
      ? " FOR SHARE OF p, t, r, k, ks, b, cr, ar, cg, ak, ai"
      : "";
    const linearizationLock = tx.dialect === "postgres" ? " FOR SHARE OF p, ai" : "";
    await dependencies.beforeEligibilityLockWait?.();
    const serialized = await tx.query<{ id: unknown }>(`SELECT ai.id FROM a2a_route_policies p
      JOIN a2a_advertised_interfaces ai ON ai.target_id = p.target_id
        AND ai.card_registry_id = p.card_registry_id AND ai.interface_url = p.interface_url
      WHERE p.state = 'active' AND p.operation_class = $1 AND p.target_id = $2
        AND p.interface_url = $3 AND p.caller_generation_id = $4 AND p.policy_version = $5
        AND p.policy_digest_sha256 = $6 AND p.extension_spec_digest_sha256 = $7${linearizationLock}`, [
      input.operationKind, input.targetAgentId, interfaceUrl, input.callerGenerationId,
      input.routePolicyVersion, input.routePolicyDigestSha256, input.extensionSpecDigestSha256,
    ]);
    if (serialized.length !== 1) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    const rows = await tx.query<SqlRow>(`SELECT
      p.*, t.id AS resolved_target_id, d.document_sha256, d.document_json,
      r.trusted_anchor_id, r.verified_key_id,
      k.key_id, k.linked_trust_anchor_id, ks.target_id AS key_target_id,
      b.canonical_origin, b.scheme_name, b.active_revision_id,
      cr.id AS credential_revision_id, cr.row_version AS credential_version,
      cr.provider, cr.external_version,
      cg.employee_id AS caller_employee_id, cg.host_id AS caller_host_id,
      ak.revoked_at AS caller_key_revoked_at, ak.expires_at AS caller_key_expires_at,
      ai.id AS advertised_interface_id
      FROM a2a_route_policies p
      JOIN a2a_discovery_targets t ON t.id = p.target_id AND t.state = 'active'
      JOIN a2a_card_registry r ON r.id = p.card_registry_id AND r.state = 'trusted'
      JOIN a2a_card_documents d ON d.id = r.document_id
      JOIN a2a_managed_key_revisions k ON k.id = p.managed_key_revision_id AND k.state = 'active'
      JOIN a2a_managed_key_sources ks ON ks.id = k.source_id AND ks.target_id = p.target_id AND ks.state = 'active'
      JOIN a2a_credential_bindings b ON b.id = p.credential_binding_id AND b.target_id = p.target_id
        AND b.state = 'active'
      JOIN a2a_credential_revisions cr ON cr.id = b.active_revision_id AND cr.binding_id = b.id
        AND cr.state = 'active'
      JOIN a2a_credential_active_revisions ar ON ar.binding_id = b.id AND ar.revision_id = cr.id
      JOIN a2a_caller_generations cg ON cg.id = p.caller_generation_id AND cg.state = 'active'
      JOIN api_keys ak ON ak.id = cg.api_key_id AND ak.employee_id = cg.employee_id
      JOIN a2a_advertised_interfaces ai ON ai.target_id = p.target_id
        AND ai.card_registry_id = p.card_registry_id AND ai.interface_url = p.interface_url
      WHERE p.state = 'active' AND p.operation_class = $1
        AND p.target_id = $2 AND p.interface_url = $3
        AND d.document_sha256 = $4 AND k.id = $5 AND p.credential_binding_id = $6
        AND p.caller_generation_id = $7 AND p.policy_version = $8 AND p.policy_digest_sha256 = $9
        AND p.extension_spec_digest_sha256 = $10
        AND cg.employee_id = $11 AND cg.api_key_id = $12 AND cg.host_id = p.host_id
        AND k.linked_trust_anchor_id = r.trusted_anchor_id AND k.key_id = r.verified_key_id${eligibilityLock}`, [
      input.operationKind, input.targetAgentId, interfaceUrl,
      input.agentCardDigestSha256, input.trustKeyId, input.credentialBindingId,
      input.callerGenerationId, input.routePolicyVersion, input.routePolicyDigestSha256,
      input.extensionSpecDigestSha256, actor.id, actor.apiKeyId,
    ]);
    if (rows.length !== 1) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    const row = rows[0]!;
    const healthRows = await tx.query<SqlRow>(`SELECT * FROM a2a_interface_health_observations
      WHERE advertised_interface_id = $1 ORDER BY id DESC LIMIT 1${tx.dialect === "postgres" ? " FOR SHARE" : ""}`, [
      asNumber(row.advertised_interface_id),
    ]);
    const health = healthRows[0];
    if (health === undefined) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    await dependencies.afterEligibilityLockWait?.();
    const now = dependencies.now?.() ?? new Date();
    const nowIso = now.toISOString();
    const callerKeyExpiresAt = row.caller_key_expires_at === null
      ? null
      : Date.parse(asString(row.caller_key_expires_at));
    const healthExpiresAt = health.expires_at === null
      ? Number.NaN
      : Date.parse(asString(health.expires_at));
    if (
      row.caller_key_revoked_at !== null ||
      callerKeyExpiresAt !== null && (!Number.isFinite(callerKeyExpiresAt) || callerKeyExpiresAt <= now.getTime()) ||
      asString(health.reachability) !== "healthy" ||
      !Number.isFinite(healthExpiresAt) || healthExpiresAt <= now.getTime()
    ) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    if (
      predecessor !== undefined &&
      (asString(predecessor.wire_conformance_artifact_id) !== asString(row.wire_conformance_artifact_id) ||
        asString(predecessor.wire_conformance_digest_sha256) !== asString(row.wire_conformance_digest_sha256))
    ) {
      rejectPredecessor();
    }
    if (asNumber(row.credential_revision_id) !== input.intendedCredentialRevisionId) {
      throw new RouteControlError(
        409,
        "intended-credential-revision-mismatch",
        "The intended credential revision is not active",
      );
    }
    const documentJson = asString(row.document_json);
    if (
      asString(row.canonical_origin) !== new URL(interfaceUrl).origin ||
      !hasExactWireInterface(documentJson, interfaceUrl, asString(row.scheme_name)) ||
      !exactExtension(documentJson, input.extensionSpecDigestSha256)
    ) {
      throw new RouteControlError(403, "route-ineligible", "The exact route is not currently eligible");
    }
    const snapshotId = `rs_${randomUUID()}`;
    const issuedAt = nowIso;
    const expiresAt = new Date(now.getTime() + SNAPSHOT_TTL_MS).toISOString();
    const response = {
      snapshot_id: snapshotId,
      operation_id: input.operationId,
      attempt_id: input.attemptId,
      operation_kind: input.operationKind,
      a2a_method: input.a2aMethod,
      issued_at: issuedAt,
      expires_at: expiresAt,
      target_agent_id: input.targetAgentId,
      interface_url: interfaceUrl,
      agent_card_digest_sha256: input.agentCardDigestSha256,
      trust_key_id: input.trustKeyId,
      credential_binding_id: input.credentialBindingId,
      credential_revision_id: input.intendedCredentialRevisionId,
      caller_generation_id: input.callerGenerationId,
      route_policy_version: input.routePolicyVersion,
      route_policy_digest_sha256: input.routePolicyDigestSha256,
      extension_uri: input.extensionUri,
      extension_spec_digest_sha256: input.extensionSpecDigestSha256,
      intended_credential_revision_id: input.intendedCredentialRevisionId,
      ...(input.predecessorCredentialRevisionId === undefined
        ? {}
        : { predecessor_credential_revision_id: input.predecessorCredentialRevisionId }),
      credential_revision_version: asNumber(row.credential_version),
      credential_provider: asString(row.provider),
      credential_external_version: asString(row.external_version),
      advertised_interface_id: asNumber(row.advertised_interface_id),
      interface_health_observation_id: asNumber(health.id),
      health_observed_at: asString(health.observed_at),
      health_expires_at: asString(health.expires_at),
      protocol_binding: "JSONRPC" as const,
      protocol_version: "1.0" as const,
      auth_scheme: "Bearer" as const,
      wire_conformance_artifact_id: asString(row.wire_conformance_artifact_id),
      wire_conformance_artifact_digest_sha256: asString(row.wire_conformance_digest_sha256),
    };
    await tx.execute(`INSERT INTO a2a_route_snapshot_issuance_audit
      (snapshot_id, actor_id, actor_api_key_id, request_sha256,
        operation_id, attempt_id, operation_kind, a2a_method,
        target_agent_id, interface_url,
        agent_card_digest_sha256, trust_key_id, credential_binding_id, credential_revision_id,
        intended_credential_revision_id, caller_generation_id, route_policy_version,
        route_policy_digest_sha256, extension_spec_digest_sha256, extension_uri,
        wire_conformance_artifact_id, wire_conformance_digest_sha256,
        predecessor_credential_revision_id,
        health_observation_id, response_json,
        issued_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
        $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)`, [
      snapshotId, actor.id, actor.apiKeyId, requestHash, input.operationId, input.attemptId,
      input.operationKind, input.a2aMethod, input.targetAgentId, interfaceUrl,
      input.agentCardDigestSha256, input.trustKeyId, input.credentialBindingId,
      input.intendedCredentialRevisionId, input.intendedCredentialRevisionId,
      input.callerGenerationId, input.routePolicyVersion,
      input.routePolicyDigestSha256, input.extensionSpecDigestSha256,
      input.extensionUri, asString(row.wire_conformance_artifact_id),
      asString(row.wire_conformance_digest_sha256),
      input.predecessorCredentialRevisionId ?? null,
      asNumber(health.id), stableJson(response), issuedAt, expiresAt,
    ]);
    return response;
  });
}
