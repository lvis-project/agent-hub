import { createHash, createHmac, randomUUID } from "node:crypto";
import { asBuffer, asNumber, asString, type SqlDatabase, type SqlRow } from "../db.js";
import {
  createTrustAnchorInTransaction,
  importAgentCard,
  revokeTrustAnchorInTransaction,
  type RegistryActor,
} from "./agent-card-store.js";
import type { AgentCardSignatureAlgorithm } from "./agent-card-registry.js";
import { canonicalizeDiscoveryDomain, exactAgentCardUrl, type DiscoveryFailureCode } from "./discovery-egress.js";
import type { ObservedJwksKey } from "./jwks.js";

const SECRET_REFERENCE = /^[a-z][a-z0-9+.-]*:\/\/[^\s\u0000-\u001f\u007f-\u009f]{1,992}$/u;
const SCHEME_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u;
const CREDENTIAL_PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/u;
const CREDENTIAL_EXTERNAL_VERSION = /^[^\s\u0000-\u001f\u007f-\u009f]{1,256}$/u;

export class DiscoveryStoreError extends Error {
  constructor(readonly statusCode: number, readonly code: string, message: string) {
    super(message);
    this.name = "DiscoveryStoreError";
  }
}

export interface DiscoveryActor extends RegistryActor {}

export interface OperationClaim {
  readonly operationId: number;
  readonly submissionId: string;
  readonly targetId: number;
  readonly canonicalDomain: string;
  readonly cardUrl: string;
  readonly requestedByEmployeeId: number;
  readonly executedByPrincipalId: number;
  readonly fenceSequence: number;
  readonly leaseToken: string;
  readonly startedAt: string;
}

export interface CachedDiscoveryDocument {
  readonly documentId: number;
  readonly kind: "agent-card" | "jwks";
  readonly sourceUrl: string;
  readonly bodySha256: string;
  readonly bodyBytes: Buffer;
  readonly etag: string | null;
  readonly lastModified: string | null;
  readonly cacheExpiresAt: string;
}

export interface RevalidationClaimResult {
  readonly replay: { readonly status: number; readonly body: unknown } | null;
  readonly claim: OperationClaim | null;
}

type MutationResult<T> = { readonly status: number; readonly body: T };

function optionalString(value: unknown): string | null {
  return value === null || value === undefined ? null : asString(value);
}

function optionalNumber(value: unknown): number | null {
  return value === null || value === undefined ? null : asNumber(value);
}

function lockSuffix(db: SqlDatabase): string {
  return db.dialect === "postgres" ? " FOR UPDATE" : "";
}

function first<T>(rows: T[], code: string, message: string): T {
  const value = rows[0];
  if (value === undefined) throw new DiscoveryStoreError(404, code, message);
  return value;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value !== "object") throw new Error("Unsupported stable JSON value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

async function claimSharedSubmission<T>(
  tx: SqlDatabase,
  input: {
    actorId: number;
    submissionId: string;
    operation: string;
    requestSha256: string;
    createdAt: string;
  },
): Promise<{ inserted: boolean; replay: MutationResult<T> | null }> {
  const inserted = await tx.query<{ actor_id: unknown }>(`INSERT INTO a2a_mutation_submissions
    (actor_id, submission_id, operation, request_sha256, response_json, response_status, created_at)
    VALUES ($1, $2, $3, $4, NULL, NULL, $5)
    ON CONFLICT(actor_id, submission_id) DO NOTHING RETURNING actor_id`, [
    input.actorId, input.submissionId, input.operation, input.requestSha256, input.createdAt,
  ]);
  if (inserted.length === 1) return { inserted: true, replay: null };
  const row = first(await tx.query<SqlRow>(`SELECT operation, request_sha256, response_json, response_status
    FROM a2a_mutation_submissions
    WHERE actor_id = $1 AND submission_id = $2${lockSuffix(tx)}`, [input.actorId, input.submissionId]),
  "submission-not-found", "Shared submission reservation is unavailable");
  if (asString(row.operation) !== input.operation || asString(row.request_sha256) !== input.requestSha256) {
    throw new DiscoveryStoreError(409, "submission-mismatch", "submission_id was already used for a different operation");
  }
  if (row.response_json === null || row.response_json === undefined || row.response_status === null || row.response_status === undefined) {
    return { inserted: false, replay: null };
  }
  return {
    inserted: false,
    replay: { status: asNumber(row.response_status), body: JSON.parse(asString(row.response_json)) as T },
  };
}

async function completeSharedSubmission(
  tx: SqlDatabase,
  input: { actorId: number; submissionId: string; status: number; body: unknown },
): Promise<void> {
  const completed = await tx.query<{ actor_id: unknown }>(`UPDATE a2a_mutation_submissions
    SET response_json = $1, response_status = $2
    WHERE actor_id = $3 AND submission_id = $4 AND response_json IS NULL AND response_status IS NULL
    RETURNING actor_id`, [stableJson(input.body), input.status, input.actorId, input.submissionId]);
  if (completed.length !== 1) {
    throw new DiscoveryStoreError(409, "operation-fenced", "Shared submission response is already terminal");
  }
}

function uniqueViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = "code" in error ? String(error.code) : "";
  if (code === "23505") return true;
  return code === "ERR_SQLITE_ERROR" && error instanceof Error && /^UNIQUE constraint failed:/u.test(error.message);
}

async function employeePrincipal(tx: SqlDatabase, employeeId: number, createdAt: string, lock = false): Promise<number> {
  await tx.query(`INSERT INTO a2a_principals (kind, employee_id, system_name, created_at)
    VALUES ('employee', $1, NULL, $2) ON CONFLICT(employee_id) DO NOTHING RETURNING id`, [employeeId, createdAt]);
  const row = first(await tx.query<{ id: unknown }>(`SELECT id FROM a2a_principals
    WHERE kind = 'employee' AND employee_id = $1${lock ? lockSuffix(tx) : ""}`, [employeeId]),
  "principal-not-found", "Employee principal is unavailable");
  return asNumber(row.id);
}

async function systemPrincipal(tx: SqlDatabase): Promise<number> {
  return asNumber(first(await tx.query<{ id: unknown }>(`SELECT id FROM a2a_principals
    WHERE kind = 'system' AND system_name = 'g003-discovery'${lockSuffix(tx)}`),
  "principal-not-found", "System recovery principal is unavailable").id);
}

async function insertAudit(
  tx: SqlDatabase,
  input: {
    operationId: number;
    requestedByEmployeeId: number;
    executedByPrincipalId: number;
    action: string;
    targetKind: string;
    targetId: string;
    beforeState: string | null;
    afterState: string | null;
    reason: string | null;
    metadata: Record<string, unknown>;
    createdAt: string;
  },
): Promise<void> {
  await tx.execute(`INSERT INTO a2a_g003_audit
    (operation_id, requested_by_employee_id, executed_by_principal_id, action, target_kind, target_id,
      before_state, after_state, reason, metadata_json, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, [
    input.operationId, input.requestedByEmployeeId, input.executedByPrincipalId, input.action,
    input.targetKind, input.targetId, input.beforeState, input.afterState, input.reason,
    stableJson(input.metadata), input.createdAt,
  ]);
}

async function runAdminMutation<T>(
  db: SqlDatabase,
  actor: DiscoveryActor,
  input: { submissionId: string; operation: string; request: unknown },
  work: (context: {
    tx: SqlDatabase;
    operationId: number;
    principalId: number;
    createdAt: string;
  }) => Promise<MutationResult<T>>,
): Promise<MutationResult<T>> {
  const requestSha256 = sha256(stableJson({ operation: input.operation, request: input.request }));
  const claim = await db.transaction(async (tx) => {
    const createdAt = new Date().toISOString();
    const shared = await claimSharedSubmission<T>(tx, {
      actorId: actor.id, submissionId: input.submissionId, operation: input.operation,
      requestSha256, createdAt,
    });
    if (shared.replay !== null) return { replay: shared.replay, context: null };
    if (!shared.inserted) {
      throw new DiscoveryStoreError(409, "submission-in-progress", "The matching operation is still running");
    }

    const principalId = await employeePrincipal(tx, actor.id, createdAt, true);
    const inserted = await tx.query<{ id: unknown }>(`INSERT INTO a2a_admin_operations
      (requested_by_employee_id, executed_by_principal_id, target_id, submission_id, operation_kind, semantic_request_hash,
        state, response_status, response_json, lease_token, fence_sequence, lease_expires_at, started_at, completed_at)
      VALUES ($1, $2, NULL, $3, $4, $5, 'running', NULL, NULL, NULL, NULL, NULL, $6, NULL)
      RETURNING id`, [
      actor.id, principalId, input.submissionId, input.operation, requestSha256, createdAt,
    ]);
    const operation = inserted[0];
    if (operation === undefined) throw new Error("Admin operation was not created");
    return { replay: null, context: { operationId: asNumber(operation.id), principalId, createdAt } };
  });
  if (claim.replay !== null) return claim.replay;
  const context = claim.context;
  if (context === null) throw new Error("Admin operation claim was not returned");

  try {
    return await db.transaction(async (tx) => {
      const operation = first(await tx.query<SqlRow>(`SELECT state, executed_by_principal_id
        FROM a2a_admin_operations WHERE id = $1${lockSuffix(tx)}`, [context.operationId]),
      "operation-not-found", "Operation not found");
      if (asString(operation.state) !== "running" || asNumber(operation.executed_by_principal_id) !== context.principalId) {
        throw new DiscoveryStoreError(409, "operation-fenced", "Operation is no longer owned by this execution");
      }
      const result = await work({ tx, ...context });
      const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
        SET state = 'succeeded', response_status = $1, response_json = $2, completed_at = $3
        WHERE id = $4 AND state = 'running' AND executed_by_principal_id = $5 RETURNING id`, [
        result.status, stableJson(result.body), new Date().toISOString(), context.operationId, context.principalId,
      ]);
      if (completed.length !== 1) throw new Error("Operation completion was not recorded exactly once");
      await completeSharedSubmission(tx, {
        actorId: actor.id, submissionId: input.submissionId, status: result.status, body: result.body,
      });
      return result;
    });
  } catch (error) {
    const expected = error instanceof DiscoveryStoreError && [404, 409, 422].includes(error.statusCode);
    const status = expected ? error.statusCode : 500;
    const responseBody = expected
      ? { detail: error.message, code: error.code }
      : { detail: "Operation persistence failed", code: "persistence-failed" };
    try {
      return await db.transaction(async (tx) => {
        const operation = first(await tx.query<SqlRow>(`SELECT * FROM a2a_admin_operations
          WHERE id = $1${lockSuffix(tx)}`, [context.operationId]), "operation-not-found", "Operation not found");
        if (asString(operation.state) !== "running") {
          return operationReplay(operation) as MutationResult<T>;
        }
        const completedAt = new Date().toISOString();
        await insertAudit(tx, {
          operationId: context.operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: context.principalId,
          action: expected ? "operation.rejected" : "operation.persistence-failed",
          targetKind: "operation", targetId: String(context.operationId), beforeState: "running", afterState: "failed",
          reason: responseBody.code, metadata: { operation: input.operation }, createdAt: completedAt,
        });
        const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
          SET state = 'failed', response_status = $1, response_json = $2, completed_at = $3
          WHERE id = $4 AND state = 'running' AND executed_by_principal_id = $5 RETURNING id`, [
          status, stableJson(responseBody), completedAt, context.operationId, context.principalId,
        ]);
        if (completed.length !== 1) throw new Error("Operation failure was not recorded exactly once");
        await completeSharedSubmission(tx, {
          actorId: actor.id, submissionId: input.submissionId, status, body: responseBody,
        });
        return { status, body: responseBody as T };
      });
    } catch {
      throw error;
    }
  }
}

function materializeTarget(row: SqlRow) {
  return {
    id: asNumber(row.id),
    canonical_origin: asString(row.canonical_origin),
    canonical_domain: asString(row.canonical_domain),
    card_url: asString(row.card_url),
    state: asString(row.state),
    row_version: asNumber(row.row_version),
    created_at: asString(row.created_at),
    disabled_at: optionalString(row.disabled_at),
    disable_reason: optionalString(row.disable_reason),
    routable: false as const,
  };
}

function storedTargetIdentity(row: SqlRow): { canonicalDomain: string; cardUrl: string } | null {
  try {
    const canonicalDomain = canonicalizeDiscoveryDomain(asString(row.canonical_domain));
    const canonicalOrigin = `https://${canonicalDomain}`;
    const cardUrl = exactAgentCardUrl(canonicalDomain).href;
    if (
      asString(row.canonical_domain) !== canonicalDomain ||
      asString(row.canonical_origin) !== canonicalOrigin ||
      asString(row.card_url) !== cardUrl
    ) return null;
    return { canonicalDomain, cardUrl };
  } catch {
    return null;
  }
}

export async function createDiscoveryTarget(
  db: SqlDatabase,
  actor: DiscoveryActor,
  input: { submissionId: string; origin: string },
) {
  let parsed: URL;
  try { parsed = new URL(input.origin); } catch { throw new DiscoveryStoreError(422, "target-origin-invalid", "Discovery target origin is invalid"); }
  if (
    parsed.protocol !== "https:" || parsed.port !== "" || parsed.username !== "" || parsed.password !== "" ||
    parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== ""
  ) {
    throw new DiscoveryStoreError(422, "target-origin-invalid", "Discovery target origin is invalid");
  }
  let canonicalDomain: string;
  try { canonicalDomain = canonicalizeDiscoveryDomain(parsed.hostname); }
  catch { throw new DiscoveryStoreError(422, "target-origin-invalid", "Discovery target origin is invalid"); }
  const canonicalOrigin = `https://${canonicalDomain}`;
  const cardUrl = exactAgentCardUrl(canonicalDomain).href;
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId,
    operation: "discovery-target.create",
    request: { canonical_origin: canonicalOrigin },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    let rows: SqlRow[];
    try {
      rows = await tx.query(`INSERT INTO a2a_discovery_targets
        (canonical_origin, canonical_domain, card_url, state, row_version, next_fence_sequence, created_by_employee_id,
          created_by_principal_id, created_at, disabled_by_employee_id, disabled_by_principal_id,
          disabled_at, disable_reason)
        VALUES ($1, $2, $3, 'active', 1, 0, $4, $5, $6, NULL, NULL, NULL, NULL) RETURNING *`, [
        canonicalOrigin, canonicalDomain, cardUrl, actor.id, principalId, createdAt,
      ]);
    } catch (error) {
      if (!uniqueViolation(error)) throw error;
      throw new DiscoveryStoreError(409, "target-conflict", "Discovery target already exists");
    }
    const target = materializeTarget(first(rows, "target-not-created", "Discovery target was not created"));
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [target.id, operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "discovery-target.created", targetKind: "discovery_target", targetId: String(target.id),
      beforeState: null, afterState: "active", reason: null,
      metadata: { canonical_origin: canonicalOrigin, card_url: cardUrl }, createdAt,
    });
    return { status: 201, body: target };
  });
}

export async function listDiscoveryTargets(db: SqlDatabase, input: { afterId: number; limit: number; state?: "active" | "disabled" }) {
  const rows = input.state === undefined
    ? await db.query(`SELECT * FROM a2a_discovery_targets WHERE id > $1 ORDER BY id LIMIT $2`, [input.afterId, input.limit + 1])
    : await db.query(`SELECT * FROM a2a_discovery_targets WHERE state = $1 AND id > $2 ORDER BY id LIMIT $3`, [input.state, input.afterId, input.limit + 1]);
  return { items: rows.slice(0, input.limit).map(materializeTarget), next_after_id: rows.length > input.limit ? asNumber(rows[input.limit]!.id) : null };
}

export async function disableDiscoveryTarget(
  db: SqlDatabase,
  actor: DiscoveryActor,
  targetId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId,
    operation: "discovery-target.disable",
    request: { target_id: targetId, expected_version: input.expectedVersion, reason: input.reason },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const row = first(await tx.query<SqlRow>(`SELECT * FROM a2a_discovery_targets WHERE id = $1${lockSuffix(tx)}`, [targetId]),
    "target-not-found", "Discovery target not found");
    if (asString(row.state) !== "active") throw new DiscoveryStoreError(409, "target-terminal", "Disabled targets are terminal");
    if (asNumber(row.row_version) !== input.expectedVersion) throw new DiscoveryStoreError(409, "stale-version", "Discovery target version is stale");
    const runningDiscovery = await tx.query<{ id: unknown }>(`SELECT id FROM a2a_admin_operations
      WHERE target_id = $1 AND operation_kind = 'discovery.revalidate' AND state = 'running'${lockSuffix(tx)}`, [targetId]);
    if (runningDiscovery.length > 0) {
      throw new DiscoveryStoreError(409, "target-busy", "A running discovery operation must complete or be recovered before disable");
    }
    const updated = first(await tx.query<SqlRow>(`UPDATE a2a_discovery_targets
      SET state = 'disabled', row_version = row_version + 1, disabled_by_employee_id = $1,
        disabled_by_principal_id = $2, disabled_at = $3, disable_reason = $4
      WHERE id = $5 AND state = 'active' AND row_version = $6 RETURNING *`, [
      actor.id, principalId, createdAt, input.reason, targetId, input.expectedVersion,
    ]), "stale-version", "Discovery target changed concurrently");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [targetId, operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "discovery-target.disabled", targetKind: "discovery_target", targetId: String(targetId),
      beforeState: "active", afterState: "disabled", reason: input.reason, metadata: {}, createdAt,
    });
    return { status: 200, body: materializeTarget(updated) };
  });
}

function operationReplay(row: SqlRow): { status: number; body: unknown } {
  return { status: asNumber(row.response_status), body: JSON.parse(asString(row.response_json)) as unknown };
}

async function rejectRevalidationClaim(
  tx: SqlDatabase,
  input: {
    operationId: number;
    requestedByEmployeeId: number;
    submissionId: string;
    executedByPrincipalId: number;
    requestedTargetId: number;
    status: 404 | 409 | 422;
    code: string;
    detail: string;
    completedAt: string;
  },
): Promise<RevalidationClaimResult> {
  const body = {
    target_id: input.requestedTargetId,
    code: input.code,
    detail: input.detail,
    routable: false as const,
    completed_at: input.completedAt,
  };
  await insertAudit(tx, {
    operationId: input.operationId,
    requestedByEmployeeId: input.requestedByEmployeeId,
    executedByPrincipalId: input.executedByPrincipalId,
    action: "discovery.claim-rejected",
    targetKind: "operation",
    targetId: String(input.operationId),
    beforeState: "claiming",
    afterState: "failed",
    reason: input.code,
    metadata: { requested_target_id: input.requestedTargetId },
    createdAt: input.completedAt,
  });
  const terminal = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
    SET state = 'failed', response_status = $1, response_json = $2, completed_at = $3
    WHERE id = $4 AND state = 'claiming' RETURNING id`, [
    input.status, stableJson(body), input.completedAt, input.operationId,
  ]);
  if (terminal.length !== 1) throw new Error("Discovery claim rejection was not recorded exactly once");
  await completeSharedSubmission(tx, {
    actorId: input.requestedByEmployeeId,
    submissionId: input.submissionId,
    status: input.status,
    body,
  });
  return { replay: { status: input.status, body }, claim: null };
}

export async function claimRevalidation(
  db: SqlDatabase,
  actor: DiscoveryActor,
  input: { targetId: number; submissionId: string; expectedVersion: number; nowMs: number },
): Promise<RevalidationClaimResult> {
  const requestSha256 = sha256(stableJson({
    operation: "discovery.revalidate",
    request: { target_id: input.targetId, expected_version: input.expectedVersion },
  }));
  return db.transaction(async (tx) => {
    const startedAt = new Date(input.nowMs).toISOString();
    const replayOrRecoverExisting = async (existing: SqlRow): Promise<RevalidationClaimResult> => {
      if (asString(existing.operation_kind) !== "discovery.revalidate" || asString(existing.semantic_request_hash) !== requestSha256) {
        throw new DiscoveryStoreError(409, "submission-mismatch", "submission_id was already used for a different operation");
      }
      const state = asString(existing.state);
      if (state === "claiming") {
        throw new DiscoveryStoreError(409, "submission-in-progress", "The matching discovery operation is still being claimed");
      }
      if (state !== "running") return { replay: operationReplay(existing), claim: null };
      if (Date.parse(asString(existing.lease_expires_at)) > input.nowMs) {
        throw new DiscoveryStoreError(409, "submission-in-progress", "The matching discovery operation is still running");
      }
      const target = first(await tx.query<SqlRow>(`SELECT * FROM a2a_discovery_targets WHERE id = $1${lockSuffix(tx)}`, [input.targetId]),
      "target-not-found", "Discovery target not found");
      const systemPrincipalId = await systemPrincipal(tx);
      const fence = asNumber(target.next_fence_sequence) + 1;
      const leaseToken = randomUUID();
      const leaseExpiresAt = startedAt;
      const responseBody = {
        target_id: input.targetId,
        outcome: "failed",
        code: "persistence-failed",
        detail: "The prior discovery execution expired before a trustworthy endpoint outcome committed",
        routable: false as const,
        completed_at: startedAt,
      };
      const recovered = await tx.query<SqlRow>(`UPDATE a2a_admin_operations
        SET executed_by_principal_id = $1, lease_token = $2, fence_sequence = $3, lease_expires_at = $4,
          state = 'failed', response_status = 500, response_json = $5, completed_at = $6
        WHERE id = $7 AND state = 'running' AND fence_sequence = $8 RETURNING *`, [
        systemPrincipalId, leaseToken, fence, leaseExpiresAt, stableJson(responseBody), startedAt,
        asNumber(existing.id), asNumber(existing.fence_sequence),
      ]);
      if (recovered.length !== 1) throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation was recovered concurrently");
      await tx.execute("UPDATE a2a_discovery_targets SET next_fence_sequence = $1 WHERE id = $2", [fence, input.targetId]);
      await insertAudit(tx, {
        operationId: asNumber(existing.id), requestedByEmployeeId: actor.id,
        executedByPrincipalId: systemPrincipalId, action: "discovery.persistence-failed",
        targetKind: "discovery_target", targetId: String(input.targetId), beforeState: "running", afterState: "failed",
        reason: "persistence-failed", metadata: { recovered_fence_sequence: fence }, createdAt: startedAt,
      });
      await completeSharedSubmission(tx, {
        actorId: actor.id, submissionId: input.submissionId, status: 500, body: responseBody,
      });
      return { replay: { status: 500, body: responseBody }, claim: null };
    };
    const shared = await claimSharedSubmission<unknown>(tx, {
      actorId: actor.id,
      submissionId: input.submissionId,
      operation: "discovery.revalidate",
      requestSha256,
      createdAt: startedAt,
    });
    if (shared.replay !== null) return { replay: shared.replay, claim: null };
    if (!shared.inserted) {
      const existing = (await tx.query<SqlRow>(`SELECT * FROM a2a_admin_operations
        WHERE requested_by_employee_id = $1 AND submission_id = $2${lockSuffix(tx)}`, [actor.id, input.submissionId]))[0];
      if (existing === undefined) {
        throw new DiscoveryStoreError(409, "submission-in-progress", "The matching shared submission is still running");
      }
      return replayOrRecoverExisting(existing);
    }

    const employeePrincipalId = await employeePrincipal(tx, actor.id, startedAt, true);
    const inserted = await tx.query<{ id: unknown }>(`INSERT INTO a2a_admin_operations
      (requested_by_employee_id, executed_by_principal_id, target_id, submission_id, operation_kind, semantic_request_hash,
        state, response_status, response_json, lease_token, fence_sequence, lease_expires_at, started_at, completed_at)
      VALUES ($1, $2, NULL, $3, 'discovery.revalidate', $4, 'claiming', NULL, NULL, NULL, NULL, NULL, $5, NULL)
      RETURNING id`, [
      actor.id, employeePrincipalId, input.submissionId, requestSha256, startedAt,
    ]);
    const operation = inserted[0];
    if (operation === undefined) throw new Error("Discovery operation was not created");
    const operationId = asNumber(operation.id);
    const target = (await tx.query<SqlRow>(`SELECT * FROM a2a_discovery_targets WHERE id = $1${lockSuffix(tx)}`, [input.targetId]))[0];
    if (target === undefined) {
      return rejectRevalidationClaim(tx, {
        operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        submissionId: input.submissionId,
        requestedTargetId: input.targetId, status: 404, code: "target-not-found",
        detail: "Discovery target not found", completedAt: startedAt,
      });
    }
    const targetIdentity = storedTargetIdentity(target);
    if (targetIdentity === null) {
      return rejectRevalidationClaim(tx, {
        operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        submissionId: input.submissionId,
        requestedTargetId: input.targetId, status: 422, code: "target-invalid",
        detail: "Stored discovery target identity violates the canonical HTTPS contract", completedAt: startedAt,
      });
    }
    if (asString(target.state) !== "active") {
      return rejectRevalidationClaim(tx, {
        operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        submissionId: input.submissionId,
        requestedTargetId: input.targetId, status: 409, code: "target-disabled",
        detail: "Discovery target is disabled", completedAt: startedAt,
      });
    }
    if (asNumber(target.row_version) !== input.expectedVersion) {
      return rejectRevalidationClaim(tx, {
        operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        submissionId: input.submissionId,
        requestedTargetId: input.targetId, status: 409, code: "stale-version",
        detail: "Discovery target version is stale", completedAt: startedAt,
      });
    }
    const running = await tx.query<{ id: unknown }>(`SELECT id FROM a2a_admin_operations
      WHERE target_id = $1 AND operation_kind = 'discovery.revalidate' AND state = 'running'${lockSuffix(tx)}`, [input.targetId]);
    if (running.length > 0) {
      return rejectRevalidationClaim(tx, {
        operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        submissionId: input.submissionId,
        requestedTargetId: input.targetId, status: 409, code: "target-busy",
        detail: "Discovery target already has a running operation", completedAt: startedAt,
      });
    }
    const fence = asNumber(target.next_fence_sequence) + 1;
    const leaseToken = randomUUID();
    const leaseExpiresAt = new Date(input.nowMs + 2 * 60_000).toISOString();
    await tx.execute("UPDATE a2a_discovery_targets SET next_fence_sequence = $1 WHERE id = $2", [fence, input.targetId]);
    const claimed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
      SET state = 'running', target_id = $1, lease_token = $2, fence_sequence = $3, lease_expires_at = $4
      WHERE id = $5 AND state = 'claiming' RETURNING id`, [input.targetId, leaseToken, fence, leaseExpiresAt, operationId]);
    if (claimed.length !== 1) throw new Error("Discovery operation claim was not finalized exactly once");
    return {
      replay: null,
      claim: {
        operationId, submissionId: input.submissionId, targetId: input.targetId,
        canonicalDomain: targetIdentity.canonicalDomain, cardUrl: targetIdentity.cardUrl,
        requestedByEmployeeId: actor.id, executedByPrincipalId: employeePrincipalId,
        fenceSequence: fence, leaseToken, startedAt,
      },
    };
  });
}

export async function loadDiscoveryCache(db: SqlDatabase, targetId: number): Promise<ReadonlyMap<"agent-card" | "jwks", CachedDiscoveryDocument>> {
  const rows = await db.query<SqlRow>(`SELECT c.kind, c.document_id, c.etag, c.last_modified, c.cache_expires_at,
    d.source_url, d.body_sha256, d.body_blob
    FROM a2a_discovery_cache_entries c JOIN a2a_discovery_documents d ON d.id = c.document_id
    WHERE c.target_id = $1 ORDER BY c.kind`, [targetId]);
  const result = new Map<"agent-card" | "jwks", CachedDiscoveryDocument>();
  for (const row of rows) {
    const kind = asString(row.kind);
    if (kind !== "agent-card" && kind !== "jwks") throw new Error("Invalid discovery cache kind");
    result.set(kind, Object.freeze({
      documentId: asNumber(row.document_id), kind, sourceUrl: asString(row.source_url),
      bodySha256: asString(row.body_sha256), bodyBytes: asBuffer(row.body_blob),
      etag: optionalString(row.etag), lastModified: optionalString(row.last_modified),
      cacheExpiresAt: asString(row.cache_expires_at),
    }));
  }
  return result;
}

async function lockCurrentOperation(tx: SqlDatabase, claim: OperationClaim): Promise<void> {
  const operation = first(await tx.query<SqlRow>(`SELECT * FROM a2a_admin_operations WHERE id = $1${lockSuffix(tx)}`, [claim.operationId]),
  "operation-not-found", "Discovery operation not found");
  if (
    asString(operation.state) !== "running" || asString(operation.lease_token) !== claim.leaseToken ||
    asNumber(operation.fence_sequence) !== claim.fenceSequence ||
    asNumber(operation.executed_by_principal_id) !== claim.executedByPrincipalId
  ) {
    throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation is no longer owned by this execution");
  }
}

async function storeDocument(
  tx: SqlDatabase,
  input: { claim: OperationClaim; kind: "agent-card" | "jwks"; sourceUrl: string; bodyBytes: Buffer; bodySha256: string; createdAt: string },
): Promise<number> {
  const row = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_discovery_documents
    (target_id, operation_id, kind, source_url, body_sha256, body_blob, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, [
    input.claim.targetId, input.claim.operationId, input.kind, input.sourceUrl,
    input.bodySha256, input.bodyBytes, input.createdAt,
  ]), "document-not-created", "Discovery document was not stored");
  return asNumber(row.id);
}

async function updateCache(
  tx: SqlDatabase,
  input: {
    claim: OperationClaim;
    kind: "agent-card" | "jwks";
    status: 200 | 304;
    documentId: number | null;
    noStore: boolean;
    etag: string | null;
    lastModified: string | null;
    cacheExpiresAt: string | null;
    updatedAt: string;
  },
): Promise<void> {
  if (input.noStore) {
    await tx.execute("DELETE FROM a2a_discovery_cache_entries WHERE target_id = $1 AND kind = $2", [input.claim.targetId, input.kind]);
    return;
  }
  if (input.documentId === null || input.cacheExpiresAt === null) throw new Error("Reusable discovery cache requires an immutable document");
  const validatorUpdate = input.status === 304
    ? `etag = COALESCE(excluded.etag, a2a_discovery_cache_entries.etag),
      last_modified = COALESCE(excluded.last_modified, a2a_discovery_cache_entries.last_modified),`
    : `etag = excluded.etag,
      last_modified = excluded.last_modified,`;
  await tx.execute(`INSERT INTO a2a_discovery_cache_entries
    (target_id, kind, document_id, etag, last_modified, cache_expires_at, row_version, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, 1, $7)
    ON CONFLICT(target_id, kind) DO UPDATE SET
      document_id = excluded.document_id,
      ${validatorUpdate}
      cache_expires_at = excluded.cache_expires_at,
      row_version = a2a_discovery_cache_entries.row_version + 1,
      updated_at = excluded.updated_at`, [
    input.claim.targetId, input.kind, input.documentId, input.etag, input.lastModified, input.cacheExpiresAt, input.updatedAt,
  ]);
}

export interface SuccessfulDiscoveryDocumentInput {
  readonly status: 200 | 304;
  readonly sourceUrl: string;
  readonly bodyBytes: Buffer;
  readonly bodyValue: unknown;
  readonly bodySha256: string;
  readonly existingDocumentId: number | null;
  readonly noStore: boolean;
  readonly etag: string | null;
  readonly lastModified: string | null;
  readonly cacheExpiresAt: string | null;
  readonly freshnessMs: number;
}

export async function completeDiscoverySuccess(
  db: SqlDatabase,
  actor: DiscoveryActor,
  input: {
    claim: OperationClaim;
    card: SuccessfulDiscoveryDocumentInput;
    jwks: SuccessfulDiscoveryDocumentInput | null;
    observedKeys: readonly ObservedJwksKey[];
    evidenceExpiresAt: string;
    completedAtMs: number;
  },
): Promise<MutationResult<unknown>> {
  return db.transaction(async (tx) => {
    await lockCurrentOperation(tx, input.claim);
    const completedAt = new Date(input.completedAtMs).toISOString();
    const imported = await importAgentCard(tx, actor, {
      submissionId: `g003-discovery-${input.claim.operationId}-${input.claim.fenceSequence}`,
      card: input.card.bodyValue,
      provenance: { kind: "api", source: input.claim.cardUrl, detail: "G003 metadata discovery" },
    });

    let cardDocumentId = input.card.existingDocumentId;
    if (input.card.status === 200 && !input.card.noStore) {
      cardDocumentId = await storeDocument(tx, {
        claim: input.claim, kind: "agent-card", sourceUrl: input.card.sourceUrl,
        bodyBytes: input.card.bodyBytes, bodySha256: input.card.bodySha256, createdAt: completedAt,
      });
    }
    await updateCache(tx, {
      claim: input.claim, kind: "agent-card", documentId: cardDocumentId,
      status: input.card.status,
      noStore: input.card.noStore, etag: input.card.etag, lastModified: input.card.lastModified,
      cacheExpiresAt: input.card.cacheExpiresAt, updatedAt: completedAt,
    });

    let jwksDocumentId = input.jwks?.existingDocumentId ?? null;
    if (input.jwks !== null) {
      if (input.jwks.status === 200 && !input.jwks.noStore) {
        jwksDocumentId = await storeDocument(tx, {
          claim: input.claim, kind: "jwks", sourceUrl: input.jwks.sourceUrl,
          bodyBytes: input.jwks.bodyBytes, bodySha256: input.jwks.bodySha256, createdAt: completedAt,
        });
      }
      await updateCache(tx, {
        claim: input.claim, kind: "jwks", documentId: jwksDocumentId,
        status: input.jwks.status,
        noStore: input.jwks.noStore, etag: input.jwks.etag, lastModified: input.jwks.lastModified,
        cacheExpiresAt: input.jwks.cacheExpiresAt, updatedAt: completedAt,
      });
    }

    const outcome = input.card.status === 304 && (input.jwks === null || input.jwks.status === 304)
      ? "not_modified"
      : "succeeded";
    const attempt = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_discovery_attempts
      (operation_id, target_id, fence_sequence, requested_by_employee_id, executed_by_principal_id,
        outcome, error_code, card_document_id, jwks_document_id,
        card_sha256, jwks_sha256, started_at, completed_at)
      VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, $11, $12) RETURNING id`, [
      input.claim.operationId, input.claim.targetId, input.claim.fenceSequence,
      input.claim.requestedByEmployeeId, input.claim.executedByPrincipalId, outcome,
      cardDocumentId, jwksDocumentId,
      input.card.bodySha256, input.jwks?.bodySha256 ?? null, input.claim.startedAt, completedAt,
    ]), "attempt-not-created", "Discovery attempt was not stored");
    const attemptId = asNumber(attempt.id);

    const keyFindings: Array<{ code: "same-kid-material-changed"; key_id: string; previous_fingerprints: string[]; observed_fingerprint: string }> = [];
    if (input.jwks !== null) {
      const source = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_managed_key_sources
        (target_id, jku_uri, state, row_version, created_at, updated_at)
        VALUES ($1, $2, 'active', 1, $3, $3)
        ON CONFLICT(jku_uri) DO UPDATE SET updated_at = excluded.updated_at RETURNING id`, [
        input.claim.targetId, input.jwks.sourceUrl, completedAt,
      ]), "key-source-not-created", "Managed key source was not stored");
      const sourceId = asNumber(source.id);
      for (const key of input.observedKeys) {
        const changedMaterial = await tx.query<{ key_fingerprint_sha256: unknown }>(`SELECT key_fingerprint_sha256
          FROM a2a_managed_key_revisions
          WHERE source_id = $1 AND key_id = $2 AND key_fingerprint_sha256 <> $3 ORDER BY id`, [
          sourceId, key.keyId, key.fingerprintSha256,
        ]);
        const inserted = await tx.query<{ id: unknown }>(`INSERT INTO a2a_managed_key_revisions
          (source_id, key_id, algorithm, public_key_pem, key_fingerprint_sha256, state, row_version,
            linked_trust_anchor_id, first_seen_attempt_id, last_seen_attempt_id, created_at, updated_at,
            activated_by_employee_id, activated_by_principal_id, activated_at,
            revoked_by_employee_id, revoked_by_principal_id, revoked_at, decision_reason)
          VALUES ($1, $2, $3, $4, $5, 'observed', 1, NULL, $6, $6, $7, $7,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL)
          ON CONFLICT(source_id, key_id, key_fingerprint_sha256) DO NOTHING RETURNING id`, [
          sourceId, key.keyId, key.algorithm, key.publicKeyPem, key.fingerprintSha256, attemptId, completedAt,
        ]);
        if (inserted.length === 0) {
          await tx.execute(`UPDATE a2a_managed_key_revisions SET last_seen_attempt_id = $1, updated_at = $2
            WHERE source_id = $3 AND key_id = $4 AND key_fingerprint_sha256 = $5`, [
            attemptId, completedAt, sourceId, key.keyId, key.fingerprintSha256,
          ]);
        } else if (changedMaterial.length > 0) {
          const finding = {
            code: "same-kid-material-changed" as const,
            key_id: key.keyId,
            previous_fingerprints: changedMaterial.map((row) => asString(row.key_fingerprint_sha256)),
            observed_fingerprint: key.fingerprintSha256,
          };
          keyFindings.push(finding);
          await insertAudit(tx, {
            operationId: input.claim.operationId, requestedByEmployeeId: input.claim.requestedByEmployeeId,
            executedByPrincipalId: input.claim.executedByPrincipalId, action: "managed-key.material-changed",
            targetKind: "managed_key_source", targetId: String(sourceId), beforeState: "observed", afterState: "observed",
            reason: "same-kid-material-changed", metadata: finding, createdAt: completedAt,
          });
        }
      }
    }

    await tx.execute(`INSERT INTO a2a_discovery_health
      (target_id, attempt_id, fence_sequence, metadata_health, reason_code, evidence_expires_at, observed_at)
      VALUES ($1, $2, $3, 'healthy', $4, $5, $6)`, [
      input.claim.targetId, attemptId, input.claim.fenceSequence,
      outcome === "not_modified" ? "discovery-not-modified" : "discovery-succeeded",
      input.evidenceExpiresAt, completedAt,
    ]);
    const responseBody = {
      attempt_id: attemptId,
      target_id: input.claim.targetId,
      outcome,
      card_sha256: input.card.bodySha256,
      jwks_sha256: input.jwks?.bodySha256 ?? null,
      key_findings: keyFindings,
      imported: imported.body,
      metadata_health: "healthy",
      routable: false as const,
      completed_at: completedAt,
    };
    await insertAudit(tx, {
      operationId: input.claim.operationId, requestedByEmployeeId: input.claim.requestedByEmployeeId,
      executedByPrincipalId: input.claim.executedByPrincipalId, action: "discovery.completed",
      targetKind: "discovery_target", targetId: String(input.claim.targetId), beforeState: null,
      afterState: "healthy", reason: null,
      metadata: { attempt_id: attemptId, outcome, card_sha256: input.card.bodySha256, jwks_sha256: input.jwks?.bodySha256 ?? null },
      createdAt: completedAt,
    });
    const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
      SET state = 'succeeded', response_status = 200, response_json = $1, completed_at = $2
      WHERE id = $3 AND state = 'running' AND lease_token = $4 AND fence_sequence = $5 RETURNING id`, [
      stableJson(responseBody), completedAt, input.claim.operationId, input.claim.leaseToken, input.claim.fenceSequence,
    ]);
    if (completed.length !== 1) throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation was fenced during commit");
    await completeSharedSubmission(tx, {
      actorId: input.claim.requestedByEmployeeId,
      submissionId: input.claim.submissionId,
      status: 200,
      body: responseBody,
    });
    return { status: 200, body: responseBody };
  });
}

function failureHealth(errorCode: DiscoveryFailureCode): "invalid" | "unreachable" {
  return [
    "dns-rejected", "connect-rejected", "tls-rejected", "redirect-rejected", "http-rejected", "timeout",
  ].includes(errorCode)
    ? "unreachable"
    : "invalid";
}

export async function completeDiscoveryFailure(
  db: SqlDatabase,
  input: { claim: OperationClaim; errorCode: DiscoveryFailureCode; completedAtMs: number },
): Promise<MutationResult<unknown>> {
  return db.transaction(async (tx) => {
    await lockCurrentOperation(tx, input.claim);
    const completedAt = new Date(input.completedAtMs).toISOString();
    const attempt = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_discovery_attempts
      (operation_id, target_id, fence_sequence, requested_by_employee_id, executed_by_principal_id,
        outcome, error_code, card_document_id, jwks_document_id,
        card_sha256, jwks_sha256, started_at, completed_at)
      VALUES ($1, $2, $3, $4, $5, 'failed', $6, NULL, NULL, NULL, NULL, $7, $8) RETURNING id`, [
      input.claim.operationId, input.claim.targetId, input.claim.fenceSequence,
      input.claim.requestedByEmployeeId, input.claim.executedByPrincipalId,
      input.errorCode, input.claim.startedAt, completedAt,
    ]), "attempt-not-created", "Discovery failure was not stored");
    const attemptId = asNumber(attempt.id);
    const metadataHealth = failureHealth(input.errorCode);
    await tx.execute(`INSERT INTO a2a_discovery_health
      (target_id, attempt_id, fence_sequence, metadata_health, reason_code, evidence_expires_at, observed_at)
      VALUES ($1, $2, $3, $4, $5, NULL, $6)`, [
      input.claim.targetId, attemptId, input.claim.fenceSequence, metadataHealth, input.errorCode, completedAt,
    ]);
    const responseBody = {
      attempt_id: attemptId,
      target_id: input.claim.targetId,
      outcome: "failed",
      code: input.errorCode,
      detail: "Metadata discovery failed",
      metadata_health: metadataHealth,
      routable: false as const,
      completed_at: completedAt,
    };
    await insertAudit(tx, {
      operationId: input.claim.operationId, requestedByEmployeeId: input.claim.requestedByEmployeeId,
      executedByPrincipalId: input.claim.executedByPrincipalId, action: "discovery.failed",
      targetKind: "discovery_target", targetId: String(input.claim.targetId), beforeState: null,
      afterState: metadataHealth, reason: input.errorCode,
      metadata: { attempt_id: attemptId, error_code: input.errorCode }, createdAt: completedAt,
    });
    const responseStatus = input.errorCode === "timeout" ? 504 : 502;
    const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
      SET state = 'failed', response_status = $1, response_json = $2, completed_at = $3
      WHERE id = $4 AND state = 'running' AND lease_token = $5 AND fence_sequence = $6 RETURNING id`, [
      responseStatus, stableJson(responseBody), completedAt, input.claim.operationId, input.claim.leaseToken, input.claim.fenceSequence,
    ]);
    if (completed.length !== 1) throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation was fenced during failure commit");
    await completeSharedSubmission(tx, {
      actorId: input.claim.requestedByEmployeeId,
      submissionId: input.claim.submissionId,
      status: responseStatus,
      body: responseBody,
    });
    return { status: responseStatus, body: responseBody };
  });
}

export async function completeDiscoveryDomainFailure(
  db: SqlDatabase,
  input: { claim: OperationClaim; errorCode: "cache-miss"; status: number; completedAtMs: number },
): Promise<MutationResult<unknown>> {
  return db.transaction(async (tx) => {
    await lockCurrentOperation(tx, input.claim);
    const completedAt = new Date(input.completedAtMs).toISOString();
    const responseBody = {
      target_id: input.claim.targetId,
      outcome: "failed",
      code: input.errorCode,
      detail: "Discovery cache evidence is unavailable",
      routable: false as const,
      completed_at: completedAt,
    };
    await insertAudit(tx, {
      operationId: input.claim.operationId,
      requestedByEmployeeId: input.claim.requestedByEmployeeId,
      executedByPrincipalId: input.claim.executedByPrincipalId,
      action: "discovery.domain-failed",
      targetKind: "discovery_target",
      targetId: String(input.claim.targetId),
      beforeState: "running",
      afterState: "failed",
      reason: input.errorCode,
      metadata: { fence_sequence: input.claim.fenceSequence },
      createdAt: completedAt,
    });
    const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
      SET state = 'failed', response_status = $1, response_json = $2, completed_at = $3, lease_expires_at = $3
      WHERE id = $4 AND state = 'running' AND lease_token = $5 AND fence_sequence = $6 RETURNING id`, [
      input.status, stableJson(responseBody), completedAt, input.claim.operationId,
      input.claim.leaseToken, input.claim.fenceSequence,
    ]);
    if (completed.length !== 1) throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation was fenced during domain failure terminalization");
    await completeSharedSubmission(tx, {
      actorId: input.claim.requestedByEmployeeId,
      submissionId: input.claim.submissionId,
      status: input.status,
      body: responseBody,
    });
    return { status: input.status, body: responseBody };
  });
}

export async function completeDiscoveryPersistenceFailure(
  db: SqlDatabase,
  input: { claim: OperationClaim; completedAtMs: number },
): Promise<MutationResult<unknown>> {
  return db.transaction(async (tx) => {
    await lockCurrentOperation(tx, input.claim);
    const completedAt = new Date(input.completedAtMs).toISOString();
    const responseBody = {
      target_id: input.claim.targetId,
      outcome: "failed",
      code: "persistence-failed",
      detail: "Discovery persistence failed before a trustworthy endpoint outcome committed",
      routable: false as const,
      completed_at: completedAt,
    };
    await insertAudit(tx, {
      operationId: input.claim.operationId, requestedByEmployeeId: input.claim.requestedByEmployeeId,
      executedByPrincipalId: input.claim.executedByPrincipalId, action: "discovery.persistence-failed",
      targetKind: "discovery_target", targetId: String(input.claim.targetId), beforeState: "running", afterState: "failed",
      reason: "persistence-failed", metadata: { fence_sequence: input.claim.fenceSequence }, createdAt: completedAt,
    });
    const completed = await tx.query<{ id: unknown }>(`UPDATE a2a_admin_operations
      SET state = 'failed', response_status = 500, response_json = $1, completed_at = $2, lease_expires_at = $2
      WHERE id = $3 AND state = 'running' AND lease_token = $4 AND fence_sequence = $5 RETURNING id`, [
      stableJson(responseBody), completedAt, input.claim.operationId, input.claim.leaseToken, input.claim.fenceSequence,
    ]);
    if (completed.length !== 1) throw new DiscoveryStoreError(409, "operation-fenced", "Discovery operation was fenced during persistence failure terminalization");
    await completeSharedSubmission(tx, {
      actorId: input.claim.requestedByEmployeeId,
      submissionId: input.claim.submissionId,
      status: 500,
      body: responseBody,
    });
    return { status: 500, body: responseBody };
  });
}

export async function listDiscoveryAttempts(db: SqlDatabase, targetId: number, input: { afterId: number; limit: number }) {
  const rows = await db.query<SqlRow>(`SELECT id, target_id, fence_sequence, outcome, error_code,
    card_sha256, jwks_sha256, started_at, completed_at
    FROM a2a_discovery_attempts WHERE target_id = $1 AND id > $2 ORDER BY id LIMIT $3`, [targetId, input.afterId, input.limit + 1]);
  return {
    items: rows.slice(0, input.limit).map((row) => ({
      id: asNumber(row.id), target_id: asNumber(row.target_id), fence_sequence: asNumber(row.fence_sequence),
      outcome: asString(row.outcome), error_code: optionalString(row.error_code),
      card_sha256: optionalString(row.card_sha256), jwks_sha256: optionalString(row.jwks_sha256),
      started_at: asString(row.started_at), completed_at: asString(row.completed_at), routable: false as const,
    })),
    next_after_id: rows.length > input.limit ? asNumber(rows[input.limit]!.id) : null,
  };
}

export async function getDiscoveryHealth(db: SqlDatabase, targetId: number, nowMs = Date.now()) {
  first(await db.query<{ id: unknown }>("SELECT id FROM a2a_discovery_targets WHERE id = $1", [targetId]),
  "target-not-found", "Discovery target not found");
  const row = (await db.query<SqlRow>(`SELECT * FROM a2a_discovery_health
    WHERE target_id = $1 ORDER BY fence_sequence DESC LIMIT 1`, [targetId]))[0];
  if (row === undefined) {
    return { target_id: targetId, metadata_health: "unknown", reason_code: "not-yet-checked", observed_at: null, routable: false as const };
  }
  const observedAt = asString(row.observed_at);
  const storedHealth = asString(row.metadata_health);
  const stale = storedHealth === "healthy" && nowMs >= Date.parse(asString(row.evidence_expires_at));
  return {
    target_id: targetId,
    metadata_health: stale ? "stale" : asString(row.metadata_health),
    last_observed_health: storedHealth,
    reason_code: stale ? "metadata-stale" : asString(row.reason_code),
    fence_sequence: asNumber(row.fence_sequence),
    observed_at: observedAt,
    semantics: "Agent Card/JWKS metadata endpoint only",
    routable: false as const,
  };
}

function materializeKeyRevision(row: SqlRow) {
  return {
    id: asNumber(row.id), source_id: asNumber(row.source_id), target_id: asNumber(row.target_id),
    jku_uri: asString(row.jku_uri), key_id: asString(row.key_id), algorithm: asString(row.algorithm),
    key_fingerprint_sha256: asString(row.key_fingerprint_sha256), state: asString(row.state),
    row_version: asNumber(row.row_version), linked_trust_anchor_id: optionalNumber(row.linked_trust_anchor_id),
    decision_reason: optionalString(row.decision_reason),
    first_seen_attempt_id: asNumber(row.first_seen_attempt_id), last_seen_attempt_id: asNumber(row.last_seen_attempt_id),
    created_at: asString(row.created_at), updated_at: asString(row.updated_at), routable: false as const,
  };
}

export async function listManagedKeyRevisions(db: SqlDatabase, targetId: number, input: { afterId: number; limit: number; state?: "observed" | "active" | "revoked" }) {
  const rows = input.state === undefined
    ? await db.query<SqlRow>(`SELECT r.*, s.target_id, s.jku_uri FROM a2a_managed_key_revisions r
      JOIN a2a_managed_key_sources s ON s.id = r.source_id
      WHERE s.target_id = $1 AND r.id > $2 ORDER BY r.id LIMIT $3`, [targetId, input.afterId, input.limit + 1])
    : await db.query<SqlRow>(`SELECT r.*, s.target_id, s.jku_uri FROM a2a_managed_key_revisions r
      JOIN a2a_managed_key_sources s ON s.id = r.source_id
      WHERE s.target_id = $1 AND r.state = $2 AND r.id > $3 ORDER BY r.id LIMIT $4`, [targetId, input.state, input.afterId, input.limit + 1]);
  return { items: rows.slice(0, input.limit).map(materializeKeyRevision), next_after_id: rows.length > input.limit ? asNumber(rows[input.limit]!.id) : null };
}

export async function activateManagedKeyRevision(
  db: SqlDatabase,
  actor: DiscoveryActor,
  revisionId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  const reason = input.reason.trim();
  if (reason.length < 1 || reason.length > 1024 || /[\u0000-\u001f\u007f-\u009f]/u.test(reason)) {
    throw new DiscoveryStoreError(422, "decision-reason-invalid", "Decision reason is invalid");
  }
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId,
    operation: "managed-key.activate",
    request: { revision_id: revisionId, expected_version: input.expectedVersion, reason },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const row = first(await tx.query<SqlRow>(`SELECT r.*, s.target_id, s.jku_uri, t.state AS target_state
      FROM a2a_managed_key_revisions r
      JOIN a2a_managed_key_sources s ON s.id = r.source_id
      JOIN a2a_discovery_targets t ON t.id = s.target_id
      WHERE r.id = $1${lockSuffix(tx)}`, [revisionId]),
    "key-revision-not-found", "Managed key revision not found");
    if (asString(row.state) !== "observed") throw new DiscoveryStoreError(409, "invalid-key-transition", "Only observed key revisions can be activated");
    if (asString(row.target_state) !== "active") throw new DiscoveryStoreError(409, "target-disabled", "Discovery target is disabled");
    if (asNumber(row.row_version) !== input.expectedVersion) throw new DiscoveryStoreError(409, "stale-version", "Managed key revision version is stale");
    const anchor = await createTrustAnchorInTransaction(tx, actor, {
      keyId: asString(row.key_id),
      algorithm: asString(row.algorithm) as AgentCardSignatureAlgorithm,
      publicKeyPem: asString(row.public_key_pem),
    });
    const anchorBody = anchor.body;
    if (anchorBody.key_fingerprint_sha256 !== asString(row.key_fingerprint_sha256)) {
      throw new Error("Managed key fingerprint changed during exact anchor activation");
    }
    const updated = first(await tx.query<SqlRow>(`UPDATE a2a_managed_key_revisions
      SET state = 'active', row_version = row_version + 1, linked_trust_anchor_id = $1,
        activated_by_employee_id = $2, activated_by_principal_id = $3, activated_at = $4,
        decision_reason = $5, updated_at = $4
      WHERE id = $6 AND state = 'observed' AND row_version = $7 RETURNING *`, [
      anchorBody.id, actor.id, principalId, createdAt, reason, revisionId, input.expectedVersion,
    ]), "stale-version", "Managed key revision changed concurrently");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [asNumber(row.target_id), operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "managed-key.activated", targetKind: "managed_key_revision", targetId: String(revisionId),
      beforeState: "observed", afterState: "active", reason,
      metadata: { target_id: asNumber(row.target_id), key_id: asString(row.key_id), algorithm: asString(row.algorithm), fingerprint: asString(row.key_fingerprint_sha256), trust_anchor_id: anchorBody.id },
      createdAt,
    });
    return { status: 200, body: materializeKeyRevision({ ...row, ...updated }) };
  });
}

export async function revokeManagedKeyRevision(
  db: SqlDatabase,
  actor: DiscoveryActor,
  revisionId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId,
    operation: "managed-key.revoke",
    request: { revision_id: revisionId, expected_version: input.expectedVersion, reason: input.reason },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const row = first(await tx.query<SqlRow>(`SELECT r.*, s.target_id, s.jku_uri FROM a2a_managed_key_revisions r
      JOIN a2a_managed_key_sources s ON s.id = r.source_id WHERE r.id = $1${lockSuffix(tx)}`, [revisionId]),
    "key-revision-not-found", "Managed key revision not found");
    if (asString(row.state) !== "active") throw new DiscoveryStoreError(409, "invalid-key-transition", "Only active key revisions can be revoked");
    if (asNumber(row.row_version) !== input.expectedVersion) throw new DiscoveryStoreError(409, "stale-version", "Managed key revision version is stale");
    const anchorId = asNumber(row.linked_trust_anchor_id);
    const anchor = first(await tx.query<SqlRow>(`SELECT id, row_version, state FROM a2a_trust_anchors WHERE id = $1${lockSuffix(tx)}`, [anchorId]),
    "trust-anchor-not-found", "Linked trust anchor not found");
    if (asString(anchor.state) !== "active") throw new DiscoveryStoreError(409, "trust-anchor-terminal", "Linked trust anchor is already revoked");
    const cascade = await revokeTrustAnchorInTransaction(tx, actor, anchorId, {
      expectedVersion: asNumber(anchor.row_version), reason: input.reason, managedRevisionId: revisionId,
    });
    const updated = first(await tx.query<SqlRow>(`UPDATE a2a_managed_key_revisions
      SET state = 'revoked', row_version = row_version + 1, revoked_by_employee_id = $1,
        revoked_by_principal_id = $2, revoked_at = $3, decision_reason = $4, updated_at = $3
      WHERE id = $5 AND state = 'active' AND row_version = $6 RETURNING *`, [
      actor.id, principalId, createdAt, input.reason, revisionId, input.expectedVersion,
    ]), "stale-version", "Managed key revision changed concurrently");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [asNumber(row.target_id), operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "managed-key.revoked", targetKind: "managed_key_revision", targetId: String(revisionId),
      beforeState: "active", afterState: "revoked", reason: input.reason,
      metadata: { target_id: asNumber(row.target_id), key_id: asString(row.key_id), fingerprint: asString(row.key_fingerprint_sha256), trust_anchor_id: anchorId, cascaded_card_ids: cascade.body.cascaded_card_ids },
      createdAt,
    });
    return { status: 200, body: { ...materializeKeyRevision({ ...row, ...updated }), cascaded_card_ids: cascade.body.cascaded_card_ids } };
  });
}

function canonicalCredentialOrigin(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new DiscoveryStoreError(422, "credential-origin-invalid", "Credential origin is invalid"); }
  if (
    parsed.protocol !== "https:" || parsed.port !== "" || parsed.username !== "" || parsed.password !== "" ||
    parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== ""
  ) {
    throw new DiscoveryStoreError(422, "credential-origin-invalid", "Credential origin is invalid");
  }
  let domain: string;
  try { domain = canonicalizeDiscoveryDomain(parsed.hostname); }
  catch { throw new DiscoveryStoreError(422, "credential-origin-invalid", "Credential origin is invalid"); }
  return `https://${domain}`;
}

function requireCredentialReferenceHmacKey(hmacKey: string | null): string {
  if (hmacKey === null) {
    throw new DiscoveryStoreError(503, "credential-key-unavailable", "Credential reference fingerprint key is unavailable");
  }
  return hmacKey;
}

function canonicalSecretReference(value: string, hmacKey: string | null): { value: string; fingerprint: string } {
  if (value !== value.trim() || !SECRET_REFERENCE.test(value)) {
    throw new DiscoveryStoreError(422, "secret-reference-invalid", "Secret reference is invalid");
  }
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new DiscoveryStoreError(422, "secret-reference-invalid", "Secret reference is invalid"); }
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (["http", "https", "file", "data", "env", "javascript"].includes(scheme) || parsed.username !== "" || parsed.password !== "") {
    throw new DiscoveryStoreError(422, "secret-reference-invalid", "Secret reference is invalid");
  }
  return { value, fingerprint: createHmac("sha256", requireCredentialReferenceHmacKey(hmacKey)).update(value, "utf8").digest("hex") };
}

function materializeCredential(row: SqlRow) {
  return {
    id: asNumber(row.id), target_id: asNumber(row.target_id), canonical_origin: asString(row.canonical_origin),
    scheme_name: asString(row.scheme_name), scope: asString(row.scope), state: asString(row.state),
    row_version: asNumber(row.row_version), active_revision_id: optionalNumber(row.active_revision_id),
    provider: optionalString(row.provider), external_version: optionalString(row.external_version),
    created_at: asString(row.created_at), updated_at: asString(row.updated_at), revoked_at: optionalString(row.revoked_at),
    routable: false as const,
  };
}

function validateCredentialRevisionMetadata(provider: string, externalVersion: string): void {
  if (!CREDENTIAL_PROVIDER.test(provider)) {
    throw new DiscoveryStoreError(422, "credential-provider-invalid", "Credential provider is invalid");
  }
  if (!CREDENTIAL_EXTERNAL_VERSION.test(externalVersion)) {
    throw new DiscoveryStoreError(422, "credential-external-version-invalid", "Credential external version is invalid");
  }
}

export async function createCredentialBinding(
  db: SqlDatabase,
  actor: DiscoveryActor,
  targetId: number,
  input: {
    submissionId: string; origin: string; schemeName: string; scope: string;
    provider: string; externalVersion: string; secretReference: string;
    credentialReferenceHmacKey: string | null;
  },
) {
  const origin = canonicalCredentialOrigin(input.origin);
  if (!SCHEME_NAME.test(input.schemeName)) throw new DiscoveryStoreError(422, "credential-scheme-invalid", "Credential scheme is invalid");
  if (input.scope !== input.scope.trim() || input.scope.length < 1 || input.scope.length > 256 || /[\u0000-\u001f\u007f-\u009f]/u.test(input.scope)) {
    throw new DiscoveryStoreError(422, "credential-scope-invalid", "Credential scope is invalid");
  }
  validateCredentialRevisionMetadata(input.provider, input.externalVersion);
  const reference = canonicalSecretReference(input.secretReference, input.credentialReferenceHmacKey);
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId, operation: "credential-binding.create",
    request: {
      target_id: targetId, origin, scheme_name: input.schemeName, scope: input.scope,
      provider: input.provider, external_version: input.externalVersion,
      secret_reference_hmac_sha256: reference.fingerprint,
    },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const target = first(await tx.query<SqlRow>(`SELECT id, canonical_origin, state FROM a2a_discovery_targets
      WHERE id = $1${lockSuffix(tx)}`, [targetId]), "target-not-found", "Discovery target not found");
    if (asString(target.state) !== "active") throw new DiscoveryStoreError(409, "target-disabled", "Discovery target is disabled");
    if (origin !== asString(target.canonical_origin)) {
      throw new DiscoveryStoreError(422, "credential-origin-mismatch", "Credential origin must match the discovery target origin");
    }
    let binding: SqlRow;
    try {
      binding = first(await tx.query<SqlRow>(`INSERT INTO a2a_credential_bindings
        (target_id, canonical_origin, scheme_name, scope, state, row_version, created_by_employee_id,
          created_by_principal_id, created_at, updated_at, revoked_by_employee_id, revoked_by_principal_id,
          revoked_at, revoke_reason, active_revision_id)
        VALUES ($1, $2, $3, $4, 'revoked', 1, $5, $6, $7, $7, $5, $6, $7, 'credential-provisioning', NULL)
        RETURNING *`, [
        targetId, origin, input.schemeName, input.scope, actor.id, principalId, createdAt,
      ]), "credential-not-created", "Credential binding was not created");
    } catch (error) {
      if (!uniqueViolation(error)) throw error;
      throw new DiscoveryStoreError(409, "credential-conflict", "Credential binding already exists");
    }
    const revision = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_credential_revisions
      (binding_id, provider, external_version, secret_reference, secret_reference_hmac_sha256, state, row_version,
        created_by_employee_id, created_by_principal_id, created_at,
        revoked_by_employee_id, revoked_by_principal_id, revoked_at)
      VALUES ($1, $2, $3, $4, $5, 'revoked', 1, $6, $7, $8, $6, $7, $8) RETURNING id`, [
      asNumber(binding.id), input.provider, input.externalVersion, reference.value, reference.fingerprint,
      actor.id, principalId, createdAt,
    ]), "credential-revision-not-created", "Credential revision was not created");
    await tx.execute(`INSERT INTO a2a_credential_active_revisions (binding_id, revision_id, revision_state)
      VALUES ($1, $2, 'active')`, [asNumber(binding.id), asNumber(revision.id)]);
    await tx.execute(`UPDATE a2a_credential_revisions
      SET state = 'active', revoked_by_employee_id = NULL, revoked_by_principal_id = NULL, revoked_at = NULL
      WHERE id = $1 AND binding_id = $2 AND state = 'revoked'`, [asNumber(revision.id), asNumber(binding.id)]);
    const activatedBinding = first(await tx.query<SqlRow>(`UPDATE a2a_credential_bindings
      SET state = 'active', active_revision_id = $1, revoked_by_employee_id = NULL,
        revoked_by_principal_id = NULL, revoked_at = NULL, revoke_reason = NULL
      WHERE id = $2 AND state = 'revoked' RETURNING *`, [asNumber(revision.id), asNumber(binding.id)]),
    "credential-not-created", "Credential binding activation was not completed");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [targetId, operationId]);
    const body = materializeCredential({ ...activatedBinding, provider: input.provider, external_version: input.externalVersion });
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "credential-binding.created", targetKind: "credential_binding", targetId: String(binding.id),
      beforeState: null, afterState: "active", reason: null,
      metadata: {
        target_id: targetId, canonical_origin: origin, scheme_name: input.schemeName, scope: input.scope,
        provider: input.provider, external_version: input.externalVersion,
      },
      createdAt,
    });
    return { status: 201, body };
  });
}

export async function listCredentialBindings(db: SqlDatabase, targetId: number, input: { afterId: number; limit: number; state?: "active" | "revoked" }) {
  const statePredicate = input.state === undefined ? "" : "AND b.state = $3";
  const params = input.state === undefined
    ? [targetId, input.afterId, input.limit + 1]
    : [targetId, input.afterId, input.state, input.limit + 1];
  const limitParam = input.state === undefined ? "$3" : "$4";
  const rows = await db.query<SqlRow>(`SELECT b.*, r.provider, r.external_version
    FROM a2a_credential_bindings b
    LEFT JOIN a2a_credential_revisions r ON r.id = COALESCE(
      b.active_revision_id,
      (SELECT MAX(history.id) FROM a2a_credential_revisions history WHERE history.binding_id = b.id)
    ) AND r.binding_id = b.id
    WHERE b.target_id = $1 AND b.id > $2 ${statePredicate} ORDER BY b.id LIMIT ${limitParam}`, params);
  return { items: rows.slice(0, input.limit).map(materializeCredential), next_after_id: rows.length > input.limit ? asNumber(rows[input.limit]!.id) : null };
}

export async function rotateCredentialBinding(
  db: SqlDatabase,
  actor: DiscoveryActor,
  bindingId: number,
  input: {
    submissionId: string; expectedVersion: number; provider: string; externalVersion: string; secretReference: string;
    credentialReferenceHmacKey: string | null;
  },
) {
  validateCredentialRevisionMetadata(input.provider, input.externalVersion);
  const reference = canonicalSecretReference(input.secretReference, input.credentialReferenceHmacKey);
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId, operation: "credential-binding.rotate",
    request: {
      binding_id: bindingId, expected_version: input.expectedVersion,
      provider: input.provider, external_version: input.externalVersion,
      secret_reference_hmac_sha256: reference.fingerprint,
    },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const binding = first(await tx.query<SqlRow>(`SELECT b.*, t.state AS target_state
      FROM a2a_credential_bindings b JOIN a2a_discovery_targets t ON t.id = b.target_id
      WHERE b.id = $1${lockSuffix(tx)}`, [bindingId]),
    "credential-not-found", "Credential binding not found");
    if (asString(binding.state) !== "active") throw new DiscoveryStoreError(409, "credential-terminal", "Revoked credential bindings are terminal");
    if (asString(binding.target_state) !== "active") throw new DiscoveryStoreError(409, "target-disabled", "Discovery target is disabled");
    if (asNumber(binding.row_version) !== input.expectedVersion) throw new DiscoveryStoreError(409, "stale-version", "Credential binding version is stale");
    const oldRevisionId = asNumber(binding.active_revision_id);
    const oldRevision = first(await tx.query<SqlRow>(`SELECT * FROM a2a_credential_revisions
      WHERE id = $1 AND binding_id = $2${lockSuffix(tx)}`, [oldRevisionId, bindingId]),
    "credential-revision-not-found", "Active credential revision not found");
    if (asString(oldRevision.state) !== "active") throw new DiscoveryStoreError(409, "credential-revision-terminal", "Active credential revision is not active");
    let revision: { id: unknown };
    try {
      revision = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_credential_revisions
        (binding_id, provider, external_version, secret_reference, secret_reference_hmac_sha256, state, row_version,
          created_by_employee_id, created_by_principal_id, created_at,
          revoked_by_employee_id, revoked_by_principal_id, revoked_at)
        VALUES ($1, $2, $3, $4, $5, 'revoked', 1, $6, $7, $8, $6, $7, $8) RETURNING id`, [
        bindingId, input.provider, input.externalVersion, reference.value, reference.fingerprint,
        actor.id, principalId, createdAt,
      ]), "credential-revision-not-created", "Credential revision was not created");
    } catch (error) {
      if (!uniqueViolation(error)) throw error;
      throw new DiscoveryStoreError(409, "credential-reference-conflict", "Secret reference was already used for this binding");
    }
    await tx.execute("DELETE FROM a2a_credential_active_revisions WHERE binding_id = $1 AND revision_id = $2", [bindingId, oldRevisionId]);
    const revokedOld = await tx.query<{ id: unknown }>(`UPDATE a2a_credential_revisions
      SET state = 'revoked', row_version = row_version + 1, revoked_by_employee_id = $1,
        revoked_by_principal_id = $2, revoked_at = $3
      WHERE id = $4 AND binding_id = $5 AND state = 'active' RETURNING id`, [
      actor.id, principalId, createdAt, oldRevisionId, bindingId,
    ]);
    if (revokedOld.length !== 1) throw new DiscoveryStoreError(409, "credential-revision-terminal", "Active credential revision changed concurrently");
    await tx.execute(`INSERT INTO a2a_credential_active_revisions (binding_id, revision_id, revision_state)
      VALUES ($1, $2, 'active')`, [bindingId, asNumber(revision.id)]);
    await tx.execute(`UPDATE a2a_credential_revisions
      SET state = 'active', revoked_by_employee_id = NULL, revoked_by_principal_id = NULL, revoked_at = NULL
      WHERE id = $1 AND binding_id = $2 AND state = 'revoked'`, [asNumber(revision.id), bindingId]);
    const updated = first(await tx.query<SqlRow>(`UPDATE a2a_credential_bindings
      SET active_revision_id = $1, row_version = row_version + 1, updated_at = $2
      WHERE id = $3 AND state = 'active' AND row_version = $4 RETURNING *`, [
      asNumber(revision.id), createdAt, bindingId, input.expectedVersion,
    ]), "stale-version", "Credential binding changed concurrently");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [asNumber(binding.target_id), operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "credential-binding.rotated", targetKind: "credential_binding", targetId: String(bindingId),
      beforeState: "active", afterState: "active", reason: null,
      metadata: {
        target_id: asNumber(binding.target_id), canonical_origin: asString(binding.canonical_origin),
        scheme_name: asString(binding.scheme_name), scope: asString(binding.scope),
        provider: input.provider, external_version: input.externalVersion,
      },
      createdAt,
    });
    return { status: 200, body: materializeCredential({ ...updated, provider: input.provider, external_version: input.externalVersion }) };
  });
}

export async function revokeCredentialBinding(
  db: SqlDatabase,
  actor: DiscoveryActor,
  bindingId: number,
  input: { submissionId: string; expectedVersion: number; reason: string; credentialReferenceHmacKey: string | null },
) {
  requireCredentialReferenceHmacKey(input.credentialReferenceHmacKey);
  return runAdminMutation(db, actor, {
    submissionId: input.submissionId, operation: "credential-binding.revoke",
    request: { binding_id: bindingId, expected_version: input.expectedVersion, reason: input.reason },
  }, async ({ tx, operationId, principalId, createdAt }) => {
    const binding = first(await tx.query<SqlRow>(`SELECT * FROM a2a_credential_bindings WHERE id = $1${lockSuffix(tx)}`, [bindingId]),
    "credential-not-found", "Credential binding not found");
    if (asString(binding.state) !== "active") throw new DiscoveryStoreError(409, "credential-terminal", "Revoked credential bindings are terminal");
    if (asNumber(binding.row_version) !== input.expectedVersion) throw new DiscoveryStoreError(409, "stale-version", "Credential binding version is stale");
    const revisionId = asNumber(binding.active_revision_id);
    const revision = first(await tx.query<SqlRow>(`SELECT * FROM a2a_credential_revisions
      WHERE id = $1 AND binding_id = $2${lockSuffix(tx)}`, [revisionId, bindingId]),
    "credential-revision-not-found", "Active credential revision not found");
    if (asString(revision.state) !== "active") throw new DiscoveryStoreError(409, "credential-revision-terminal", "Active credential revision is not active");
    await tx.execute("DELETE FROM a2a_credential_active_revisions WHERE binding_id = $1 AND revision_id = $2", [bindingId, revisionId]);
    const revokedRevision = await tx.query<{ id: unknown }>(`UPDATE a2a_credential_revisions
      SET state = 'revoked', row_version = row_version + 1, revoked_by_employee_id = $1,
        revoked_by_principal_id = $2, revoked_at = $3
      WHERE id = $4 AND binding_id = $5 AND state = 'active' RETURNING id`, [
      actor.id, principalId, createdAt, revisionId, bindingId,
    ]);
    if (revokedRevision.length !== 1) throw new DiscoveryStoreError(409, "credential-revision-terminal", "Active credential revision changed concurrently");
    const updated = first(await tx.query<SqlRow>(`UPDATE a2a_credential_bindings
      SET state = 'revoked', row_version = row_version + 1, active_revision_id = NULL, updated_at = $1,
        revoked_by_employee_id = $2, revoked_by_principal_id = $3, revoked_at = $1, revoke_reason = $4
      WHERE id = $5 AND state = 'active' AND row_version = $6 RETURNING *`, [
      createdAt, actor.id, principalId, input.reason, bindingId, input.expectedVersion,
    ]), "stale-version", "Credential binding changed concurrently");
    await tx.execute("UPDATE a2a_admin_operations SET target_id = $1 WHERE id = $2", [asNumber(binding.target_id), operationId]);
    await insertAudit(tx, {
      operationId, requestedByEmployeeId: actor.id, executedByPrincipalId: principalId,
      action: "credential-binding.revoked", targetKind: "credential_binding", targetId: String(bindingId),
      beforeState: "active", afterState: "revoked", reason: input.reason,
      metadata: {
        target_id: asNumber(binding.target_id), canonical_origin: asString(binding.canonical_origin),
        scheme_name: asString(binding.scheme_name), scope: asString(binding.scope),
        provider: asString(revision.provider), external_version: asString(revision.external_version),
      },
      createdAt,
    });
    return {
      status: 200,
      body: materializeCredential({
        ...updated,
        provider: asString(revision.provider),
        external_version: asString(revision.external_version),
      }),
    };
  });
}
