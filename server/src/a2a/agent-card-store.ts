import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { asNumber, asString, type SqlDatabase, type SqlRow } from "../db.js";
import {
  admitPreparedAgentCardDocument,
  AgentCardAdmissionError,
  prepareAgentCardDocument,
  type AgentCardSignatureAlgorithm,
  type PreparedAgentCardAdmission,
  type TrustedAgentCardKey,
} from "./agent-card-registry.js";

export type RegistryState = "discovered" | "trusted" | "rejected" | "revoked";
export type TrustAnchorState = "active" | "revoked";

export interface RegistryActor {
  readonly id: number;
  readonly employeeCode: string;
}

export interface ProvenanceInput {
  readonly kind: "manual" | "api" | "migration";
  readonly source: string;
  readonly detail?: string;
}

export class AgentCardStoreError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AgentCardStoreError";
  }
}

type MutationResponse<T> = { readonly status: number; readonly body: T };

interface TrustAnchorRow extends SqlRow {
  id: unknown;
  key_id: unknown;
  algorithm: unknown;
  public_key_pem: unknown;
  key_fingerprint_sha256: unknown;
  state: unknown;
  row_version: unknown;
  created_by: unknown;
  created_at: unknown;
  revoked_by: unknown;
  revoked_at: unknown;
  revoke_reason: unknown;
}

interface RegistryRow extends SqlRow {
  id: unknown;
  document_id: unknown;
  preferred_interface_uri: unknown;
  state: unknown;
  trusted_anchor_id: unknown;
  verified_key_id: unknown;
  row_version: unknown;
  created_at: unknown;
  updated_at: unknown;
  reviewed_by: unknown;
  decision_reason: unknown;
}

interface DocumentRow extends SqlRow {
  id: unknown;
  document_sha256: unknown;
  payload_sha256: unknown;
  document_json: unknown;
  payload_json: unknown;
  name: unknown;
  card_version: unknown;
  preferred_interface_uri: unknown;
  created_at: unknown;
}

function optionalNumber(value: unknown): number | null {
  return value === null || value === undefined ? null : asNumber(value);
}

function optionalString(value: unknown): string | null {
  return value === null || value === undefined ? null : asString(value);
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value !== "object") throw new Error("Unsupported idempotency value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function isUniqueConstraintViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = "code" in error ? error.code : undefined;
  if (code === "23505") return true;
  const message = error instanceof Error ? error.message : "";
  return code === "ERR_SQLITE_ERROR" && /^UNIQUE constraint failed:/u.test(message);
}

function canonicalInterfaceUri(value: string): string {
  const normalized = new URL(value).href;
  if (normalized.length > 2048) {
    throw new AgentCardStoreError(422, "agent-card-invalid", "Agent Card is invalid");
  }
  return normalized;
}

function lockSuffix(db: SqlDatabase): string {
  return db.dialect === "postgres" ? " FOR UPDATE" : "";
}

function shareLockSuffix(db: SqlDatabase): string {
  return db.dialect === "postgres" ? " FOR SHARE" : "";
}

function first<T>(rows: T[], message: string): T {
  const value = rows[0];
  if (value === undefined) throw new AgentCardStoreError(404, "not-found", message);
  return value;
}

function registryState(value: unknown): RegistryState {
  const state = asString(value);
  if (state !== "discovered" && state !== "trusted" && state !== "rejected" && state !== "revoked") {
    throw new Error("Invalid registry state in database");
  }
  return state;
}

function anchorState(value: unknown): TrustAnchorState {
  const state = asString(value);
  if (state !== "active" && state !== "revoked") throw new Error("Invalid trust-anchor state in database");
  return state;
}

function materializeAnchor(row: TrustAnchorRow) {
  return {
    id: asNumber(row.id),
    key_id: asString(row.key_id),
    algorithm: asString(row.algorithm) as AgentCardSignatureAlgorithm,
    public_key_pem: asString(row.public_key_pem),
    key_fingerprint_sha256: asString(row.key_fingerprint_sha256),
    state: anchorState(row.state),
    row_version: asNumber(row.row_version),
    created_by: asNumber(row.created_by),
    created_at: asString(row.created_at),
    revoked_by: optionalNumber(row.revoked_by),
    revoked_at: optionalString(row.revoked_at),
    revoke_reason: optionalString(row.revoke_reason),
  } as const;
}

type CardDocumentProjection = Pick<DocumentRow, "document_sha256" | "payload_sha256" | "name" | "card_version">;

function materializeCard(registry: RegistryRow, document: CardDocumentProjection) {
  return {
    id: asNumber(registry.id),
    state: registryState(registry.state),
    row_version: asNumber(registry.row_version),
    document_sha256: asString(document.document_sha256),
    payload_sha256: asString(document.payload_sha256),
    name: asString(document.name),
    version: asString(document.card_version),
    preferred_interface_uri: asString(registry.preferred_interface_uri),
    trusted_anchor_id: optionalNumber(registry.trusted_anchor_id),
    verified_key_id: optionalString(registry.verified_key_id),
    reviewed_by: optionalNumber(registry.reviewed_by),
    decision_reason: optionalString(registry.decision_reason),
    created_at: asString(registry.created_at),
    updated_at: asString(registry.updated_at),
    routable: false as const,
  } as const;
}

function canonicalAnchor(input: {
  keyId: string;
  algorithm: AgentCardSignatureAlgorithm;
  publicKeyPem: string;
}): { definition: TrustedAgentCardKey; fingerprint: string } {
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/u.test(input.publicKeyPem)) {
    throw new AgentCardStoreError(422, "trust-anchor-key-invalid", "Trust anchor must contain a public key, not private key material");
  }
  let key: KeyObject;
  try {
    key = createPublicKey(input.publicKeyPem);
  } catch {
    throw new AgentCardStoreError(422, "trust-anchor-key-invalid", "Trust anchor must be a PEM-encoded public key");
  }
  const valid = input.algorithm === "ES256"
    ? key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1"
    : key.asymmetricKeyType === "ed25519";
  if (!valid) {
    throw new AgentCardStoreError(422, "trust-anchor-key-invalid", `Trust anchor key does not match ${input.algorithm}`);
  }
  const publicKeyPem = key.export({ type: "spki", format: "pem" }).toString();
  const fingerprint = sha256(key.export({ type: "spki", format: "der" }));
  return {
    definition: Object.freeze({ keyId: input.keyId, algorithm: input.algorithm, publicKeyPem, active: true }),
    fingerprint,
  };
}

type KnownAnchor = {
  readonly id: number;
  readonly rowVersion: number;
  readonly fingerprint: string;
  readonly state: TrustAnchorState;
  readonly definition: TrustedAgentCardKey;
};

async function knownAnchors(db: SqlDatabase, lockForImport = false): Promise<KnownAnchor[]> {
  const lock = lockForImport && db.dialect === "postgres" ? " FOR SHARE" : "";
  const rows = await db.query<TrustAnchorRow>(`SELECT * FROM a2a_trust_anchors ORDER BY id${lock}`);
  return rows.map((row) => {
    const anchor = materializeAnchor(row);
    return {
      id: anchor.id,
      rowVersion: anchor.row_version,
      fingerprint: anchor.key_fingerprint_sha256,
      state: anchor.state,
      definition: Object.freeze({
        keyId: anchor.key_id,
        algorithm: anchor.algorithm,
        publicKeyPem: anchor.public_key_pem,
        active: anchor.state === "active",
      }),
    };
  });
}

function redactedAnchorSnapshot(anchors: readonly KnownAnchor[]) {
  return anchors
    .filter((anchor) => anchor.state === "active")
    .sort((left, right) => left.id - right.id)
    .map((anchor) => ({
      id: anchor.id,
      row_version: anchor.rowVersion,
      key_id: anchor.definition.keyId,
      algorithm: anchor.definition.algorithm,
      key_fingerprint_sha256: anchor.fingerprint,
    }));
}

async function audit(
  tx: SqlDatabase,
  actor: RegistryActor,
  action: string,
  targetKind: "trust_anchor" | "agent_card",
  targetId: number,
  beforeState: string | null,
  afterState: string | null,
  reason: string | null,
  metadata: Record<string, unknown>,
  createdAt: string,
): Promise<void> {
  await tx.execute(`INSERT INTO a2a_registry_audit
    (actor_id, action, target_kind, target_id, before_state, after_state, reason, metadata_json, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
    actor.id, action, targetKind, String(targetId), beforeState, afterState, reason, stableJson(metadata), createdAt,
  ]);
}

async function idempotentMutation<T>(
  tx: SqlDatabase,
  actor: RegistryActor,
  submissionId: string,
  operation: string,
  request: unknown,
  work: () => Promise<MutationResponse<T>>,
): Promise<MutationResponse<T>> {
  const requestSha256 = sha256(stableJson({ operation, request }));
  const createdAt = new Date().toISOString();
  const inserted = await tx.query<{ actor_id: unknown }>(`INSERT INTO a2a_mutation_submissions
    (actor_id, submission_id, operation, request_sha256, response_json, response_status, created_at)
    VALUES ($1, $2, $3, $4, NULL, NULL, $5)
    ON CONFLICT(actor_id, submission_id) DO NOTHING RETURNING actor_id`, [
    actor.id, submissionId, operation, requestSha256, createdAt,
  ]);
  if (inserted.length === 0) {
    const row = first(await tx.query<SqlRow>(`SELECT operation, request_sha256, response_json, response_status
      FROM a2a_mutation_submissions WHERE actor_id = $1 AND submission_id = $2${lockSuffix(tx)}`,
    [actor.id, submissionId]), "Idempotency record not found");
    if (asString(row.operation) !== operation || asString(row.request_sha256) !== requestSha256) {
      throw new AgentCardStoreError(409, "submission-mismatch", "submission_id was already used for a different mutation");
    }
    if (row.response_json === null || row.response_json === undefined || row.response_status === null || row.response_status === undefined) {
      throw new AgentCardStoreError(409, "submission-in-progress", "The matching mutation has not completed");
    }
    return { status: asNumber(row.response_status), body: JSON.parse(asString(row.response_json)) as T };
  }
  const response = await work();
  const completed = await tx.query<{ actor_id: unknown }>(`UPDATE a2a_mutation_submissions
    SET response_json = $1, response_status = $2
    WHERE actor_id = $3 AND submission_id = $4 AND response_json IS NULL AND response_status IS NULL
    RETURNING actor_id`, [stableJson(response.body), response.status, actor.id, submissionId]);
  if (completed.length !== 1) throw new Error("Idempotency response was not recorded exactly once");
  return response;
}

export async function createTrustAnchor(
  db: SqlDatabase,
  actor: RegistryActor,
  input: { submissionId: string; keyId: string; algorithm: AgentCardSignatureAlgorithm; publicKeyPem: string },
) {
  const normalized = canonicalAnchor(input);
  return db.transaction((tx) => idempotentMutation(tx, actor, input.submissionId, "trust-anchor.create", {
    key_id: input.keyId,
    algorithm: input.algorithm,
    public_key_pem: normalized.definition.publicKeyPem,
    key_fingerprint_sha256: normalized.fingerprint,
  }, async () => {
    const createdAt = new Date().toISOString();
    let rows: TrustAnchorRow[];
    try {
      rows = await tx.query<TrustAnchorRow>(`INSERT INTO a2a_trust_anchors
        (key_id, algorithm, public_key_pem, key_fingerprint_sha256, state, row_version, created_by, created_at,
          revoked_by, revoked_at, revoke_reason)
        VALUES ($1, $2, $3, $4, 'active', 1, $5, $6, NULL, NULL, NULL) RETURNING *`, [
        input.keyId, input.algorithm, normalized.definition.publicKeyPem, normalized.fingerprint, actor.id, createdAt,
      ]);
    } catch (error) {
      if (!isUniqueConstraintViolation(error)) throw error;
      throw new AgentCardStoreError(409, "trust-anchor-conflict", "Trust-anchor key ID or fingerprint already exists");
    }
    const anchor = materializeAnchor(first(rows, "Trust anchor was not created"));
    await audit(tx, actor, "trust-anchor.created", "trust_anchor", anchor.id, null, "active", null, {
      key_id: anchor.key_id, algorithm: anchor.algorithm, fingerprint: anchor.key_fingerprint_sha256,
    }, createdAt);
    return { status: 201, body: anchor };
  }));
}

function boundedPage<T extends { id: number }>(items: T[], limit: number) {
  const hasMore = items.length > limit;
  const pageItems = hasMore ? items.slice(0, limit) : items;
  return {
    items: pageItems,
    next_after_id: hasMore ? pageItems[pageItems.length - 1]!.id : null,
  } as const;
}

export async function listTrustAnchors(
  db: SqlDatabase,
  input: { state?: TrustAnchorState; afterId: number; limit: number },
) {
  const rows = input.state === undefined
    ? await db.query<TrustAnchorRow>("SELECT * FROM a2a_trust_anchors WHERE id > $1 ORDER BY id LIMIT $2", [input.afterId, input.limit + 1])
    : await db.query<TrustAnchorRow>("SELECT * FROM a2a_trust_anchors WHERE state = $1 AND id > $2 ORDER BY id LIMIT $3", [input.state, input.afterId, input.limit + 1]);
  return boundedPage(rows.map(materializeAnchor), input.limit);
}

export async function revokeTrustAnchor(
  db: SqlDatabase,
  actor: RegistryActor,
  anchorId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return db.transaction((tx) => idempotentMutation(tx, actor, input.submissionId, "trust-anchor.revoke", {
    anchor_id: anchorId, expected_version: input.expectedVersion, reason: input.reason,
  }, async () => {
    const anchorRow = first(await tx.query<TrustAnchorRow>(`SELECT * FROM a2a_trust_anchors WHERE id = $1${lockSuffix(tx)}`,
      [anchorId]), "Trust anchor not found");
    const anchor = materializeAnchor(anchorRow);
    if (anchor.state !== "active") throw new AgentCardStoreError(409, "trust-anchor-terminal", "Revoked trust anchors are terminal");
    if (anchor.row_version !== input.expectedVersion) throw new AgentCardStoreError(409, "stale-version", "Trust-anchor version is stale");
    const changedAt = new Date().toISOString();
    const revokedAnchors = await tx.query<TrustAnchorRow>(`UPDATE a2a_trust_anchors
      SET state = 'revoked', row_version = row_version + 1, revoked_by = $1, revoked_at = $2, revoke_reason = $3
      WHERE id = $4 AND state = 'active' AND row_version = $5 RETURNING *`, [
      actor.id, changedAt, input.reason, anchorId, input.expectedVersion,
    ]);
    if (revokedAnchors.length !== 1) throw new AgentCardStoreError(409, "stale-version", "Trust-anchor version changed concurrently");
    const affected = await tx.query<RegistryRow>(`SELECT * FROM a2a_card_registry
      WHERE trusted_anchor_id = $1 AND state = 'trusted' ORDER BY id${lockSuffix(tx)}`, [anchorId]);
    for (const registry of affected) {
      const cardId = asNumber(registry.id);
      const cascaded = await tx.query<{ id: unknown }>(`UPDATE a2a_card_registry
        SET state = 'revoked', row_version = row_version + 1, updated_at = $1, reviewed_by = $2, decision_reason = $3
        WHERE id = $4 AND state = 'trusted' AND row_version = $5 RETURNING id`, [
        changedAt, actor.id, input.reason, cardId, asNumber(registry.row_version),
      ]);
      if (cascaded.length !== 1) throw new AgentCardStoreError(409, "stale-version", "Trusted card changed during anchor revocation");
      await audit(tx, actor, "agent-card.revoked-by-anchor", "agent_card", cardId, "trusted", "revoked", input.reason, {
        trust_anchor_id: anchorId,
      }, changedAt);
    }
    await audit(tx, actor, "trust-anchor.revoked", "trust_anchor", anchorId, "active", "revoked", input.reason, {
      cascaded_card_ids: affected.map((row) => asNumber(row.id)),
    }, changedAt);
    const updated = materializeAnchor(first(await tx.query<TrustAnchorRow>("SELECT * FROM a2a_trust_anchors WHERE id = $1", [anchorId]), "Trust anchor not found"));
    return { status: 200, body: { ...updated, cascaded_card_ids: affected.map((row) => asNumber(row.id)) } };
  }));
}

function admitImport(
  preparedDocument: ReturnType<typeof prepareAgentCardDocument>,
  anchors: KnownAnchor[],
): PreparedAgentCardAdmission {
  try {
    return admitPreparedAgentCardDocument(preparedDocument, {
      trustedKeys: anchors.map((anchor) => anchor.definition),
    });
  } catch (error) {
    if (error instanceof AgentCardAdmissionError) {
      throw new AgentCardStoreError(422, error.code, `Agent Card admission failed: ${error.code}`);
    }
    throw error;
  }
}

export async function importAgentCard(
  db: SqlDatabase,
  actor: RegistryActor,
  input: { submissionId: string; card: unknown; provenance: ProvenanceInput },
) {
  let preparedDocument: ReturnType<typeof prepareAgentCardDocument>;
  try {
    preparedDocument = prepareAgentCardDocument(input.card);
  } catch (error) {
    if (error instanceof AgentCardAdmissionError) {
      throw new AgentCardStoreError(422, error.code, `Agent Card admission failed: ${error.code}`);
    }
    throw error;
  }
  return db.transaction(async (tx) => {
    return idempotentMutation(tx, actor, input.submissionId, "agent-card.import", {
      canonical_document: preparedDocument.documentJson,
      provenance: input.provenance,
    }, async () => {
      // Mutable trust state is evaluated only for a new submission. Exact
      // successful retries return above before current anchor lifecycle matters.
      const anchors = await knownAnchors(tx, true);
      const prepared = admitImport(preparedDocument, anchors);
      const preferredInterfaceUri = canonicalInterfaceUri(prepared.admitted.preferredInterface);
      const observedAt = new Date().toISOString();
      await tx.query(`INSERT INTO a2a_card_documents
        (document_sha256, payload_sha256, document_json, payload_json, name, card_version, preferred_interface_uri, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT(document_sha256) DO NOTHING RETURNING id`, [
        prepared.documentSha256, prepared.payloadSha256, prepared.documentJson, prepared.payloadJson,
        prepared.admitted.name, prepared.admitted.version, preferredInterfaceUri, observedAt,
      ]);
      const document = first(await tx.query<DocumentRow>("SELECT * FROM a2a_card_documents WHERE document_sha256 = $1", [prepared.documentSha256]), "Agent Card document not found");
      const documentId = asNumber(document.id);
      await tx.query(`INSERT INTO a2a_card_registry
        (document_id, preferred_interface_uri, state, trusted_anchor_id, verified_key_id, row_version,
          created_at, updated_at, reviewed_by, decision_reason)
        VALUES ($1, $2, 'discovered', NULL, NULL, 1, $3, $3, NULL, NULL)
        ON CONFLICT(document_id) DO NOTHING RETURNING id`, [documentId, preferredInterfaceUri, observedAt]);
      const registry = first(await tx.query<RegistryRow>(`SELECT * FROM a2a_card_registry WHERE document_id = $1${lockSuffix(tx)}`, [documentId]), "Agent Card registry record not found");
      const registryId = asNumber(registry.id);
      const observation = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_card_observations
        (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, [
        registryId, actor.id, input.submissionId, input.provenance.kind, input.provenance.source,
        input.provenance.detail ?? null, observedAt,
      ]), "Agent Card observation was not created");
      const verifiedAnchor = prepared.admitted.verifiedKeyId === null
        ? undefined
        : anchors.find((anchor) => anchor.definition.keyId === prepared.admitted.verifiedKeyId);
      await tx.execute(`INSERT INTO a2a_card_verifications
        (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
          document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
        asNumber(observation.id), documentId, verifiedAnchor?.id ?? null, prepared.admitted.trustState,
        prepared.admitted.verifiedKeyId, prepared.documentSha256, prepared.payloadSha256,
        stableJson(redactedAnchorSnapshot(anchors)), observedAt,
      ]);
      await audit(tx, actor, "agent-card.observed", "agent_card", registryId, registryState(registry.state), registryState(registry.state), null, {
        observation_id: asNumber(observation.id), submission_id: input.submissionId,
        document_sha256: prepared.documentSha256, admission_trust_state: prepared.admitted.trustState,
        verified_key_id: prepared.admitted.verifiedKeyId,
      }, observedAt);
      return {
        status: 201,
        body: {
          card: materializeCard(registry, document),
          observation_id: asNumber(observation.id),
          admission: {
            trust_state: prepared.admitted.trustState,
            verified_key_id: prepared.admitted.verifiedKeyId,
            document_sha256: prepared.documentSha256,
            payload_sha256: prepared.payloadSha256,
          },
        },
      };
    });
  });
}

export async function listAgentCards(
  db: SqlDatabase,
  input: { state?: RegistryState; afterId: number; limit: number },
) {
  const where = input.state === undefined
    ? "WHERE r.id > $1"
    : "WHERE r.state = $1 AND r.id > $2";
  const params = input.state === undefined
    ? [input.afterId, input.limit + 1]
    : [input.state, input.afterId, input.limit + 1];
  const limitParameter = input.state === undefined ? "$2" : "$3";
  const rows = await db.query<RegistryRow & CardDocumentProjection>(`SELECT r.*,
    d.document_sha256, d.payload_sha256, d.name, d.card_version
    FROM a2a_card_registry r JOIN a2a_card_documents d ON d.id = r.document_id
    ${where} ORDER BY r.id LIMIT ${limitParameter}`, params);
  return boundedPage(rows.map((row) => materializeCard(row, row)), input.limit);
}

export async function getAgentCard(db: SqlDatabase, cardId: number) {
  const registry = first(await db.query<RegistryRow>("SELECT * FROM a2a_card_registry WHERE id = $1", [cardId]), "Agent Card not found");
  const document = first(await db.query<DocumentRow>("SELECT * FROM a2a_card_documents WHERE id = $1", [asNumber(registry.document_id)]), "Agent Card document not found");
  return {
    ...materializeCard(registry, document),
    document_json: asString(document.document_json),
    payload_json: asString(document.payload_json),
  };
}

export async function getAgentCardHistory(
  db: SqlDatabase,
  cardId: number,
  input: { observationsAfterId: number; verificationsAfterId: number; auditAfterId: number; limit: number },
) {
  return db.transaction(async (tx) => {
    first(await tx.query<RegistryRow>(`SELECT id FROM a2a_card_registry WHERE id = $1${shareLockSuffix(tx)}`, [cardId]), "Agent Card not found");
    const observations = await tx.query<SqlRow>(`SELECT id, actor_id, submission_id, provenance_kind,
      provenance_source, provenance_detail, observed_at FROM a2a_card_observations
      WHERE registry_id = $1 AND id > $2 ORDER BY id LIMIT $3`, [cardId, input.observationsAfterId, input.limit + 1]);
    const verifications = await tx.query<SqlRow>(`SELECT v.id, v.observation_id, v.trust_anchor_id,
      v.admission_trust_state, v.verified_key_id, v.document_sha256, v.payload_sha256,
      v.trust_anchor_snapshot_json, v.verified_at
      FROM a2a_card_verifications v JOIN a2a_card_observations o ON o.id = v.observation_id
      WHERE o.registry_id = $1 AND v.id > $2 ORDER BY v.id LIMIT $3`, [cardId, input.verificationsAfterId, input.limit + 1]);
    const auditRows = await tx.query<SqlRow>(`SELECT id, actor_id, action, target_kind, target_id, before_state, after_state, reason,
      metadata_json, created_at FROM a2a_registry_audit
      WHERE target_kind = 'agent_card' AND target_id = $1 AND id > $2 ORDER BY id LIMIT $3`, [String(cardId), input.auditAfterId, input.limit + 1]);
    const observationPage = boundedPage(observations.map((row) => ({
      id: asNumber(row.id), actor_id: asNumber(row.actor_id), submission_id: asString(row.submission_id),
      provenance: { kind: asString(row.provenance_kind), source: asString(row.provenance_source), detail: optionalString(row.provenance_detail) },
      observed_at: asString(row.observed_at),
    })), input.limit);
    const verificationPage = boundedPage(verifications.map((row) => ({
      id: asNumber(row.id), observation_id: asNumber(row.observation_id), trust_anchor_id: optionalNumber(row.trust_anchor_id),
      admission_trust_state: asString(row.admission_trust_state), verified_key_id: optionalString(row.verified_key_id),
      document_sha256: asString(row.document_sha256), payload_sha256: asString(row.payload_sha256),
      trust_anchor_snapshot: JSON.parse(asString(row.trust_anchor_snapshot_json)) as unknown,
      verified_at: asString(row.verified_at),
    })), input.limit);
    const auditPage = boundedPage(auditRows.map(materializeAudit), input.limit);
    return {
      observations: observationPage,
      verifications: verificationPage,
      audit: auditPage,
    };
  });
}

async function lockRegistryAndDocument(tx: SqlDatabase, cardId: number) {
  const registry = first(await tx.query<RegistryRow>(`SELECT * FROM a2a_card_registry WHERE id = $1${lockSuffix(tx)}`, [cardId]), "Agent Card not found");
  const document = first(await tx.query<DocumentRow>("SELECT * FROM a2a_card_documents WHERE id = $1", [asNumber(registry.document_id)]), "Agent Card document not found");
  return { registry, document };
}

export async function reviewAgentCard(
  db: SqlDatabase,
  actor: RegistryActor,
  cardId: number,
  input: { submissionId: string; expectedVersion: number; decision: "trusted" | "rejected"; reason: string },
) {
  if (input.decision === "rejected") {
    return db.transaction((tx) => idempotentMutation(tx, actor, input.submissionId, "agent-card.review", {
      card_id: cardId, expected_version: input.expectedVersion, decision: input.decision, reason: input.reason,
    }, async () => {
      const { registry, document } = await lockRegistryAndDocument(tx, cardId);
      if (registryState(registry.state) !== "discovered") throw new AgentCardStoreError(409, "terminal-state", "Only discovered cards can be reviewed");
      if (asNumber(registry.row_version) !== input.expectedVersion) throw new AgentCardStoreError(409, "stale-version", "Agent Card version is stale");
      const changedAt = new Date().toISOString();
      const updatedRows = await tx.query<RegistryRow>(`UPDATE a2a_card_registry SET state = 'rejected', row_version = row_version + 1,
        updated_at = $1, reviewed_by = $2, decision_reason = $3
        WHERE id = $4 AND state = 'discovered' AND row_version = $5 RETURNING *`, [changedAt, actor.id, input.reason, cardId, input.expectedVersion]);
      if (updatedRows.length !== 1) throw new AgentCardStoreError(409, "stale-version", "Agent Card changed concurrently");
      await audit(tx, actor, "agent-card.rejected", "agent_card", cardId, "discovered", "rejected", input.reason, {}, changedAt);
      return { status: 200, body: materializeCard(updatedRows[0]!, document) };
    }));
  }

  return db.transaction((tx) => idempotentMutation(tx, actor, input.submissionId, "agent-card.review", {
    card_id: cardId, expected_version: input.expectedVersion, decision: input.decision, reason: input.reason,
  }, async () => {
    const initialRegistry = first(await tx.query<RegistryRow>("SELECT * FROM a2a_card_registry WHERE id = $1", [cardId]), "Agent Card not found");
    const initialDocument = first(await tx.query<DocumentRow>("SELECT * FROM a2a_card_documents WHERE id = $1", [asNumber(initialRegistry.document_id)]), "Agent Card document not found");
    const anchors = await knownAnchors(tx);
    if (!anchors.some((anchor) => anchor.state === "active")) throw new AgentCardStoreError(409, "trust-anchor-required", "No active explicit trust anchor is available");
    const preparedDocument = prepareAgentCardDocument(JSON.parse(asString(initialDocument.document_json)) as unknown);
    const prepared = admitImport(preparedDocument, anchors);
    const verifiedKeyId = prepared.admitted.verifiedKeyId;
    if (verifiedKeyId === null) throw new AgentCardStoreError(409, "signature-not-trusted", "Agent Card is not signed by an active explicit trust anchor");
    const selected = anchors.find((anchor) => anchor.definition.keyId === verifiedKeyId);
    if (selected === undefined) throw new AgentCardStoreError(409, "trust-anchor-required", "Verified trust anchor is unavailable");
    const anchorRow = first(await tx.query<TrustAnchorRow>(`SELECT * FROM a2a_trust_anchors WHERE id = $1${lockSuffix(tx)}`, [selected.id]), "Trust anchor not found");
    const anchor = materializeAnchor(anchorRow);
    if (anchor.state !== "active" || anchor.key_id !== verifiedKeyId) {
      throw new AgentCardStoreError(409, "trust-anchor-revoked", "The verified trust anchor is not active");
    }
    const { registry, document } = await lockRegistryAndDocument(tx, cardId);
    if (registryState(registry.state) !== "discovered") throw new AgentCardStoreError(409, "terminal-state", "Only discovered cards can be reviewed");
    if (asNumber(registry.row_version) !== input.expectedVersion) throw new AgentCardStoreError(409, "stale-version", "Agent Card version is stale");
    if (tx.dialect === "postgres") {
      await tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [asString(registry.preferred_interface_uri)]);
    }
    const competing = await tx.query<RegistryRow>(`SELECT id FROM a2a_card_registry
      WHERE preferred_interface_uri = $1 AND state = 'trusted' AND id <> $2${lockSuffix(tx)}`, [
      asString(registry.preferred_interface_uri), cardId,
    ]);
    if (competing.length > 0) throw new AgentCardStoreError(409, "trusted-interface-conflict", "A trusted card already owns this preferred interface");
    const changedAt = new Date().toISOString();
    const updatedRows = await tx.query<RegistryRow>(`UPDATE a2a_card_registry SET state = 'trusted', trusted_anchor_id = $1,
      verified_key_id = $2, row_version = row_version + 1, updated_at = $3, reviewed_by = $4, decision_reason = $5
      WHERE id = $6 AND state = 'discovered' AND row_version = $7 RETURNING *`, [
      anchor.id, verifiedKeyId, changedAt, actor.id, input.reason, cardId, input.expectedVersion,
    ]);
    if (updatedRows.length !== 1) throw new AgentCardStoreError(409, "stale-version", "Agent Card changed concurrently");
    const observation = first(await tx.query<{ id: unknown }>(`INSERT INTO a2a_card_observations
      (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
      VALUES ($1, $2, $3, 'admin-review', $4, $5, $6) RETURNING id`, [
      cardId, actor.id, input.submissionId, actor.employeeCode, input.reason, changedAt,
    ]), "Agent Card review observation was not created");
    await tx.execute(`INSERT INTO a2a_card_verifications
      (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
        document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
      VALUES ($1, $2, $3, 'trusted', $4, $5, $6, $7, $8)`, [
      asNumber(observation.id), asNumber(document.id), anchor.id, verifiedKeyId,
      asString(document.document_sha256), asString(document.payload_sha256),
      stableJson(redactedAnchorSnapshot(anchors)), changedAt,
    ]);
    await audit(tx, actor, "agent-card.trusted", "agent_card", cardId, "discovered", "trusted", input.reason, {
      trust_anchor_id: anchor.id, verified_key_id: verifiedKeyId,
    }, changedAt);
    return { status: 200, body: materializeCard(updatedRows[0]!, document) };
  }));
}

export async function revokeAgentCard(
  db: SqlDatabase,
  actor: RegistryActor,
  cardId: number,
  input: { submissionId: string; expectedVersion: number; reason: string },
) {
  return db.transaction((tx) => idempotentMutation(tx, actor, input.submissionId, "agent-card.revoke", {
    card_id: cardId, expected_version: input.expectedVersion, reason: input.reason,
  }, async () => {
    const { registry, document } = await lockRegistryAndDocument(tx, cardId);
    if (registryState(registry.state) !== "trusted") throw new AgentCardStoreError(409, "invalid-transition", "Only trusted cards can be revoked");
    if (asNumber(registry.row_version) !== input.expectedVersion) throw new AgentCardStoreError(409, "stale-version", "Agent Card version is stale");
    const changedAt = new Date().toISOString();
    const updatedRows = await tx.query<RegistryRow>(`UPDATE a2a_card_registry SET state = 'revoked', row_version = row_version + 1,
      updated_at = $1, reviewed_by = $2, decision_reason = $3
      WHERE id = $4 AND state = 'trusted' AND row_version = $5 RETURNING *`, [changedAt, actor.id, input.reason, cardId, input.expectedVersion]);
    if (updatedRows.length !== 1) throw new AgentCardStoreError(409, "stale-version", "Agent Card changed concurrently");
    await audit(tx, actor, "agent-card.revoked", "agent_card", cardId, "trusted", "revoked", input.reason, {}, changedAt);
    return { status: 200, body: materializeCard(updatedRows[0]!, document) };
  }));
}

function materializeAudit(row: SqlRow) {
  return {
    id: asNumber(row.id), actor_id: asNumber(row.actor_id), action: asString(row.action),
    target_kind: asString(row.target_kind), target_id: asString(row.target_id),
    before_state: optionalString(row.before_state), after_state: optionalString(row.after_state),
    reason: optionalString(row.reason), metadata: JSON.parse(asString(row.metadata_json)) as unknown,
    created_at: asString(row.created_at),
  };
}

export async function listRegistryAudit(db: SqlDatabase, afterId: number, limit: number) {
  const rows = await db.query<SqlRow>(`SELECT * FROM a2a_registry_audit WHERE id > $1 ORDER BY id LIMIT $2`, [afterId, limit + 1]);
  return boundedPage(rows.map(materializeAudit), limit);
}
