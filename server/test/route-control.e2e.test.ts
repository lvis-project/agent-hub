import { createHash, generateKeyPairSync, sign as signPayload } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { prepareAgentCardDocument } from "../src/a2a/agent-card-registry.js";
import {
  DISCOVERY_MAX_BODY_BYTES,
  type DiscoveryTransport,
  type DiscoveryTransportRequest,
  type DiscoveryTransportResponse,
} from "../src/a2a/discovery-egress.js";
import { createCredentialBinding, rotateCredentialBinding } from "../src/a2a/discovery-store.js";
import { resolveRouteSnapshot, RouteControlError } from "../src/a2a/route-control-store.js";
import type { Settings } from "../src/config.js";
import { asNumber, createDatabase, type SqlDatabase } from "../src/db.js";

const EXTENSION_URI = "urn:uuid:383a1d70-5c3b-42d9-a65d-9f084b7a1a44";
const SPEC_SOURCE_URL = "https://spec.example.test/a2a/exact-send-replay/v1";
const A2A_SPECIFICATION_URI = "https://a2a-protocol.org/v1.0.0/specification/";
const SPEC_BYTES = Buffer.from("LVIS exact-send-replay specification v1\n", "utf8");
const SPEC_DIGEST = createHash("sha256").update(SPEC_BYTES).digest("hex");
const parityDatabaseUrl = process.env.AGENT_HUB_P4_5_DATABASE_URL ?? "sqlite://:memory:";
const secondaryParityDatabaseUrl = parityDatabaseUrl !== "sqlite://:memory:" && parityDatabaseUrl.startsWith("sqlite://")
  ? "sqlite://:memory:"
  : parityDatabaseUrl;
const settings: Settings = {
  databaseUrl: "sqlite://:memory:", postgresTls: { mode: "disabled", caFile: null }, host: "127.0.0.1", port: 8000, logLevel: "silent",
  rateLimitPerIpPerMinute: 10_000, signupRateLimitPerIpPerMinute: 10_000,
  trustedProxyIps: [], corsOrigins: ["http://localhost:5173"], tlsHstsMaxAge: 0,
  credentialReferenceHmacKey: "test-only-credential-reference-key-0001",
};

class ProbeTransport implements DiscoveryTransport {
  readonly inputs: DiscoveryTransportRequest[] = [];
  reachabilityBody = Buffer.from("{}");
  specGate?: Promise<void>;
  onSpecRequest?: () => void;
  async request(input: DiscoveryTransportRequest): Promise<DiscoveryTransportResponse> {
    this.inputs.push(input);
    if (input.url.href === SPEC_SOURCE_URL) {
      this.onSpecRequest?.();
      await this.specGate;
      return { statusCode: 200, headers: { "content-type": "application/octet-stream" }, body: SPEC_BYTES };
    }
    return { statusCode: 401, headers: { "content-type": "application/json" }, body: this.reachabilityBody };
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

async function seedActor(db: SqlDatabase, employeeCode: string, role: "employee" | "admin", token: string) {
  const timestamp = new Date().toISOString();
  await db.execute(`INSERT INTO departments (code, name, path, created_at) VALUES
    ('platform', 'Platform', '/platform', $1) ON CONFLICT(code) DO NOTHING`, [timestamp]);
  const department = (await db.query<{ id: unknown }>("SELECT id FROM departments WHERE code = 'platform'"))[0]!;
  const employee = (await db.query<{ id: unknown }>(`INSERT INTO employees
    (employee_code, name, email, department_id, job_level, reputation_tokens, created_at)
    VALUES ($1, $2, $3, $4, 5, 0, $5) RETURNING id`, [
    employeeCode, employeeCode, `${employeeCode}@example.test`, asNumber(department.id), timestamp,
  ]))[0]!;
  const employeeId = asNumber(employee.id);
  const apiKey = (await db.query<{ id: unknown }>(`INSERT INTO api_keys
    (employee_id, label, key_hash, key_prefix, role, created_at, expires_at, revoked_at)
    VALUES ($1, 'test', $2, $3, $4, $5, NULL, NULL) RETURNING id`, [
    employeeId, createHash("sha256").update(token).digest("hex"), token.slice(0, 16), role, timestamp,
  ]))[0]!;
  return { employeeId, apiKeyId: asNumber(apiKey.id) };
}

async function seedAdditionalApiKey(db: SqlDatabase, employeeId: number, token: string) {
  const timestamp = new Date().toISOString();
  const apiKey = (await db.query<{ id: unknown }>(`INSERT INTO api_keys
    (employee_id, label, key_hash, key_prefix, role, created_at, expires_at, revoked_at)
    VALUES ($1, 'other-host', $2, $3, 'employee', $4, NULL, NULL) RETURNING id`, [
    employeeId, createHash("sha256").update(token).digest("hex"), token.slice(0, 16), timestamp,
  ]))[0]!;
  return asNumber(apiKey.id);
}

function routeCard(additionalRequired = false) {
  return {
    name: "Remote Agent", description: "P4-5 route fixture.", version: "1.0.0",
    capabilities: {
      streaming: false, pushNotifications: false, extendedAgentCard: false,
      extensions: [
        {
          uri: EXTENSION_URI,
          required: false,
          params: {
            profile: "lvis-exact-send-replay", profileVersion: "1",
            requestBody: "exact-serialized-jsonrpc", resultRetentionSeconds: "604800",
            specDigestSha256: SPEC_DIGEST,
          },
        },
        { uri: "https://optional.example.test/telemetry/v1", required: false, params: { mode: "audit" } },
        ...(additionalRequired
          ? [{ uri: "https://required.example.test/foreign/v1", required: true, params: { mode: "required" } }]
          : []),
      ],
    },
    skills: [{ id: "delegate", name: "Delegate", description: "Delegate work.", tags: ["work"] }],
    supportedInterfaces: [{
      url: "https://runtime.example.test/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0",
    }],
    defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"],
    securitySchemes: { bearerAuth: { httpAuthSecurityScheme: { scheme: "bearer" } } },
    securityRequirements: [{ schemes: { bearerAuth: { list: [] } } }],
  };
}

async function seedRouteSubjects(db: SqlDatabase, adminId: number, card = routeCard()) {
  const now = new Date().toISOString();
  const principal = (await db.query<{ id: unknown }>(`INSERT INTO a2a_principals
    (kind, employee_id, system_name, created_at) VALUES ('employee', $1, NULL, $2) RETURNING id`, [adminId, now]))[0]!;
  const principalId = asNumber(principal.id);
  const target = (await db.query<{ id: unknown }>(`INSERT INTO a2a_discovery_targets
    (canonical_origin, canonical_domain, card_url, state, row_version, next_fence_sequence,
      created_by_employee_id, created_by_principal_id, created_at,
      disabled_by_employee_id, disabled_by_principal_id, disabled_at, disable_reason)
    VALUES ('https://runtime.example.test', 'runtime.example.test',
      'https://runtime.example.test/.well-known/agent-card.json', 'active', 1, 1,
      $1, $2, $3, NULL, NULL, NULL, NULL) RETURNING id`, [adminId, principalId, now]))[0]!;
  const targetId = asNumber(target.id);
  const anchor = (await db.query<{ id: unknown }>(`INSERT INTO a2a_trust_anchors
    (key_id, algorithm, public_key_pem, key_fingerprint_sha256, state, row_version,
      created_by, created_at, revoked_by, revoked_at, revoke_reason)
    VALUES ('route-key', 'ES256', 'test-public-key', $1, 'active', 1, $2, $3, NULL, NULL, NULL)
    RETURNING id`, ["c".repeat(64), adminId, now]))[0]!;
  const anchorId = asNumber(anchor.id);
  const prepared = prepareAgentCardDocument(card);
  const document = (await db.query<{ id: unknown }>(`INSERT INTO a2a_card_documents
    (document_sha256, payload_sha256, document_json, payload_json, name, card_version,
      preferred_interface_uri, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, [
    prepared.documentSha256, prepared.payloadSha256, prepared.documentJson, prepared.payloadJson,
    prepared.name, prepared.version, prepared.preferredInterface, now,
  ]))[0]!;
  const registry = (await db.query<{ id: unknown }>(`INSERT INTO a2a_card_registry
    (document_id, preferred_interface_uri, state, trusted_anchor_id, verified_key_id,
      row_version, created_at, updated_at, reviewed_by, decision_reason)
    VALUES ($1, $2, 'trusted', $3, 'route-key', 1, $4, $4, $5, 'route fixture') RETURNING id`, [
    asNumber(document.id), prepared.preferredInterface, anchorId, now, adminId,
  ]))[0]!;
  await db.execute(`INSERT INTO a2a_mutation_submissions
    (actor_id, submission_id, operation, request_sha256, response_json, response_status, created_at)
    VALUES ($1, 'seed-discovery', 'seed.discovery', $2, '{}', 200, $3)`, [adminId, "d".repeat(64), now]);
  const operation = (await db.query<{ id: unknown }>(`INSERT INTO a2a_admin_operations
    (requested_by_employee_id, executed_by_principal_id, target_id, submission_id, operation_kind,
      semantic_request_hash, state, response_status, response_json, lease_token, fence_sequence,
      lease_expires_at, started_at, completed_at)
    VALUES ($1, $2, $3, 'seed-discovery', 'discovery.revalidate', $4, 'succeeded', 200, '{}',
      'seed-lease', 1, $5, $6, $6) RETURNING id`, [
    adminId, principalId, targetId, "e".repeat(64), new Date(Date.now() + 60_000).toISOString(), now,
  ]))[0]!;
  const attempt = (await db.query<{ id: unknown }>(`INSERT INTO a2a_discovery_attempts
    (operation_id, target_id, fence_sequence, requested_by_employee_id, executed_by_principal_id,
      outcome, error_code, card_document_id, jwks_document_id, card_sha256, jwks_sha256,
      started_at, completed_at)
    VALUES ($1, $2, 1, $3, $4, 'succeeded', NULL, NULL, NULL, $5, NULL, $6, $6) RETURNING id`, [
    asNumber(operation.id), targetId, adminId, principalId, prepared.documentSha256, now,
  ]))[0]!;
  const source = (await db.query<{ id: unknown }>(`INSERT INTO a2a_managed_key_sources
    (target_id, jku_uri, state, row_version, created_at, updated_at)
    VALUES ($1, 'https://runtime.example.test/keys.jwks', 'active', 1, $2, $2) RETURNING id`, [targetId, now]))[0]!;
  const key = (await db.query<{ id: unknown }>(`INSERT INTO a2a_managed_key_revisions
    (source_id, key_id, algorithm, public_key_pem, key_fingerprint_sha256, state, row_version,
      linked_trust_anchor_id, first_seen_attempt_id, last_seen_attempt_id, created_at, updated_at,
      activated_by_employee_id, activated_by_principal_id, activated_at,
      revoked_by_employee_id, revoked_by_principal_id, revoked_at, decision_reason)
    VALUES ($1, 'route-key', 'ES256', 'test-public-key', $2, 'active', 1, $3, $4, $4, $5, $5,
      $6, $7, $5, NULL, NULL, NULL, 'route fixture') RETURNING id`, [
    asNumber(source.id), "c".repeat(64), anchorId, asNumber(attempt.id), now, adminId, principalId,
  ]))[0]!;
  const credential = await createCredentialBinding(db, { id: adminId, employeeCode: "admin-route" }, targetId, {
    submissionId: "seed-credential", origin: "https://runtime.example.test", schemeName: "bearerAuth",
    scope: "a2a", provider: "vault", externalVersion: "v1",
    secretReference: "vault://route/v1", credentialReferenceHmacKey: settings.credentialReferenceHmacKey,
  });
  return {
    targetId, registryId: asNumber(registry.id), keyRevisionId: asNumber(key.id),
    credentialBindingId: credential.body.id,
    credentialRevisionId: credential.body.active_revision_id!, cardDigest: prepared.documentSha256,
  };
}

function wireBundle(agentCardDigest: string, overrides: Record<string, unknown> = {}) {
  return {
    schema_version: "lvis-wire-conformance-bundle/v1",
    artifact_id: "wire-artifact-1",
    agent_hub_head_sha: "1".repeat(40),
    lvis_app_head_sha: "2".repeat(40),
    remote_server_head_sha: "7".repeat(40),
    a2a_tck_tag: "1.0.0.alpha2",
    a2a_tck_commit_sha: "29063fe95e903cddac5d8ff811ab94df1ad6ef86",
    agent_hub_lock_digest_sha256: "4".repeat(64),
    lvis_app_lock_digest_sha256: "5".repeat(64),
    remote_server_lock_digest_sha256: "8".repeat(64),
    a2a_tck_lock_digest_sha256: "6".repeat(64),
    a2a_specification_uri: A2A_SPECIFICATION_URI,
    extension_spec_uri: EXTENSION_URI,
    extension_spec_digest_sha256: SPEC_DIGEST,
    agent_card_digest_sha256: agentCardDigest,
    test_vectors_total: 40,
    test_vectors_passed: 40,
    test_vectors_failed: 0,
    test_vectors_skipped: 0,
    verification_state: "passed",
    ...overrides,
  };
}

async function seedVerifiedEvidence(
  app: Awaited<ReturnType<typeof buildApp>>,
  admin: { authorization: string },
  agentCardDigest: string,
  suffix = "1",
) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signer = await app.inject({
    method: "POST", url: "/api/v1/admin/a2a/evidence-signers", headers: admin,
    payload: {
      submission_id: `evidence-signer-${suffix}`, key_id: `evidence-signer-${suffix}`,
      public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    },
  });
  expect(signer.statusCode).toBe(201);
  const spec = await app.inject({
    method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
    payload: { submission_id: `served-spec-${suffix}`, source_url: SPEC_SOURCE_URL },
  });
  expect(spec.statusCode).toBe(201);
  expect(spec.json()).toMatchObject({
    spec_uri: EXTENSION_URI, source_url: SPEC_SOURCE_URL,
    body_sha256: SPEC_DIGEST, body_size: SPEC_BYTES.length,
  });
  const bundle = wireBundle(agentCardDigest);
  const rawPayload = Buffer.from(canonicalJson(bundle), "utf8");
  const signature = signPayload(null, rawPayload, privateKey);
  const evidence = await app.inject({
    method: "POST", url: "/api/v1/admin/a2a/wire-conformance-evidence", headers: admin,
    payload: {
      submission_id: `wire-evidence-${suffix}`, signer_id: signer.json().id,
      served_spec_observation_id: spec.json().id,
      signed_payload_base64: rawPayload.toString("base64"), signature_base64: signature.toString("base64"),
    },
  });
  expect(evidence.statusCode).toBe(201);
  expect(evidence.json()).toMatchObject({
    artifact_digest_sha256: createHash("sha256").update(rawPayload).digest("hex"),
    remote_server_head_sha: bundle.remote_server_head_sha,
    remote_server_lock_digest_sha256: bundle.remote_server_lock_digest_sha256,
    a2a_specification_uri: A2A_SPECIFICATION_URI,
    a2a_tck_tag: "1.0.0.alpha2",
    a2a_tck_commit_sha: "29063fe95e903cddac5d8ff811ab94df1ad6ef86",
  });
  return {
    signerId: signer.json().id as number,
    servedSpecObservationId: spec.json().id as number,
    specDigest: spec.json().body_sha256 as string,
    wireConformanceEvidenceId: evidence.json().id as number,
    artifactId: evidence.json().artifact_id as string,
    artifactDigest: evidence.json().artifact_digest_sha256 as string,
    publicKey, privateKey, bundle,
  };
}

describe("G005 direct route control plane", () => {
  const cleanups: Array<() => Promise<void>> = [];
  afterEach(async () => { while (cleanups.length > 0) await cleanups.pop()!(); });

  it("probes the advertised interface, provisions an explicit grant, and issues one no-store exact snapshot", async () => {
    const db = createDatabase(parityDatabaseUrl);
    if (db.dialect === "postgres") {
      await db.execute("DROP SCHEMA IF EXISTS public CASCADE");
      await db.execute("CREATE SCHEMA public");
    }
    const transport = new ProbeTransport();
    const app = await buildApp({
      database: db, settings,
      testOnlyDiscoveryDependencies: {
        resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 as const }]; } },
        transport,
      },
    });
    cleanups.push(async () => { await app.close(); await db.close(); });
    await db.execute("CREATE TABLE external_claim_probe (id INTEGER PRIMARY KEY)");
    if (db.dialect === "sqlite") {
      const indexColumns = await db.query<{ name: unknown; desc: unknown }>(
        "PRAGMA index_xinfo('ix_a2a_interface_health_latest')",
      );
      expect(indexColumns.slice(0, 2).map((row) => [row.name, asNumber(row.desc)])).toEqual([
        ["advertised_interface_id", 0], ["id", 1],
      ]);
    } else {
      const index = (await db.query<{ indexdef: string }>(`SELECT indexdef FROM pg_indexes
        WHERE schemaname = 'public' AND indexname = 'ix_a2a_interface_health_latest'`))[0]!;
      expect(index.indexdef).toContain("(advertised_interface_id, id DESC)");
    }
    const adminToken = "admin-route-token-0000000000000001";
    const actorToken = "actor-route-token-0000000000000001";
    const adminActor = await seedActor(db, "admin-route", "admin", adminToken);
    const actor = await seedActor(db, "actor-route", "employee", actorToken);
    const adminId = adminActor.employeeId;
    const actorId = actor.employeeId;
    const otherHostToken = "actor-other-host-token-000000000001";
    await seedAdditionalApiKey(db, actorId, otherHostToken);
    const subject = await seedRouteSubjects(db, adminId);
    const admin = { authorization: `Bearer ${adminToken}` };
    const missingSpecSource = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-source-missing" },
    });
    expect(missingSpecSource.statusCode).toBe(422);
    const malformedSpecSource = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-source-malformed", source_url: "not a URL" },
    });
    expect(malformedSpecSource.statusCode).toBe(422);
    expect(malformedSpecSource.json()).toMatchObject({ code: "served-spec-source-url-invalid" });
    const identifierAsSource = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-source-urn", source_url: EXTENSION_URI },
    });
    expect(identifierAsSource.statusCode).toBe(422);
    expect(identifierAsSource.json()).toMatchObject({ code: "served-spec-source-url-invalid" });
    expect(transport.inputs).toHaveLength(0);
    const retryAfterFetchFailure = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-source-urn", source_url: SPEC_SOURCE_URL },
    });
    expect(retryAfterFetchFailure.statusCode).toBe(201);
    expect(retryAfterFetchFailure.json()).toMatchObject({
      spec_uri: EXTENSION_URI, source_url: SPEC_SOURCE_URL, body_sha256: SPEC_DIGEST,
    });
    const evidence = await seedVerifiedEvidence(app, admin, subject.cardDigest);
    const requestsAfterInitialObservation = transport.inputs.length;
    const servedSpecReplay = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-1", source_url: SPEC_SOURCE_URL },
    });
    expect(servedSpecReplay.statusCode).toBe(201);
    expect(servedSpecReplay.json()).toMatchObject({ id: evidence.servedSpecObservationId, spec_uri: EXTENSION_URI });
    expect(transport.inputs).toHaveLength(requestsAfterInitialObservation);
    const servedSpecMismatch = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-1", source_url: "https://different.example.test/spec" },
    });
    expect(servedSpecMismatch.statusCode).toBe(409);
    expect(servedSpecMismatch.json()).toMatchObject({ code: "submission-mismatch" });
    expect(transport.inputs).toHaveLength(requestsAfterInitialObservation);
    const concurrentRequestCount = transport.inputs.length;
    const concurrent = await Promise.all([
      app.inject({
        method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
        payload: { submission_id: "served-spec-concurrent", source_url: SPEC_SOURCE_URL },
      }),
      app.inject({
        method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
        payload: { submission_id: "served-spec-concurrent", source_url: SPEC_SOURCE_URL },
      }),
    ]);
    const successfulConcurrent = concurrent.find((response) => response.statusCode === 201);
    expect(successfulConcurrent).toBeDefined();
    expect(concurrent.every((response) => response.statusCode === 201 || response.statusCode === 409)).toBe(true);
    for (const response of concurrent.filter((candidate) => candidate.statusCode === 409)) {
      expect(response.json()).toMatchObject({ code: "submission-in-progress" });
    }
    expect(transport.inputs).toHaveLength(concurrentRequestCount + 1);
    const concurrentReplay = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-concurrent", source_url: SPEC_SOURCE_URL },
    });
    expect(concurrentReplay.statusCode).toBe(201);
    expect(concurrentReplay.json()).toEqual(successfulConcurrent!.json());
    expect(transport.inputs).toHaveLength(concurrentRequestCount + 1);
    let releaseSpecFetch!: () => void;
    let markSpecStarted!: () => void;
    transport.specGate = new Promise<void>((resolve) => { releaseSpecFetch = resolve; });
    const specStarted = new Promise<void>((resolve) => { markSpecStarted = resolve; });
    transport.onSpecRequest = markSpecStarted;
    const slowObservation = app.inject({
      method: "POST", url: "/api/v1/admin/a2a/served-spec-observations", headers: admin,
      payload: { submission_id: "served-spec-slow", source_url: SPEC_SOURCE_URL },
    });
    await specStarted;
    try {
      const unrelatedWrite = await Promise.race([
        db.execute("INSERT INTO external_claim_probe (id) VALUES (1)").then(() => "written" as const),
        new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 250)),
      ]);
      expect(unrelatedWrite).toBe("written");
    } finally {
      releaseSpecFetch();
      transport.specGate = undefined;
      transport.onSpecRequest = undefined;
    }
    expect((await slowObservation).statusCode).toBe(201);

    const caller = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/caller-generations", headers: admin,
      payload: { submission_id: "caller-provision", caller_generation_id: "caller-generation-1",
        employee_id: actorId, api_key_id: actor.apiKeyId, host_id: "host-1" } });
    expect(caller.statusCode).toBe(201);
    expect(caller.json()).toMatchObject({ api_key_id: actor.apiKeyId, host_id: "host-1" });
    const callerReplay = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/caller-generations", headers: admin,
      payload: { submission_id: "caller-provision", caller_generation_id: "caller-generation-1",
        employee_id: actorId, api_key_id: actor.apiKeyId, host_id: "host-1" } });
    expect(callerReplay.statusCode).toBe(201);
    expect(callerReplay.json()).toEqual(caller.json());
    expect(await db.query("SELECT id FROM a2a_caller_generations")).toHaveLength(1);
    const invalidCallerCursor = await app.inject({
      method: "GET",
      url: "/api/v1/admin/a2a/caller-generations?after_id=%20invalid",
      headers: admin,
    });
    expect(invalidCallerCursor.statusCode).toBe(422);
    for (const suffix of ["a", "b", "c"] as const) {
      const pagedCaller = await app.inject({
        method: "POST", url: "/api/v1/admin/a2a/caller-generations", headers: admin,
        payload: {
          submission_id: `caller-page-${suffix}`, caller_generation_id: `caller-page-${suffix}`,
          employee_id: actorId, api_key_id: actor.apiKeyId, host_id: "host-1",
        },
      });
      expect(pagedCaller.statusCode).toBe(201);
    }
    const callerPageOne = await app.inject({
      method: "GET",
      url: "/api/v1/admin/a2a/caller-generations?after_id=caller-generation-1&limit=2",
      headers: admin,
    });
    expect(callerPageOne.statusCode).toBe(200);
    expect(callerPageOne.json().items.map((item: { caller_generation_id: string }) => item.caller_generation_id))
      .toEqual(["caller-page-a", "caller-page-b"]);
    expect(callerPageOne.json().next_after_id).toBe("caller-page-b");
    const callerPageTwo = await app.inject({
      method: "GET",
      url: `/api/v1/admin/a2a/caller-generations?after_id=${callerPageOne.json().next_after_id}&limit=2`,
      headers: admin,
    });
    expect(callerPageTwo.json().items.map((item: { caller_generation_id: string }) => item.caller_generation_id))
      .toEqual(["caller-page-c"]);
    expect(callerPageTwo.json().next_after_id).toBeNull();
    const requestsBeforeHealth = transport.inputs.length;
    const health = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: { submission_id: "interface-probe", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a" } });
    expect(health.statusCode).toBe(201);
    expect(health.json()).toMatchObject({ reachability: "healthy", reason_code: "interface-reachable" });
    expect(transport.inputs).toHaveLength(requestsBeforeHealth + 1);
    expect(transport.inputs.at(-1)).toMatchObject({ pinnedAddress: { address: "8.8.8.8", family: 4 } });
    expect(transport.inputs.at(-1)!.headers).not.toHaveProperty("Authorization");
    for (const suffix of ["b", "c"] as const) {
      const pagedHealth = await app.inject({
        method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
        payload: {
          submission_id: `interface-probe-${suffix}`, target_id: subject.targetId,
          card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a",
        },
      });
      expect(pagedHealth.statusCode).toBe(201);
    }
    const healthPageOne = await app.inject({
      method: "GET", url: "/api/v1/admin/a2a/advertised-interfaces/health?after_id=0&limit=2", headers: admin,
    });
    expect(healthPageOne.statusCode).toBe(200);
    expect(healthPageOne.json().items.map((item: { id: number }) => item.id)).toEqual([
      health.json().id, health.json().id + 1,
    ]);
    expect(healthPageOne.json().next_after_id).toBe(health.json().id + 1);
    const healthPageTwo = await app.inject({
      method: "GET",
      url: `/api/v1/admin/a2a/advertised-interfaces/health?after_id=${healthPageOne.json().next_after_id}&limit=2`,
      headers: admin,
    });
    expect(healthPageTwo.json().items.map((item: { id: number }) => item.id)).toEqual([health.json().id + 2]);
    expect(healthPageTwo.json().next_after_id).toBeNull();

    transport.reachabilityBody = Buffer.alloc(DISCOVERY_MAX_BODY_BYTES + 1, 0x61);
    const oversizedHealth = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: {
        submission_id: "interface-probe-oversized", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a",
      },
    });
    expect(oversizedHealth.statusCode).toBe(201);
    expect(oversizedHealth.json()).toMatchObject({ reachability: "unreachable", reason_code: "body-too-large" });
    const storedOversizedHealth = (await db.query<{
      reachability: string; reason_code: string; expires_at: unknown;
    }>(`SELECT reachability, reason_code, expires_at FROM a2a_interface_health_observations
      WHERE id = $1`, [oversizedHealth.json().id]))[0]!;
    expect(storedOversizedHealth).toEqual({ reachability: "unreachable", reason_code: "body-too-large", expires_at: null });

    transport.reachabilityBody = Buffer.from("{}");
    const recoveredHealth = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: {
        submission_id: "interface-probe-recovered", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a",
      },
    });
    expect(recoveredHealth.statusCode).toBe(201);
    expect(recoveredHealth.json()).toMatchObject({ reachability: "healthy", reason_code: "interface-reachable" });

    const policy = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "policy-provision", target_id: subject.targetId, card_registry_id: subject.registryId,
        managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "caller-generation-1", host_id: "host-1", operation_kind: "initial_send",
        interface_url: "https://runtime.example.test/a2a",
        served_spec_observation_id: evidence.servedSpecObservationId,
        extension_spec_digest_sha256: evidence.specDigest,
        wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
        wire_conformance_artifact_digest_sha256: evidence.artifactDigest, route_policy_version: 1,
      } });
    expect(policy.statusCode).toBe(201);
    const policyBody = policy.json();
    expect(policyBody).toMatchObject({
      operation_kind: "initial_send",
      served_spec_observation_id: evidence.servedSpecObservationId,
      wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
      wire_conformance_artifact_id: evidence.artifactId,
      wire_conformance_artifact_digest_sha256: evidence.artifactDigest,
      remote_server_head_sha: evidence.bundle.remote_server_head_sha,
      remote_server_lock_digest_sha256: evidence.bundle.remote_server_lock_digest_sha256,
      a2a_specification_uri: A2A_SPECIFICATION_URI,
    });
    expect(policyBody).not.toHaveProperty("operation_class");
    expect(policyBody).not.toHaveProperty("wire_conformance_digest_sha256");
    const policyList = await app.inject({
      method: "GET", url: "/api/v1/admin/a2a/route-policies", headers: admin,
    });
    expect(policyList.statusCode).toBe(200);
    expect(policyList.json().items[0]).toMatchObject({
      operation_kind: "initial_send",
      served_spec_observation_id: evidence.servedSpecObservationId,
      wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
      wire_conformance_artifact_id: evidence.artifactId,
      wire_conformance_artifact_digest_sha256: evidence.artifactDigest,
      remote_server_head_sha: evidence.bundle.remote_server_head_sha,
      remote_server_lock_digest_sha256: evidence.bundle.remote_server_lock_digest_sha256,
      a2a_specification_uri: A2A_SPECIFICATION_URI,
    });
    expect(policyList.json().items[0]).not.toHaveProperty("operation_class");
    expect(policyList.json().items[0]).not.toHaveProperty("wire_conformance_digest_sha256");
    const originalLocaleCompare = String.prototype.localeCompare;
    String.prototype.localeCompare = function localeCompareInReverse(compareString: string): number {
      const left = String(this);
      return left === compareString ? 0 : left < compareString ? 1 : -1;
    };
    const replayPolicy = await (async () => {
      try {
        return await app.inject({
          method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
          payload: {
            submission_id: "policy-replay", target_id: subject.targetId, card_registry_id: subject.registryId,
            managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
            caller_generation_id: "caller-generation-1", host_id: "host-1",
            operation_kind: "exact_initial_send_replay",
            interface_url: "https://runtime.example.test/a2a",
            served_spec_observation_id: evidence.servedSpecObservationId,
            extension_spec_digest_sha256: evidence.specDigest,
            wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
            wire_conformance_artifact_digest_sha256: evidence.artifactDigest, route_policy_version: 1,
          },
        });
      } finally {
        String.prototype.localeCompare = originalLocaleCompare;
      }
    })();
    expect(replayPolicy.statusCode).toBe(201);
    const replayPolicyBody = replayPolicy.json();
    expect(replayPolicyBody.route_policy_digest_sha256).toBe(policyBody.route_policy_digest_sha256);
    const requestBody = {
      operation_id: "operation-1", attempt_id: "attempt-1", operation_kind: "initial_send",
      a2a_method: "SendMessage", target_agent_id: subject.targetId,
      interface_url: "https://runtime.example.test/a2a", agent_card_digest_sha256: subject.cardDigest,
      trust_key_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
      caller_generation_id: "caller-generation-1", route_policy_version: 1,
      route_policy_digest_sha256: policyBody.route_policy_digest_sha256,
      extension_uri: EXTENSION_URI, extension_spec_digest_sha256: SPEC_DIGEST,
      intended_credential_revision_id: subject.credentialRevisionId,
    } as const;
    const racePolicy = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "policy-race", target_id: subject.targetId, card_registry_id: subject.registryId,
        managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "caller-generation-1", host_id: "host-1", operation_kind: "initial_send",
        interface_url: "https://runtime.example.test/a2a",
        served_spec_observation_id: evidence.servedSpecObservationId,
        extension_spec_digest_sha256: evidence.specDigest,
        wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
        wire_conformance_artifact_digest_sha256: evidence.artifactDigest, route_policy_version: 2,
      } });
    expect(racePolicy.statusCode).toBe(201);
    const racePolicyBody = racePolicy.json();
    const policyPageOne = await app.inject({
      method: "GET", url: "/api/v1/admin/a2a/route-policies?after_id=0&limit=2", headers: admin,
    });
    expect(policyPageOne.statusCode).toBe(200);
    expect(policyPageOne.json().items.map((item: { id: number }) => item.id)).toEqual([
      policyBody.id, replayPolicyBody.id,
    ]);
    expect(policyPageOne.json().next_after_id).toBe(replayPolicyBody.id);
    expect(policyPageOne.json().items.every((item: Record<string, unknown>) =>
      Object.hasOwn(item, "operation_kind") && !Object.hasOwn(item, "operation_class"))).toBe(true);
    const policyPageTwo = await app.inject({
      method: "GET",
      url: `/api/v1/admin/a2a/route-policies?after_id=${policyPageOne.json().next_after_id}&limit=2`,
      headers: admin,
    });
    expect(policyPageTwo.json().items.map((item: { id: number }) => item.id)).toEqual([racePolicyBody.id]);
    expect(policyPageTwo.json().next_after_id).toBeNull();
    await expect(resolveRouteSnapshot(db, { id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route" }, {
      operationId: "operation-race", attemptId: "attempt-race", operationKind: "initial_send",
      a2aMethod: "SendMessage", targetAgentId: subject.targetId,
      interfaceUrl: "https://runtime.example.test/a2a", agentCardDigestSha256: subject.cardDigest,
      trustKeyId: subject.keyRevisionId, credentialBindingId: subject.credentialBindingId,
      callerGenerationId: "caller-generation-1", routePolicyVersion: 2,
      routePolicyDigestSha256: racePolicyBody.route_policy_digest_sha256,
      extensionUri: EXTENSION_URI, extensionSpecDigestSha256: SPEC_DIGEST,
      intendedCredentialRevisionId: subject.credentialRevisionId,
    }, {
      async afterCandidateRead(tx, candidatePolicyId) {
        const revokedAt = new Date().toISOString();
        await tx.execute(`UPDATE a2a_route_policies SET state = 'revoked', row_version = row_version + 1,
          revoked_by_employee_id = $1, revoked_at = $2, revoke_reason = 'race won by revocation'
          WHERE id = $3`, [adminId, revokedAt, candidatePolicyId]);
      },
    })).rejects.toSatisfy((error: unknown) =>
      error instanceof RouteControlError && error.code === "route-ineligible");
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(0);

    const otherHostDenied = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${otherHostToken}` },
      payload: { ...requestBody, attempt_id: "attempt-other-host-key" } });
    expect(otherHostDenied.statusCode).toBe(403);
    expect(otherHostDenied.json()).toMatchObject({ code: "route-ineligible" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(0);

    const resolved = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: requestBody });
    expect(resolved.statusCode).toBe(200);
    expect(resolved.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(resolved.headers.pragma).toBe("no-cache");
    expect(resolved.json()).toEqual(expect.objectContaining({
      ...requestBody, credential_revision_id: subject.credentialRevisionId,
      credential_provider: "vault", credential_external_version: "v1",
      protocol_binding: "JSONRPC", protocol_version: "1.0", auth_scheme: "Bearer",
      served_spec_observation_id: evidence.servedSpecObservationId,
      wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
      wire_conformance_artifact_id: evidence.artifactId,
      wire_conformance_artifact_digest_sha256: evidence.artifactDigest,
      agent_hub_head_sha: evidence.bundle.agent_hub_head_sha,
      lvis_app_head_sha: evidence.bundle.lvis_app_head_sha,
      remote_server_head_sha: evidence.bundle.remote_server_head_sha,
      a2a_tck_tag: evidence.bundle.a2a_tck_tag,
      a2a_tck_commit_sha: evidence.bundle.a2a_tck_commit_sha,
      agent_hub_lock_digest_sha256: evidence.bundle.agent_hub_lock_digest_sha256,
      lvis_app_lock_digest_sha256: evidence.bundle.lvis_app_lock_digest_sha256,
      remote_server_lock_digest_sha256: evidence.bundle.remote_server_lock_digest_sha256,
      a2a_tck_lock_digest_sha256: evidence.bundle.a2a_tck_lock_digest_sha256,
      a2a_specification_uri: A2A_SPECIFICATION_URI,
    }));
    const serialized = resolved.body;
    expect(serialized).not.toContain("vault://route/v1");
    expect(serialized).not.toContain("secret_reference");
    const issuance = await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit");
    expect(issuance).toHaveLength(1);
    expect(issuance[0]).toMatchObject({
      remote_server_head_sha: evidence.bundle.remote_server_head_sha,
      remote_server_lock_digest_sha256: evidence.bundle.remote_server_lock_digest_sha256,
      a2a_specification_uri: A2A_SPECIFICATION_URI,
    });

    const exactReplay = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: requestBody });
    expect(exactReplay.statusCode).toBe(200);
    expect(exactReplay.json()).toEqual(resolved.json());
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

    const otherCredentialReplay = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${otherHostToken}` }, payload: requestBody });
    expect(otherCredentialReplay.statusCode).toBe(409);
    expect(otherCredentialReplay.json()).toMatchObject({ code: "route-attempt-conflict" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

    const initialWithPredecessor = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` },
      payload: { ...requestBody, predecessor_credential_revision_id: subject.credentialRevisionId } });
    expect(initialWithPredecessor.statusCode).toBe(409);
    expect(initialWithPredecessor.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

    const mismatchedReplay = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` },
      payload: { ...requestBody, intended_credential_revision_id: subject.credentialRevisionId + 999 } });
    expect(mismatchedReplay.statusCode).toBe(409);
    expect(mismatchedReplay.json()).toMatchObject({ code: "route-attempt-conflict" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

    const replayBase = {
      ...requestBody,
      operation_kind: "exact_initial_send_replay",
      route_policy_version: 1,
      route_policy_digest_sha256: replayPolicyBody.route_policy_digest_sha256,
    } as const;
    const missingPredecessor = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` },
      payload: { ...replayBase, attempt_id: "attempt-replay-missing" } });
    expect(missingPredecessor.statusCode).toBe(409);
    expect(missingPredecessor.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    const mismatchedPredecessor = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-mismatch",
        predecessor_credential_revision_id: subject.credentialRevisionId + 999,
      } });
    expect(mismatchedPredecessor.statusCode).toBe(409);
    expect(mismatchedPredecessor.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    const noPrior = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, operation_id: "operation-no-prior", attempt_id: "attempt-replay-no-prior",
        predecessor_credential_revision_id: subject.credentialRevisionId,
      } });
    expect(noPrior.statusCode).toBe(409);
    expect(noPrior.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    const crossActor = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${otherHostToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-cross-actor",
        predecessor_credential_revision_id: subject.credentialRevisionId,
      } });
    expect(crossActor.statusCode).toBe(409);
    expect(crossActor.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    const crossLineage = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-cross-lineage",
        credential_binding_id: subject.credentialBindingId + 999,
        predecessor_credential_revision_id: subject.credentialRevisionId,
      } });
    expect(crossLineage.statusCode).toBe(409);
    expect(crossLineage.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    const crossRoutePolicy = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-cross-policy", route_policy_version: 2,
        route_policy_digest_sha256: racePolicyBody.route_policy_digest_sha256,
        predecessor_credential_revision_id: subject.credentialRevisionId,
      } });
    expect(crossRoutePolicy.statusCode).toBe(409);
    expect(crossRoutePolicy.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

    const concurrentRequest = { ...requestBody, operation_id: "operation-concurrent", attempt_id: "attempt-concurrent" };
    const [concurrentLeft, concurrentRight] = await Promise.all([
      app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
        headers: { authorization: `Bearer ${actorToken}` }, payload: concurrentRequest }),
      app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
        headers: { authorization: `Bearer ${actorToken}` }, payload: concurrentRequest }),
    ]);
    expect(concurrentLeft.statusCode).toBe(200);
    expect(concurrentRight.statusCode).toBe(200);
    expect(concurrentRight.json()).toEqual(concurrentLeft.json());
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(2);

    const expiredClock = new Date(Date.parse(resolved.json().expires_at) + 1);
    const expiredReplay = await resolveRouteSnapshot(db, {
      id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route",
    }, {
      operationId: requestBody.operation_id, attemptId: requestBody.attempt_id,
      operationKind: requestBody.operation_kind, a2aMethod: requestBody.a2a_method,
      targetAgentId: requestBody.target_agent_id, interfaceUrl: requestBody.interface_url,
      agentCardDigestSha256: requestBody.agent_card_digest_sha256,
      trustKeyId: requestBody.trust_key_id, credentialBindingId: requestBody.credential_binding_id,
      callerGenerationId: requestBody.caller_generation_id,
      routePolicyVersion: requestBody.route_policy_version,
      routePolicyDigestSha256: requestBody.route_policy_digest_sha256,
      extensionUri: requestBody.extension_uri,
      extensionSpecDigestSha256: requestBody.extension_spec_digest_sha256,
      intendedCredentialRevisionId: requestBody.intended_credential_revision_id,
    }, { now: () => expiredClock });
    expect(expiredReplay).toEqual(resolved.json());
    expect(Date.parse(String(expiredReplay.expires_at))).toBeLessThan(expiredClock.getTime());
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(2);

    const rotated = await rotateCredentialBinding(db, { id: adminId, employeeCode: "admin-route" },
      subject.credentialBindingId, {
        submissionId: "rotate-after-snapshot", expectedVersion: 1, provider: "vault", externalVersion: "v2",
        secretReference: "vault://route/v2", credentialReferenceHmacKey: settings.credentialReferenceHmacKey,
      });
    const activeRevisionB = rotated.body.active_revision_id!;
    const replayB = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-b",
        intended_credential_revision_id: activeRevisionB,
        predecessor_credential_revision_id: subject.credentialRevisionId,
      } });
    expect(replayB.statusCode).toBe(200);
    expect(replayB.json()).toMatchObject({
      operation_id: requestBody.operation_id, attempt_id: "attempt-replay-b",
      operation_kind: "exact_initial_send_replay",
      predecessor_credential_revision_id: subject.credentialRevisionId,
      credential_revision_id: activeRevisionB,
    });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(3);

    const rotatedAgain = await rotateCredentialBinding(db, { id: adminId, employeeCode: "admin-route" },
      subject.credentialBindingId, {
        submissionId: "rotate-after-replay-b", expectedVersion: 2, provider: "vault", externalVersion: "v3",
        secretReference: "vault://route/v3", credentialReferenceHmacKey: settings.credentialReferenceHmacKey,
      });
    const activeRevisionC = rotatedAgain.body.active_revision_id!;
    const replayC = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-c",
        intended_credential_revision_id: activeRevisionC,
        predecessor_credential_revision_id: activeRevisionB,
      } });
    expect(replayC.statusCode).toBe(200);
    expect(replayC.json()).toMatchObject({
      attempt_id: "attempt-replay-c", predecessor_credential_revision_id: activeRevisionB,
      credential_revision_id: activeRevisionC,
    });
    const stalePredecessor = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` }, payload: {
        ...replayBase, attempt_id: "attempt-replay-stale",
        intended_credential_revision_id: activeRevisionC,
        predecessor_credential_revision_id: activeRevisionB,
      } });
    expect(stalePredecessor.statusCode).toBe(409);
    expect(stalePredecessor.json()).toMatchObject({ code: "predecessor-credential-revision-invalid" });
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);

    const mismatch = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` },
      payload: { ...requestBody, attempt_id: "attempt-mismatch", intended_credential_revision_id: subject.credentialRevisionId } });
    expect(mismatch.statusCode).toBe(409);
    expect(mismatch.json()).toMatchObject({ code: "intended-credential-revision-mismatch" });
    expect(mismatch.body).not.toContain(String(activeRevisionC));
    expect(mismatch.body).not.toContain("vault://route/v3");
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);

    const revoked = await app.inject({ method: "POST", url: `/api/v1/admin/a2a/route-policies/${policyBody.id}/revoke`,
      headers: admin, payload: { submission_id: "policy-revoke", expected_version: 1, reason: "route retired" } });
    expect(revoked.statusCode).toBe(200);
    const denied = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${actorToken}` },
      payload: { ...requestBody, attempt_id: "attempt-after-revoke", intended_credential_revision_id: activeRevisionC } });
    expect(denied.statusCode).toBe(403);
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);

    const authenticationRacePolicy = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "policy-authentication-race", target_id: subject.targetId,
        card_registry_id: subject.registryId, managed_key_revision_id: subject.keyRevisionId,
        credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "caller-generation-1", host_id: "host-1", operation_kind: "initial_send",
        interface_url: "https://runtime.example.test/a2a",
        served_spec_observation_id: evidence.servedSpecObservationId,
        extension_spec_digest_sha256: evidence.specDigest,
        wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
        wire_conformance_artifact_digest_sha256: evidence.artifactDigest, route_policy_version: 3,
      },
    });
    expect(authenticationRacePolicy.statusCode).toBe(201);
    await expect(resolveRouteSnapshot(db, {
      id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route",
    }, {
      operationId: "operation-authentication-race", attemptId: "attempt-authentication-race",
      operationKind: "initial_send", a2aMethod: "SendMessage", targetAgentId: subject.targetId,
      interfaceUrl: requestBody.interface_url, agentCardDigestSha256: subject.cardDigest,
      trustKeyId: subject.keyRevisionId, credentialBindingId: subject.credentialBindingId,
      callerGenerationId: "caller-generation-1", routePolicyVersion: 3,
      routePolicyDigestSha256: authenticationRacePolicy.json().route_policy_digest_sha256,
      extensionUri: EXTENSION_URI, extensionSpecDigestSha256: SPEC_DIGEST,
      intendedCredentialRevisionId: activeRevisionC,
    }, {
      async afterCandidateRead(tx) {
        await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE id = $2", [
          new Date().toISOString(), actor.apiKeyId,
        ]);
      },
    })).rejects.toSatisfy((error: unknown) =>
      error instanceof RouteControlError && error.code === "route-ineligible");
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);

    const expiryBoundary = new Date(Date.parse(health.json().expires_at));
    let lockWaitClock = new Date(expiryBoundary.getTime() - 1);
    let freshClockReads = 0;
    await expect(resolveRouteSnapshot(db, {
      id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route",
    }, {
      operationId: "operation-expiry-lock-wait", attemptId: "attempt-expiry-lock-wait",
      operationKind: "initial_send", a2aMethod: "SendMessage", targetAgentId: subject.targetId,
      interfaceUrl: requestBody.interface_url, agentCardDigestSha256: subject.cardDigest,
      trustKeyId: subject.keyRevisionId, credentialBindingId: subject.credentialBindingId,
      callerGenerationId: "caller-generation-1", routePolicyVersion: 3,
      routePolicyDigestSha256: authenticationRacePolicy.json().route_policy_digest_sha256,
      extensionUri: EXTENSION_URI, extensionSpecDigestSha256: SPEC_DIGEST,
      intendedCredentialRevisionId: activeRevisionC,
    }, {
      async afterCandidateRead(tx) {
        await tx.execute("UPDATE api_keys SET expires_at = $1 WHERE id = $2", [
          expiryBoundary.toISOString(), actor.apiKeyId,
        ]);
      },
      async afterEligibilityLockWait() {
        lockWaitClock = expiryBoundary;
      },
      now() {
        freshClockReads += 1;
        return lockWaitClock;
      },
    })).rejects.toSatisfy((error: unknown) =>
      error instanceof RouteControlError && error.code === "route-ineligible");
    expect(freshClockReads).toBe(1);
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);

    const healthRaceInput = {
      operationId: "operation-health-race", attemptId: "attempt-health-race",
      operationKind: "initial_send" as const, a2aMethod: "SendMessage" as const,
      targetAgentId: subject.targetId, interfaceUrl: requestBody.interface_url,
      agentCardDigestSha256: subject.cardDigest, trustKeyId: subject.keyRevisionId,
      credentialBindingId: subject.credentialBindingId, callerGenerationId: "caller-generation-1",
      routePolicyVersion: 3,
      routePolicyDigestSha256: authenticationRacePolicy.json().route_policy_digest_sha256,
      extensionUri: EXTENSION_URI, extensionSpecDigestSha256: SPEC_DIGEST,
      intendedCredentialRevisionId: activeRevisionC,
    };
    if (db.dialect === "postgres") {
      const writerDb = createDatabase(parityDatabaseUrl);
      let writerLocked!: () => void;
      let releaseWriter!: () => void;
      let resolverBeforeLock!: () => void;
      const writerLockedPromise = new Promise<void>((resolve) => { writerLocked = resolve; });
      const releaseWriterPromise = new Promise<void>((resolve) => { releaseWriter = resolve; });
      const resolverBeforeLockPromise = new Promise<void>((resolve) => { resolverBeforeLock = resolve; });
      try {
        const writer = writerDb.transaction(async (tx) => {
          await tx.query("SELECT id FROM a2a_advertised_interfaces WHERE id = $1 FOR UPDATE", [health.json().advertised_interface_id]);
          writerLocked();
          await releaseWriterPromise;
          const observedAt = new Date().toISOString();
          await tx.execute(`INSERT INTO a2a_interface_health_observations
            (advertised_interface_id, target_id, card_registry_id, interface_url, reachability,
              reason_code, evidence_sha256, observed_at, expires_at, observed_by_employee_id)
            VALUES ($1, $2, $3, $4, 'unreachable', 'concurrent-probe-failed', $5, $6, NULL, $7)`, [
            health.json().advertised_interface_id, subject.targetId, subject.registryId,
            requestBody.interface_url, "f".repeat(64), observedAt, adminId,
          ]);
        });
        await writerLockedPromise;
        const resolving = resolveRouteSnapshot(db, {
          id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route",
        }, healthRaceInput, {
          async beforeEligibilityLockWait() { resolverBeforeLock(); },
        });
        await resolverBeforeLockPromise;
        await new Promise<void>((resolve) => setTimeout(resolve, 25));
        releaseWriter();
        await writer;
        await expect(resolving).rejects.toSatisfy((error: unknown) =>
          error instanceof RouteControlError && error.code === "route-ineligible");
      } finally {
        await writerDb.close();
      }
    } else {
      await expect(resolveRouteSnapshot(db, {
        id: actorId, apiKeyId: actor.apiKeyId, employeeCode: "actor-route",
      }, healthRaceInput, {
        async afterCandidateRead(tx) {
          const observedAt = new Date().toISOString();
          await tx.execute(`INSERT INTO a2a_interface_health_observations
            (advertised_interface_id, target_id, card_registry_id, interface_url, reachability,
              reason_code, evidence_sha256, observed_at, expires_at, observed_by_employee_id)
            VALUES ($1, $2, $3, $4, 'unreachable', 'sequential-probe-failed', $5, $6, NULL, $7)`, [
            health.json().advertised_interface_id, subject.targetId, subject.registryId,
            requestBody.interface_url, "f".repeat(64), observedAt, adminId,
          ]);
        },
      })).rejects.toSatisfy((error: unknown) =>
        error instanceof RouteControlError && error.code === "route-ineligible");
    }
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(4);
    await expect(db.execute("UPDATE a2a_route_snapshot_issuance_audit SET expires_at = expires_at"))
      .rejects.toThrow(/append-only/u);
  });

  it("verifies immutable signed wire evidence and rejects every unverified lineage claim", async () => {
    const db = createDatabase(secondaryParityDatabaseUrl);
    if (db.dialect === "postgres") {
      await db.execute("DROP SCHEMA IF EXISTS public CASCADE");
      await db.execute("CREATE SCHEMA public");
    }
    const transport = new ProbeTransport();
    const app = await buildApp({
      database: db, settings,
      testOnlyDiscoveryDependencies: {
        resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 as const }]; } },
        transport,
      },
    });
    cleanups.push(async () => { await app.close(); await db.close(); });
    const adminToken = "admin-evidence-token-000000000000001";
    const actorToken = "actor-evidence-token-000000000000001";
    const adminActor = await seedActor(db, "admin-evidence", "admin", adminToken);
    const actor = await seedActor(db, "actor-evidence", "employee", actorToken);
    const subject = await seedRouteSubjects(db, adminActor.employeeId);
    const admin = { authorization: `Bearer ${adminToken}` };
    const baseline = await seedVerifiedEvidence(app, admin, subject.cardDigest, "evidence-test");
    const evidenceAudit = (await db.query<{ metadata_json: string }>(`SELECT metadata_json
      FROM a2a_route_admin_audit WHERE action = 'wire-conformance.verified' ORDER BY id DESC LIMIT 1`))[0]!;
    expect(JSON.parse(evidenceAudit.metadata_json)).toMatchObject({
      remote_server_head_sha: baseline.bundle.remote_server_head_sha,
      remote_server_lock_digest_sha256: baseline.bundle.remote_server_lock_digest_sha256,
      a2a_specification_uri: A2A_SPECIFICATION_URI,
    });

    const submitBundle = async (input: {
      submissionId: string; bundle: Record<string, unknown>;
      signerId?: number; signingKey?: typeof baseline.privateKey; rawPayload?: Buffer; signature?: Buffer;
    }) => {
      const rawPayload = input.rawPayload ?? Buffer.from(canonicalJson(input.bundle), "utf8");
      const signature = input.signature ?? signPayload(null, rawPayload, input.signingKey ?? baseline.privateKey);
      return app.inject({
        method: "POST", url: "/api/v1/admin/a2a/wire-conformance-evidence", headers: admin,
        payload: {
          submission_id: input.submissionId,
          signer_id: input.signerId ?? baseline.signerId,
          served_spec_observation_id: baseline.servedSpecObservationId,
          signed_payload_base64: rawPayload.toString("base64"),
          signature_base64: signature.toString("base64"),
        },
      });
    };

    const payloadAtBoundary = Buffer.alloc(32 * 1024, 0x20);
    const acceptedBoundary = await submitBundle({
      submissionId: "wire-payload-boundary", bundle: {}, rawPayload: payloadAtBoundary,
      signature: signPayload(null, payloadAtBoundary, baseline.privateKey),
    });
    expect(acceptedBoundary.statusCode).toBe(422);
    expect(acceptedBoundary.json()).toMatchObject({ code: "wire-evidence-invalid" });

    const payloadAboveBoundary = Buffer.alloc((32 * 1024) + 1, 0x20);
    const rejectedPayload = await submitBundle({
      submissionId: "wire-payload-above-boundary", bundle: {}, rawPayload: payloadAboveBoundary,
      signature: signPayload(null, payloadAboveBoundary, baseline.privateKey),
    });
    expect(rejectedPayload.statusCode).toBe(422);
    expect(rejectedPayload.json()).toMatchObject({ code: "invalid-request" });

    const rejectedSignature = await submitBundle({
      submissionId: "wire-signature-above-boundary", bundle: baseline.bundle,
      signature: Buffer.alloc(65, 0),
    });
    expect(rejectedSignature.statusCode).toBe(422);
    expect(rejectedSignature.json()).toMatchObject({ code: "invalid-request" });

    const nonCanonicalBundle = wireBundle(subject.cardDigest, { artifact_id: "wire-noncanonical" });
    const nonCanonicalRaw = Buffer.from(JSON.stringify(nonCanonicalBundle), "utf8");
    const nonCanonical = await submitBundle({
      submissionId: "wire-noncanonical", bundle: nonCanonicalBundle,
      rawPayload: nonCanonicalRaw, signature: signPayload(null, nonCanonicalRaw, baseline.privateKey),
    });
    expect(nonCanonical.statusCode).toBe(422);
    expect(nonCanonical.json()).toMatchObject({ code: "wire-evidence-canonicalization-invalid" });

    const missingRemoteHead = wireBundle(subject.cardDigest, { artifact_id: "wire-missing-remote-head" });
    delete (missingRemoteHead as Record<string, unknown>).remote_server_head_sha;
    const missingRemote = await submitBundle({
      submissionId: "wire-missing-remote-head", bundle: missingRemoteHead,
    });
    expect(missingRemote.statusCode).toBe(422);
    expect(missingRemote.json()).toMatchObject({ code: "wire-evidence-schema-invalid" });

    const specificationMismatch = await submitBundle({
      submissionId: "wire-a2a-specification-mismatch",
      bundle: wireBundle(subject.cardDigest, {
        artifact_id: "wire-a2a-specification-mismatch",
        a2a_specification_uri: "https://a2a-protocol.org/main/specification/",
      }),
    });
    expect(specificationMismatch.statusCode).toBe(422);
    expect(specificationMismatch.json()).toMatchObject({ code: "wire-evidence-schema-invalid" });

    const remoteLockMismatch = await submitBundle({
      submissionId: "wire-remote-lock-mismatch",
      bundle: wireBundle(subject.cardDigest, {
        artifact_id: "wire-remote-lock-mismatch", remote_server_lock_digest_sha256: "not-a-digest",
      }),
    });
    expect(remoteLockMismatch.statusCode).toBe(422);
    expect(remoteLockMismatch.json()).toMatchObject({ code: "digest-invalid" });

    const malformedTckTag = await submitBundle({
      submissionId: "wire-malformed-tck-tag",
      bundle: wireBundle(subject.cardDigest, {
        artifact_id: "wire-malformed-tck-tag", a2a_tck_tag: "1.0.0..alpha2",
      }),
    });
    expect(malformedTckTag.statusCode).toBe(422);
    expect(malformedTckTag.json()).toMatchObject({ code: "wire-evidence-tck-tag-invalid" });

    const tamperBundle = wireBundle(subject.cardDigest, { artifact_id: "wire-tamper-a" });
    const signedTamperRaw = Buffer.from(canonicalJson(tamperBundle), "utf8");
    const tamperedRaw = Buffer.from(signedTamperRaw.toString("utf8").replace("wire-tamper-a", "wire-tamper-b"));
    const tampered = await submitBundle({
      submissionId: "wire-tampered", bundle: tamperBundle, rawPayload: tamperedRaw,
      signature: signPayload(null, signedTamperRaw, baseline.privateKey),
    });
    expect(tampered.statusCode).toBe(422);
    expect(tampered.json()).toMatchObject({ code: "wire-evidence-signature-invalid" });

    const remoteTamperBundle = wireBundle(subject.cardDigest, { artifact_id: "wire-remote-head-tamper" });
    const signedRemoteRaw = Buffer.from(canonicalJson(remoteTamperBundle), "utf8");
    const tamperedRemoteRaw = Buffer.from(signedRemoteRaw.toString("utf8").replace(
      `"remote_server_head_sha":"${"7".repeat(40)}"`,
      `"remote_server_head_sha":"${"9".repeat(40)}"`,
    ));
    const tamperedRemote = await submitBundle({
      submissionId: "wire-remote-head-tamper", bundle: remoteTamperBundle, rawPayload: tamperedRemoteRaw,
      signature: signPayload(null, signedRemoteRaw, baseline.privateKey),
    });
    expect(tamperedRemote.statusCode).toBe(422);
    expect(tamperedRemote.json()).toMatchObject({ code: "wire-evidence-signature-invalid" });

    const otherKeys = generateKeyPairSync("ed25519");
    const otherSigner = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/evidence-signers", headers: admin,
      payload: {
        submission_id: "other-signer", key_id: "other-evidence-signer",
        public_key_pem: otherKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
      },
    });
    expect(otherSigner.statusCode).toBe(201);
    const wrongSigner = await submitBundle({
      submissionId: "wire-wrong-signer",
      bundle: wireBundle(subject.cardDigest, { artifact_id: "wire-wrong-signer" }),
      signerId: otherSigner.json().id,
    });
    expect(wrongSigner.statusCode).toBe(422);
    expect(wrongSigner.json()).toMatchObject({ code: "wire-evidence-signature-invalid" });

    const mutableHead = await submitBundle({
      submissionId: "wire-mutable-head",
      bundle: wireBundle(subject.cardDigest, { artifact_id: "wire-mutable-head", agent_hub_head_sha: "main" }),
    });
    expect(mutableHead.statusCode).toBe(422);
    expect(mutableHead.json()).toMatchObject({ code: "wire-evidence-head-invalid" });
    const skipped = await submitBundle({
      submissionId: "wire-skipped",
      bundle: wireBundle(subject.cardDigest, {
        artifact_id: "wire-skipped", test_vectors_passed: 39, test_vectors_skipped: 1,
      }),
    });
    expect(skipped.statusCode).toBe(422);
    expect(skipped.json()).toMatchObject({ code: "wire-evidence-not-passing" });
    const specMismatch = await submitBundle({
      submissionId: "wire-spec-mismatch",
      bundle: wireBundle(subject.cardDigest, {
        artifact_id: "wire-spec-mismatch", extension_spec_digest_sha256: "a".repeat(64),
      }),
    });
    expect(specMismatch.statusCode).toBe(409);
    expect(specMismatch.json()).toMatchObject({ code: "served-spec-lineage-mismatch" });

    const wrongCard = await submitBundle({
      submissionId: "wire-wrong-card",
      bundle: wireBundle("f".repeat(64), { artifact_id: "wire-wrong-card" }),
    });
    expect(wrongCard.statusCode).toBe(201);

    const caller = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/caller-generations", headers: admin,
      payload: {
        submission_id: "evidence-caller", caller_generation_id: "evidence-caller",
        employee_id: actor.employeeId, api_key_id: actor.apiKeyId, host_id: "evidence-host",
      },
    });
    expect(caller.statusCode).toBe(201);
    const health = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: {
        submission_id: "evidence-health", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a",
      },
    });
    expect(health.statusCode).toBe(201);
    const policyBase = {
      target_id: subject.targetId, card_registry_id: subject.registryId,
      managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
      caller_generation_id: "evidence-caller", host_id: "evidence-host", operation_kind: "initial_send",
      interface_url: "https://runtime.example.test/a2a", extension_spec_digest_sha256: SPEC_DIGEST,
      route_policy_version: 1,
    } as const;
    const arbitraryClaims = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        ...policyBase, submission_id: "arbitrary-evidence-claims",
        served_spec_observation_id: 999_999, wire_conformance_evidence_id: 999_999,
        wire_conformance_artifact_digest_sha256: "b".repeat(64),
      },
    });
    expect(arbitraryClaims.statusCode).toBe(404);
    expect(arbitraryClaims.json()).toMatchObject({ code: "route-evidence-ineligible" });
    const wrongCardPolicy = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        ...policyBase, submission_id: "wrong-card-evidence-policy",
        served_spec_observation_id: baseline.servedSpecObservationId,
        wire_conformance_evidence_id: wrongCard.json().id,
        wire_conformance_artifact_digest_sha256: wrongCard.json().artifact_digest_sha256,
      },
    });
    expect(wrongCardPolicy.statusCode).toBe(422);
    expect(wrongCardPolicy.json()).toMatchObject({ code: "wire-evidence-card-mismatch" });

    const policy = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        ...policyBase, submission_id: "verified-evidence-policy",
        served_spec_observation_id: baseline.servedSpecObservationId,
        wire_conformance_evidence_id: baseline.wireConformanceEvidenceId,
        wire_conformance_artifact_digest_sha256: baseline.artifactDigest,
      },
    });
    expect(policy.statusCode).toBe(201);
    const revokedWire = await app.inject({
      method: "POST", url: `/api/v1/admin/a2a/wire-conformance-evidence/${baseline.wireConformanceEvidenceId}/revoke`,
      headers: admin, payload: { submission_id: "revoke-wire-evidence", reason: "superseded test evidence" },
    });
    expect(revokedWire.statusCode).toBe(200);
    const denied = await app.inject({
      method: "POST", url: "/api/v1/a2a/routes/resolve", headers: { authorization: `Bearer ${actorToken}` },
      payload: {
        operation_id: "evidence-operation", attempt_id: "evidence-attempt", operation_kind: "initial_send",
        a2a_method: "SendMessage", target_agent_id: subject.targetId,
        interface_url: "https://runtime.example.test/a2a", agent_card_digest_sha256: subject.cardDigest,
        trust_key_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "evidence-caller", route_policy_version: 1,
        route_policy_digest_sha256: policy.json().route_policy_digest_sha256,
        extension_uri: EXTENSION_URI, extension_spec_digest_sha256: SPEC_DIGEST,
        intended_credential_revision_id: subject.credentialRevisionId,
      },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({ code: "route-ineligible" });

    const revokedSigner = await app.inject({
      method: "POST", url: `/api/v1/admin/a2a/evidence-signers/${baseline.signerId}/revoke`, headers: admin,
      payload: { submission_id: "revoke-evidence-signer", reason: "signer retired" },
    });
    expect(revokedSigner.statusCode).toBe(200);
    const afterSignerRevoke = await submitBundle({
      submissionId: "wire-after-signer-revoke",
      bundle: wireBundle(subject.cardDigest, { artifact_id: "wire-after-signer-revoke" }),
    });
    expect(afterSignerRevoke.statusCode).toBe(404);
    expect(afterSignerRevoke.json()).toMatchObject({ code: "evidence-signer-not-active" });
    const revokedSpec = await app.inject({
      method: "POST", url: `/api/v1/admin/a2a/served-spec-observations/${baseline.servedSpecObservationId}/revoke`,
      headers: admin, payload: { submission_id: "revoke-served-spec", reason: "spec superseded" },
    });
    expect(revokedSpec.statusCode).toBe(200);
    await expect(db.execute("UPDATE a2a_wire_conformance_evidence SET artifact_id = artifact_id"))
      .rejects.toThrow(/append-only/u);
    await expect(db.execute("UPDATE a2a_evidence_signers SET key_id = key_id"))
      .rejects.toThrow(/append-only/u);
    expect(await db.query("SELECT issuance_sequence FROM a2a_route_snapshot_issuance_audit")).toHaveLength(0);
  });

  it("rejects any additional required extension while ignoring unrelated optional extensions", async () => {
    const db = createDatabase(secondaryParityDatabaseUrl);
    if (db.dialect === "postgres") {
      await db.execute("DROP SCHEMA IF EXISTS public CASCADE");
      await db.execute("CREATE SCHEMA public");
    }
    const app = await buildApp({
      database: db, settings,
      testOnlyDiscoveryDependencies: {
        resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 as const }]; } },
        transport: new ProbeTransport(),
      },
    });
    cleanups.push(async () => { await app.close(); await db.close(); });
    const adminToken = "admin-required-extension-token-000001";
    const actorToken = "actor-required-extension-token-000001";
    const adminActor = await seedActor(db, "admin-required-extension", "admin", adminToken);
    const actor = await seedActor(db, "actor-required-extension", "employee", actorToken);
    const subject = await seedRouteSubjects(db, adminActor.employeeId, routeCard(true));
    const admin = { authorization: `Bearer ${adminToken}` };
    const evidence = await seedVerifiedEvidence(app, admin, subject.cardDigest, "required-extension");
    expect((await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/caller-generations", headers: admin,
      payload: {
        submission_id: "required-extension-caller", caller_generation_id: "required-extension-caller",
        employee_id: actor.employeeId, api_key_id: actor.apiKeyId, host_id: "required-extension-host",
      },
    })).statusCode).toBe(201);
    expect((await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: {
        submission_id: "required-extension-health", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a",
      },
    })).statusCode).toBe(201);
    const rejected = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "required-extension-policy", target_id: subject.targetId,
        card_registry_id: subject.registryId, managed_key_revision_id: subject.keyRevisionId,
        credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "required-extension-caller", host_id: "required-extension-host",
        operation_kind: "initial_send", interface_url: "https://runtime.example.test/a2a",
        served_spec_observation_id: evidence.servedSpecObservationId,
        extension_spec_digest_sha256: evidence.specDigest,
        wire_conformance_evidence_id: evidence.wireConformanceEvidenceId,
        wire_conformance_artifact_digest_sha256: evidence.artifactDigest, route_policy_version: 1,
      },
    });
    expect(rejected.statusCode).toBe(422);
    expect(rejected.json()).toMatchObject({ code: "extension-contract-ineligible" });
  });

  it("authenticates before strict raw parsing and rejects duplicate keys with no-store errors", async () => {
    const db = createDatabase(secondaryParityDatabaseUrl);
    if (db.dialect === "postgres") {
      await db.execute("DROP SCHEMA IF EXISTS public CASCADE");
      await db.execute("CREATE SCHEMA public");
    }
    const app = await buildApp({ database: db, settings });
    cleanups.push(async () => { await app.close(); await db.close(); });
    const token = "duplicate-route-token-00000000000001";
    await seedActor(db, "duplicate-route", "employee", token);
    const duplicate = '{"operation_id":"first","operation_id":"second"}';
    const unauthorized = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { "content-type": "application/json" }, payload: duplicate });
    expect(unauthorized.statusCode).toBe(401);
    expect(unauthorized.headers["cache-control"]).toBe("no-store, max-age=0");
    const rejected = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, payload: duplicate });
    expect(rejected.statusCode).toBe(400);
    expect(rejected.headers["cache-control"]).toBe("no-store, max-age=0");
    const ordinaryDuplicate = await app.inject({
      method: "POST", url: "/api/v1/network/discussions",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      payload: '{"title":"first","title":"second","body":"ordinary body","tags":[]}',
    });
    expect(ordinaryDuplicate.statusCode).toBe(201);
    expect(ordinaryDuplicate.json()).toMatchObject({ title: "second" });
    const oversizedRouteBody = `{"operation_id":"first","padding":"${"x".repeat(66 * 1024)}"}`;
    const oversizedRoute = await app.inject({
      method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      payload: oversizedRouteBody,
    });
    expect(oversizedRoute.statusCode).toBe(400);
    const oversizedOrdinary = await app.inject({
      method: "POST", url: "/api/v1/network/discussions",
      headers: { authorization: `Bearer ${token}` },
      payload: { title: "large ordinary request", body: "x".repeat(66 * 1024), tags: [] },
    });
    expect(oversizedOrdinary.statusCode).toBe(422);
    const nestedDuplicate = '{"operation_id":"first","extra":{"value":1,"value":2}}';
    const nested = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, payload: nestedDuplicate });
    expect(nested.statusCode).toBe(400);
    const unknown = await app.inject({ method: "POST", url: "/api/v1/a2a/routes/resolve",
      headers: { authorization: `Bearer ${token}` }, payload: { unknown_field: true } });
    expect(unknown.statusCode).toBe(422);
    expect(unknown.json()).toMatchObject({ code: "invalid-request" });
    expect(unknown.headers["cache-control"]).toBe("no-store, max-age=0");
  });

  it("marks an early route-control rate-limit response as non-cacheable", async () => {
    const db = createDatabase(secondaryParityDatabaseUrl);
    if (db.dialect === "postgres") {
      await db.execute("DROP SCHEMA IF EXISTS public CASCADE");
      await db.execute("CREATE SCHEMA public");
    }
    const app = await buildApp({
      database: db,
      settings: { ...settings, rateLimitPerIpPerMinute: 1 },
    });
    cleanups.push(async () => { await app.close(); await db.close(); });
    const token = "rate-limited-route-admin-token-000001";
    await seedActor(db, "rate-limited-route-admin", "admin", token);
    const headers = { authorization: `Bearer ${token}` };
    const first = await app.inject({ method: "GET", url: "/api/v1/admin/a2a/caller-generations", headers });
    expect(first.statusCode).toBe(200);
    const limited = await app.inject({ method: "GET", url: "/api/v1/admin/a2a/caller-generations", headers });
    expect(limited.statusCode).toBe(429);
    expect(limited.headers["cache-control"]).toBe("no-store, max-age=0");
    expect(limited.headers.pragma).toBe("no-cache");
  });
});
