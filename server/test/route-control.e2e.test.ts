import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { prepareAgentCardDocument } from "../src/a2a/agent-card-registry.js";
import type {
  DiscoveryTransport,
  DiscoveryTransportRequest,
  DiscoveryTransportResponse,
} from "../src/a2a/discovery-egress.js";
import { createCredentialBinding, rotateCredentialBinding } from "../src/a2a/discovery-store.js";
import { resolveRouteSnapshot, RouteControlError } from "../src/a2a/route-control-store.js";
import type { Settings } from "../src/config.js";
import { asNumber, createDatabase, type SqlDatabase } from "../src/db.js";

const EXTENSION_URI = "https://lvis.ai/a2a/extensions/exact-send-replay/v1";
const SPEC_DIGEST = "a".repeat(64);
const WIRE_DIGEST = "b".repeat(64);
const parityDatabaseUrl = process.env.AGENT_HUB_P4_5_DATABASE_URL ?? "sqlite://:memory:";
const settings: Settings = {
  databaseUrl: "sqlite://:memory:", host: "127.0.0.1", port: 8000, logLevel: "silent",
  rateLimitPerIpPerMinute: 10_000, signupRateLimitPerIpPerMinute: 10_000,
  trustedProxyIps: [], corsOrigins: ["http://localhost:5173"], tlsHstsMaxAge: 0,
  credentialReferenceHmacKey: "test-only-credential-reference-key-0001",
};

class ProbeTransport implements DiscoveryTransport {
  readonly inputs: DiscoveryTransportRequest[] = [];
  async request(input: DiscoveryTransportRequest): Promise<DiscoveryTransportResponse> {
    this.inputs.push(input);
    return { statusCode: 401, headers: { "content-type": "application/json" }, body: Buffer.from("{}") };
  }
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

function routeCard() {
  return {
    name: "Remote Agent", description: "P4-5 route fixture.", version: "1.0.0",
    capabilities: {
      streaming: false, pushNotifications: false, extendedAgentCard: false,
      extensions: [{
        uri: EXTENSION_URI,
        description: "Durable exact replay for ambiguous non-streaming SendMessage responses.",
        required: false,
        params: {
          profile: "lvis-exact-send-replay", profileVersion: "1",
          requestBody: "exact-serialized-jsonrpc", resultRetentionSeconds: "604800",
          specDigestSha256: SPEC_DIGEST,
        },
      }],
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

async function seedRouteSubjects(db: SqlDatabase, adminId: number) {
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
  const prepared = prepareAgentCardDocument(routeCard());
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
    const health = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/advertised-interfaces/probe", headers: admin,
      payload: { submission_id: "interface-probe", target_id: subject.targetId,
        card_registry_id: subject.registryId, interface_url: "https://runtime.example.test/a2a" } });
    expect(health.statusCode).toBe(201);
    expect(health.json()).toMatchObject({ reachability: "healthy", reason_code: "interface-reachable" });
    expect(transport.inputs).toHaveLength(1);
    expect(transport.inputs[0]).toMatchObject({ pinnedAddress: { address: "8.8.8.8", family: 4 } });
    expect(transport.inputs[0]!.headers).not.toHaveProperty("Authorization");

    const policy = await app.inject({ method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "policy-provision", target_id: subject.targetId, card_registry_id: subject.registryId,
        managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "caller-generation-1", host_id: "host-1", operation_kind: "initial_send",
        interface_url: "https://runtime.example.test/a2a", extension_spec_digest_sha256: SPEC_DIGEST,
        wire_conformance_artifact_id: "wire-artifact-1",
        wire_conformance_artifact_digest_sha256: WIRE_DIGEST, route_policy_version: 1,
      } });
    expect(policy.statusCode).toBe(201);
    const policyBody = policy.json();
    expect(policyBody).toMatchObject({
      wire_conformance_artifact_id: "wire-artifact-1",
      wire_conformance_artifact_digest_sha256: WIRE_DIGEST,
    });
    expect(policyBody).not.toHaveProperty("wire_conformance_digest_sha256");
    const policyList = await app.inject({
      method: "GET", url: "/api/v1/admin/a2a/route-policies", headers: admin,
    });
    expect(policyList.statusCode).toBe(200);
    expect(policyList.json().items[0]).toMatchObject({
      wire_conformance_artifact_id: "wire-artifact-1",
      wire_conformance_artifact_digest_sha256: WIRE_DIGEST,
    });
    expect(policyList.json().items[0]).not.toHaveProperty("wire_conformance_digest_sha256");
    const replayPolicy = await app.inject({
      method: "POST", url: "/api/v1/admin/a2a/route-policies", headers: admin,
      payload: {
        submission_id: "policy-replay", target_id: subject.targetId, card_registry_id: subject.registryId,
        managed_key_revision_id: subject.keyRevisionId, credential_binding_id: subject.credentialBindingId,
        caller_generation_id: "caller-generation-1", host_id: "host-1",
        operation_kind: "exact_initial_send_replay",
        interface_url: "https://runtime.example.test/a2a", extension_spec_digest_sha256: SPEC_DIGEST,
        wire_conformance_artifact_id: "wire-artifact-1",
        wire_conformance_artifact_digest_sha256: WIRE_DIGEST, route_policy_version: 1,
      },
    });
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
        interface_url: "https://runtime.example.test/a2a", extension_spec_digest_sha256: SPEC_DIGEST,
        wire_conformance_artifact_id: "wire-artifact-race",
        wire_conformance_artifact_digest_sha256: WIRE_DIGEST, route_policy_version: 2,
      } });
    expect(racePolicy.statusCode).toBe(201);
    const racePolicyBody = racePolicy.json();
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
      wire_conformance_artifact_id: "wire-artifact-1",
      wire_conformance_artifact_digest_sha256: WIRE_DIGEST,
    }));
    const serialized = resolved.body;
    expect(serialized).not.toContain("vault://route/v1");
    expect(serialized).not.toContain("secret_reference");
    expect(await db.query("SELECT * FROM a2a_route_snapshot_issuance_audit")).toHaveLength(1);

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
        interface_url: "https://runtime.example.test/a2a", extension_spec_digest_sha256: SPEC_DIGEST,
        wire_conformance_artifact_id: "wire-artifact-authentication-race",
        wire_conformance_artifact_digest_sha256: WIRE_DIGEST, route_policy_version: 3,
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

  it("authenticates before strict raw parsing and rejects duplicate keys with no-store errors", async () => {
    const db = createDatabase(parityDatabaseUrl);
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
});
