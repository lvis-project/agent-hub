import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { canonicalizeAgentCardPayload } from "../src/a2a/agent-card-registry.js";
import { createTrustAnchor } from "../src/a2a/agent-card-store.js";
import {
  DiscoveryBoundaryError,
  type DiscoveryTransport,
  type DiscoveryTransportRequest,
  type DiscoveryTransportResponse,
} from "../src/a2a/discovery-egress.js";
import {
  claimRevalidation,
  completeDiscoveryFailure,
  completeDiscoveryPersistenceFailure,
} from "../src/a2a/discovery-store.js";
import type { Settings } from "../src/config.js";
import { asBuffer, asNumber, asString, createDatabase, type SqlDatabase } from "../src/db.js";

const postgresUrl = process.env.AGENT_HUB_TEST_POSTGRES_URL;
const describePostgres = postgresUrl === undefined ? describe.skip : describe;

type Enrollment = { token: string; employeeCode: string };

type DiscoveryTransportStep = DiscoveryTransportResponse | Error |
  ((input: DiscoveryTransportRequest) => DiscoveryTransportResponse | Promise<DiscoveryTransportResponse>);

class PgScriptedTransport implements DiscoveryTransport {
  readonly inputs: DiscoveryTransportRequest[] = [];
  constructor(readonly steps: DiscoveryTransportStep[]) {}
  async request(input: DiscoveryTransportRequest): Promise<DiscoveryTransportResponse> {
    this.inputs.push(input);
    const step = this.steps.shift();
    if (step === undefined) throw new Error("Unexpected PostgreSQL discovery request");
    if (step instanceof Error) throw step;
    return typeof step === "function" ? step(input) : step;
  }
}

function discoveryResponse(
  body: Buffer | string,
  overrides: Partial<DiscoveryTransportResponse> = {},
): DiscoveryTransportResponse {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json", "cache-control": "max-age=60" },
    body: typeof body === "string" ? Buffer.from(body) : Buffer.from(body),
    ...overrides,
  };
}

async function enroll(app: Awaited<ReturnType<typeof buildApp>>, displayName: string): Promise<Enrollment> {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const publicAddress = `ah1_${createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 40)}`;
  const challenge = await app.inject({ method: "POST", url: "/api/v1/auth/signup/challenge", payload: { public_address: publicAddress, public_key_pem: publicKey, display_name: displayName } });
  expect(challenge.statusCode).toBe(201);
  const challengeBody = challenge.json() as { challenge_id: string; message: string };
  const signature = sign("sha256", Buffer.from(challengeBody.message), pair.privateKey).toString("base64url");
  const complete = await app.inject({ method: "POST", url: "/api/v1/auth/signup", payload: { challenge_id: challengeBody.challenge_id, public_address: publicAddress, public_key_pem: publicKey, signature } });
  expect(complete.statusCode).toBe(201);
  const result = complete.json() as { access_token: string; employee_code: string };
  return { token: result.access_token, employeeCode: result.employee_code };
}

async function createPost(app: Awaited<ReturnType<typeof buildApp>>, token: string, path: "discussions" | "issues") {
  const response = await app.inject({
    method: "POST",
    url: `/api/v1/network/${path}`,
    headers: { authorization: `Bearer ${token}` },
    payload: { title: `Concurrent ${path}`, body: "This body creates contribution tokens for integrity checks.", tags: ["concurrency"] },
  });
  expect(response.statusCode).toBe(201);
  return (response.json() as { id: number }).id;
}

async function enrollAdmin(app: Awaited<ReturnType<typeof buildApp>>, db: SqlDatabase, displayName: string): Promise<Enrollment> {
  const enrollment = await enroll(app, displayName);
  await db.execute("UPDATE api_keys SET role = 'admin' WHERE key_hash = $1", [createHash("sha256").update(enrollment.token).digest("hex")]);
  return enrollment;
}

function agentCardSigner(keyId: string) {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    keyId,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    signCard(value: Record<string, unknown>) {
      const payload = canonicalizeAgentCardPayload(value);
      const protectedHeader = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JOSE" })).toString("base64url");
      value.signatures = [{
        protected: protectedHeader,
        signature: sign("sha256", Buffer.from(`${protectedHeader}.${payload.toString("base64url")}`, "ascii"), {
          key: pair.privateKey, dsaEncoding: "ieee-p1363",
        }).toString("base64url"),
      }];
    },
  };
}

function agentCard(version: string, preferredInterface = "https://pg-agent.example.test/a2a"): Record<string, unknown> {
  return {
    name: "PostgreSQL Work Assistant", description: "A concurrency-test Agent Card.", version,
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    skills: [{ id: "delegate", name: "Delegate", description: "Delegate bounded work.", tags: ["test"] }],
    supportedInterfaces: [{ url: preferredInterface, protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"],
    securitySchemes: { bearerAuth: { httpAuthSecurityScheme: { scheme: "bearer" } } },
    securityRequirements: [{ schemes: { bearerAuth: { list: [] } } }],
  };
}

function signedDiscoveryFixture(keyId = "pg-managed-key", jku = "https://pg-discovery.example/keys.jwks") {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const value = agentCard("discovered-signed", "https://pg-runtime.example/a2a");
  const protectedHeader = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JOSE", jku })).toString("base64url");
  const payload = canonicalizeAgentCardPayload(value);
  value.signatures = [{
    protected: protectedHeader,
    signature: sign("sha256", Buffer.from(`${protectedHeader}.${payload.toString("base64url")}`, "ascii"), {
      key: pair.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url"),
  }];
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  return {
    card: value,
    jwks: { keys: [{ ...publicJwk, kid: keyId, alg: "ES256", use: "sig", key_ops: ["verify"] }] },
  };
}

async function createAgentCardAnchor(app: Awaited<ReturnType<typeof buildApp>>, token: string, signer: ReturnType<typeof agentCardSigner>) {
  const response = await app.inject({
    method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: { authorization: `Bearer ${token}` },
    payload: { submission_id: `anchor-${signer.keyId}`, key_id: signer.keyId, algorithm: "ES256", public_key_pem: signer.publicKeyPem },
  });
  expect(response.statusCode).toBe(201);
  return response.json() as { id: number; row_version: number };
}

async function importAgentCard(app: Awaited<ReturnType<typeof buildApp>>, token: string, value: unknown, submissionId: string) {
  const response = await app.inject({
    method: "POST", url: "/api/v1/admin/a2a/cards/import", headers: { authorization: `Bearer ${token}` },
    payload: { submission_id: submissionId, card: value, provenance: { kind: "api", source: "postgres-concurrency" } },
  });
  expect(response.statusCode).toBe(201);
  return response.json() as { card: { id: number }; admission: { trust_state: string } };
}

async function createDiscoveryTarget(
  app: Awaited<ReturnType<typeof buildApp>>,
  token: string,
  submissionId: string,
  origin: string,
) {
  return app.inject({
    method: "POST", url: "/api/v1/admin/a2a/discovery-targets",
    headers: { authorization: `Bearer ${token}` },
    payload: { submission_id: submissionId, origin },
  });
}

describePostgres("PostgreSQL concurrency contracts", () => {
  let primaryDb: SqlDatabase;
  let secondaryDb: SqlDatabase;
  let primaryApp: Awaited<ReturnType<typeof buildApp>>;
  let secondaryApp: Awaited<ReturnType<typeof buildApp>>;
  const settings: Settings = {
    databaseUrl: postgresUrl ?? "postgresql://unused",
    postgresTls: { mode: "disabled", caFile: null },
    host: "127.0.0.1",
    port: 8000,
    logLevel: "silent",
    rateLimitPerIpPerMinute: 1_000,
    signupRateLimitPerIpPerMinute: 1_000,
    trustedProxyIps: [],
    corsOrigins: ["http://localhost:5174"],
    tlsHstsMaxAge: 0,
    credentialReferenceHmacKey: "test-only-credential-reference-key-0001",
  };

  async function buildPgDiscoveryApp(transport: DiscoveryTransport) {
    return buildApp({
      database: primaryDb,
      settings,
      migrate: false,
      testOnlyDiscoveryDependencies: {
        transport,
        resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 }]; } },
      },
    });
  }

  async function revalidatePg(
    app: Awaited<ReturnType<typeof buildApp>>,
    token: string,
    targetId: number,
    submissionId: string,
  ) {
    return app.inject({
      method: "POST",
      url: `/api/v1/admin/a2a/discovery-targets/${targetId}/revalidate`,
      headers: { authorization: `Bearer ${token}` },
      payload: { submission_id: submissionId, expected_version: 1 },
    });
  }

  beforeAll(async () => {
    primaryDb = createDatabase(postgresUrl!);
    secondaryDb = createDatabase(postgresUrl!);
    [primaryApp, secondaryApp] = await Promise.all([
      buildApp({ database: primaryDb, settings }),
      buildApp({ database: secondaryDb, settings }),
    ]);
  });

  beforeEach(async () => {
    await primaryDb.execute(`TRUNCATE TABLE a2a_g003_audit, a2a_discovery_health,
      a2a_discovery_attempts, a2a_discovery_cache_entries, a2a_discovery_documents,
      a2a_credential_active_revisions, a2a_credential_revisions, a2a_credential_bindings, a2a_managed_key_revisions,
      a2a_managed_key_sources, a2a_admin_operations, a2a_discovery_targets, a2a_principals,
      a2a_mutation_submissions, a2a_registry_audit,
      a2a_card_verifications, a2a_card_observations, a2a_card_registry, a2a_card_documents,
      a2a_trust_anchors, network_votes, network_comments, network_posts, api_keys,
      agent_identities, employees, departments, signup_challenges RESTART IDENTITY CASCADE`);
    await primaryDb.execute(`INSERT INTO a2a_principals (kind, employee_id, system_name, created_at)
      VALUES ('system', NULL, 'g003-discovery', $1)`, [new Date().toISOString()]);
  });

  afterAll(async () => {
    if (primaryApp !== undefined) await primaryApp.close();
    if (secondaryApp !== undefined) await secondaryApp.close();
    if (primaryDb !== undefined) await primaryDb.close();
    if (secondaryDb !== undefined) await secondaryDb.close();
  });

  it("permits exactly one concurrent issue claimant", async () => {
    const owner = await enroll(primaryApp, "Issue owner");
    const firstClaimant = await enroll(primaryApp, "First claimant");
    const secondClaimant = await enroll(secondaryApp, "Second claimant");
    const issueId = await createPost(primaryApp, owner.token, "issues");
    const responses = await Promise.all([
      primaryApp.inject({ method: "POST", url: `/api/v1/network/issues/${issueId}/claim`, headers: { authorization: `Bearer ${firstClaimant.token}` } }),
      secondaryApp.inject({ method: "POST", url: `/api/v1/network/issues/${issueId}/claim`, headers: { authorization: `Bearer ${secondClaimant.token}` } }),
    ]);
    expect(responses.map((response) => response.statusCode).sort((left, right) => left - right)).toEqual([200, 409]);
  });

  it("uses one cross-phase employee submission namespace in PostgreSQL", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Cross-phase admin");
    const signer = agentCardSigner("pg-cross-phase-key");
    const anchor = await primaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors",
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        submission_id: "pg-cross-phase-p4-first", key_id: signer.keyId,
        algorithm: "ES256", public_key_pem: signer.publicKeyPem,
      },
    });
    expect(anchor.statusCode).toBe(201);
    const g003Loser = await createDiscoveryTarget(
      secondaryApp, admin.token, "pg-cross-phase-p4-first", "https://pg-cross-one.example",
    );
    expect(g003Loser.statusCode).toBe(409);
    expect(g003Loser.json()).toMatchObject({ code: "submission-mismatch" });
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_admin_operations",
    ))[0]!.count)).toBe(0);

    const g003First = await createDiscoveryTarget(
      primaryApp, admin.token, "pg-cross-phase-g003-first", "https://pg-cross-two.example",
    );
    expect(g003First.statusCode).toBe(201);
    const p4Loser = await secondaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors",
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        submission_id: "pg-cross-phase-g003-first", key_id: "pg-cross-phase-loser",
        algorithm: "ES256", public_key_pem: signer.publicKeyPem,
      },
    });
    expect(p4Loser.statusCode).toBe(409);
    expect(p4Loser.json()).toMatchObject({ code: "submission-mismatch" });
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_mutation_submissions",
    ))[0]!.count)).toBe(2);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_discovery_targets",
    ))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_trust_anchors",
    ))[0]!.count)).toBe(1);
  });

  it("linearizes distinct target creation and discovery claims in PostgreSQL", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Discovery concurrency admin");
    const targetCreates = await Promise.all([
      createDiscoveryTarget(primaryApp, admin.token, "pg-target-create-a", "https://pg-race.example"),
      createDiscoveryTarget(secondaryApp, admin.token, "pg-target-create-b", "https://PG-RACE.example."),
    ]);
    expect(targetCreates.map((response) => response.statusCode).sort((a, b) => a - b)).toEqual([201, 409]);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_discovery_targets",
    ))[0]!.count)).toBe(1);
    const targetId = (targetCreates.find((response) => response.statusCode === 201)!.json() as { id: number }).id;
    const employee = (await primaryDb.query<{ id: unknown }>(
      "SELECT id FROM employees WHERE employee_code = $1", [admin.employeeCode],
    ))[0]!;
    const actor = { id: asNumber(employee.id), employeeCode: admin.employeeCode };
    const claims = await Promise.all([
      claimRevalidation(primaryDb, actor, {
        targetId, submissionId: "pg-discovery-claim-a", expectedVersion: 1, nowMs: Date.parse("2026-07-16T05:00:00.000Z"),
      }),
      claimRevalidation(secondaryDb, actor, {
        targetId, submissionId: "pg-discovery-claim-b", expectedVersion: 1, nowMs: Date.parse("2026-07-16T05:00:00.000Z"),
      }),
    ]);
    expect(claims.filter((result) => result.claim !== null)).toHaveLength(1);
    expect(claims.filter((result) => result.replay?.status === 409)).toHaveLength(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(`SELECT COUNT(*) AS count
      FROM a2a_admin_operations WHERE operation_kind = 'discovery.revalidate' AND state = 'running'`))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_discovery_attempts",
    ))[0]!.count)).toBe(0);
  });

  it("stores exact BOM-prefixed BYTEA, hashes raw bytes, reuses them on 304, and atomically imports P4-2 state", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG byte cache admin");
    const raw = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(agentCard("pg-byte-cache")))]);
    const rawHash = createHash("sha256").update(raw).digest("hex");
    const transport = new PgScriptedTransport([
      discoveryResponse(raw, {
        headers: { "content-type": "application/json", "cache-control": "max-age=60", etag: '"pg-byte-v1"' },
      }),
      (input) => {
        expect(input.headers["If-None-Match"]).toBe('"pg-byte-v1"');
        return discoveryResponse(Buffer.alloc(0), {
          statusCode: 304,
          headers: { "cache-control": "max-age=120", etag: '"pg-byte-v1"' },
        });
      },
    ]);
    const app = await buildPgDiscoveryApp(transport);
    try {
      const targetResponse = await createDiscoveryTarget(app, admin.token, "pg-byte-target", "https://pg-byte.example");
      expect(targetResponse.statusCode).toBe(201);
      const target = targetResponse.json() as { id: number };
      const first = await revalidatePg(app, admin.token, target.id, "pg-byte-200");
      expect(first.statusCode, first.body).toBe(200);
      expect(first.json()).toMatchObject({ outcome: "succeeded", card_sha256: rawHash, routable: false });
      const stored = (await primaryDb.query<{ body_blob: unknown; body_sha256: unknown }>(
        "SELECT body_blob, body_sha256 FROM a2a_discovery_documents WHERE target_id = $1 AND kind = 'agent-card'",
        [target.id],
      ))[0]!;
      expect(asBuffer(stored.body_blob)).toEqual(raw);
      expect(asString(stored.body_sha256)).toBe(rawHash);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_card_registry",
      ))[0]!.count)).toBe(1);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE operation = 'agent-card.import'",
      ))[0]!.count)).toBe(1);

      const second = await revalidatePg(app, admin.token, target.id, "pg-byte-304");
      expect(second.statusCode, second.body).toBe(200);
      expect(second.json()).toMatchObject({ outcome: "not_modified", card_sha256: rawHash, routable: false });
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_discovery_documents",
      ))[0]!.count)).toBe(1);
      const attemptHashes = await primaryDb.query<{ card_sha256: unknown }>(
        "SELECT card_sha256 FROM a2a_discovery_attempts ORDER BY id",
      );
      expect(attemptHashes.map((row) => asString(row.card_sha256))).toEqual([rawHash, rawHash]);
      expect(transport.inputs).toHaveLength(2);
    } finally {
      await app.close();
    }
  });

  it("keeps no-store discovery bytes and validators out of PostgreSQL while committing P4-2 business state", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG no-store admin");
    const transport = new PgScriptedTransport([
      discoveryResponse(JSON.stringify(agentCard("pg-no-store")), {
        headers: {
          "content-type": "application/json", "cache-control": "no-store",
          etag: '"must-not-persist"', "last-modified": "Wed, 16 Jul 2026 00:00:00 GMT",
        },
      }),
    ]);
    const app = await buildPgDiscoveryApp(transport);
    try {
      const targetResponse = await createDiscoveryTarget(app, admin.token, "pg-no-store-target", "https://pg-no-store.example");
      const target = targetResponse.json() as { id: number };
      const result = await revalidatePg(app, admin.token, target.id, "pg-no-store-discovery");
      expect(result.statusCode, result.body).toBe(200);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_discovery_documents",
      ))[0]!.count)).toBe(0);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_discovery_cache_entries",
      ))[0]!.count)).toBe(0);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_card_registry",
      ))[0]!.count)).toBe(1);
      const persisted = JSON.stringify(await primaryDb.query(
        "SELECT response_json FROM a2a_admin_operations WHERE submission_id = 'pg-no-store-discovery'",
      ));
      expect(persisted).not.toContain("must-not-persist");
      expect(persisted).not.toContain("Wed, 16 Jul 2026");
    } finally {
      await app.close();
    }
  });

  it("fails a PostgreSQL 304 cache hit closed when immutable cached bytes are tampered", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG cache tamper admin");
    const transport = new PgScriptedTransport([
      discoveryResponse(JSON.stringify(agentCard("pg-cache-tamper")), {
        headers: { "content-type": "application/json", "cache-control": "max-age=60", etag: '"pg-tamper-v1"' },
      }),
      discoveryResponse(Buffer.alloc(0), {
        statusCode: 304,
        headers: { "cache-control": "max-age=120", etag: '"pg-tamper-v1"' },
      }),
    ]);
    const app = await buildPgDiscoveryApp(transport);
    try {
      const targetResponse = await createDiscoveryTarget(app, admin.token, "pg-tamper-target", "https://pg-tamper.example");
      const target = targetResponse.json() as { id: number };
      expect((await revalidatePg(app, admin.token, target.id, "pg-tamper-200")).statusCode).toBe(200);
      await primaryDb.execute("DROP TRIGGER a2a_discovery_documents_append_only ON a2a_discovery_documents");
      try {
        await primaryDb.execute("UPDATE a2a_discovery_documents SET body_blob = $1 WHERE target_id = $2", [
          Buffer.from("{}"), target.id,
        ]);
        const tampered = await revalidatePg(app, admin.token, target.id, "pg-tamper-304");
        expect(tampered.statusCode).toBe(502);
        expect(tampered.json()).toMatchObject({ code: "cache-miss", routable: false });
        expect(asNumber((await primaryDb.query<{ count: unknown }>(
          "SELECT COUNT(*) AS count FROM a2a_discovery_attempts",
        ))[0]!.count)).toBe(1);
        expect(asNumber((await primaryDb.query<{ count: unknown }>(
          "SELECT COUNT(*) AS count FROM a2a_discovery_health",
        ))[0]!.count)).toBe(1);
      } finally {
        await primaryDb.execute(`CREATE TRIGGER a2a_discovery_documents_append_only
          BEFORE UPDATE OR DELETE ON a2a_discovery_documents
          FOR EACH ROW EXECUTE FUNCTION reject_a2a_g003_append_only_mutation()`);
      }
    } finally {
      await app.close();
    }
  });

  it("recovers an expired PostgreSQL lease, fences the late owner, and terminalizes persistence failure", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG recovery admin");
    const employee = (await primaryDb.query<{ id: unknown }>(
      "SELECT id FROM employees WHERE employee_code = $1", [admin.employeeCode],
    ))[0]!;
    const actor = { id: asNumber(employee.id), employeeCode: admin.employeeCode };
    const firstTarget = (await createDiscoveryTarget(
      primaryApp, admin.token, "pg-recovery-target", "https://pg-recovery.example",
    )).json() as { id: number };
    const startedAt = Date.parse("2026-07-16T08:00:00.000Z");
    const original = await claimRevalidation(primaryDb, actor, {
      targetId: firstTarget.id, submissionId: "pg-expired-owner", expectedVersion: 1, nowMs: startedAt,
    });
    expect(original.claim).not.toBeNull();
    const recovered = await claimRevalidation(secondaryDb, actor, {
      targetId: firstTarget.id, submissionId: "pg-expired-owner", expectedVersion: 1, nowMs: startedAt + 120_001,
    });
    expect(recovered.replay).toMatchObject({ status: 500, body: { code: "persistence-failed", routable: false } });
    await expect(completeDiscoveryFailure(primaryDb, {
      claim: original.claim!, errorCode: "connect-rejected", completedAtMs: startedAt + 120_002,
    })).rejects.toMatchObject({ statusCode: 409, code: "operation-fenced" });

    const secondTarget = (await createDiscoveryTarget(
      primaryApp, admin.token, "pg-terminal-target", "https://pg-terminal.example",
    )).json() as { id: number };
    const terminalClaim = await claimRevalidation(primaryDb, actor, {
      targetId: secondTarget.id, submissionId: "pg-terminal-owner", expectedVersion: 1, nowMs: startedAt,
    });
    const terminal = await completeDiscoveryPersistenceFailure(primaryDb, {
      claim: terminalClaim.claim!, completedAtMs: startedAt + 1_000,
    });
    expect(terminal).toMatchObject({ status: 500, body: { code: "persistence-failed", routable: false } });
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_admin_operations WHERE state = 'failed' AND response_status = 500",
    ))[0]!.count)).toBe(2);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(
      "SELECT COUNT(*) AS count FROM a2a_discovery_attempts",
    ))[0]!.count)).toBe(0);
  });

  it("records same-kid material changes and audit findings in PostgreSQL without promotion", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG same-kid admin");
    const first = signedDiscoveryFixture("pg-same-kid");
    const changed = signedDiscoveryFixture("pg-same-kid");
    const transport = new PgScriptedTransport([
      discoveryResponse(JSON.stringify(first.card)), discoveryResponse(JSON.stringify(first.jwks)),
      discoveryResponse(JSON.stringify(changed.card)), discoveryResponse(JSON.stringify(changed.jwks)),
    ]);
    const app = await buildPgDiscoveryApp(transport);
    try {
      const target = (await createDiscoveryTarget(
        app, admin.token, "pg-same-kid-target", "https://pg-discovery.example",
      )).json() as { id: number };
      expect((await revalidatePg(app, admin.token, target.id, "pg-same-kid-first")).statusCode).toBe(200);
      const second = await revalidatePg(app, admin.token, target.id, "pg-same-kid-changed");
      expect(second.statusCode, second.body).toBe(200);
      expect(second.json()).toMatchObject({
        key_findings: [{ code: "same-kid-material-changed", key_id: "pg-same-kid" }],
        routable: false,
      });
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_managed_key_revisions WHERE state = 'observed'",
      ))[0]!.count)).toBe(2);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM a2a_g003_audit
        WHERE action = 'managed-key.material-changed' AND reason = 'same-kid-material-changed'`))[0]!.count)).toBe(1);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_trust_anchors",
      ))[0]!.count)).toBe(0);
    } finally {
      await app.close();
    }
  });

  it("linearizes managed-key and direct-anchor revocation with one PostgreSQL cascade", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "PG managed revoke admin");
    const signed = signedDiscoveryFixture("pg-managed-revoke");
    const transport = new PgScriptedTransport([
      discoveryResponse(JSON.stringify(signed.card)), discoveryResponse(JSON.stringify(signed.jwks)),
    ]);
    const app = await buildPgDiscoveryApp(transport);
    try {
      const target = (await createDiscoveryTarget(
        app, admin.token, "pg-managed-target", "https://pg-discovery.example",
      )).json() as { id: number };
      expect((await revalidatePg(app, admin.token, target.id, "pg-managed-discovery")).statusCode).toBe(200);
      const revision = (await primaryDb.query<{ id: unknown }>(
        "SELECT id FROM a2a_managed_key_revisions WHERE key_id = 'pg-managed-revoke'",
      ))[0]!;
      const activated = await app.inject({
        method: "POST",
        url: `/api/v1/admin/a2a/key-revisions/${asNumber(revision.id)}/activate`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { submission_id: "pg-managed-activate", expected_version: 1, reason: "approve PG observed key" },
      });
      expect(activated.statusCode, activated.body).toBe(200);
      const anchorId = (activated.json() as { linked_trust_anchor_id: number }).linked_trust_anchor_id;
      await expect(primaryDb.execute(
        "UPDATE a2a_managed_key_revisions SET decision_reason = NULL WHERE id = $1",
        [asNumber(revision.id)],
      )).rejects.toThrow();
      const responses = await Promise.all([
        app.inject({
          method: "POST", url: `/api/v1/admin/a2a/key-revisions/${asNumber(revision.id)}/revoke`,
          headers: { authorization: `Bearer ${admin.token}` },
          payload: { submission_id: "pg-managed-revoke", expected_version: 2, reason: "retire PG managed key" },
        }),
        secondaryApp.inject({
          method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchorId}/revoke`,
          headers: { authorization: `Bearer ${admin.token}` },
          payload: { submission_id: "pg-direct-revoke", expected_version: 1, reason: "concurrent direct revoke" },
        }),
      ]);
      expect(responses.map((response) => response.statusCode).sort((a, b) => a - b)).toEqual([200, 409]);
      expect(asString((await primaryDb.query<{ state: unknown }>(
        "SELECT state FROM a2a_managed_key_revisions WHERE id = $1", [asNumber(revision.id)],
      ))[0]!.state)).toBe("revoked");
      expect(asString((await primaryDb.query<{ state: unknown }>(
        "SELECT state FROM a2a_trust_anchors WHERE id = $1", [anchorId],
      ))[0]!.state)).toBe("revoked");
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_g003_audit WHERE action = 'managed-key.revoked'",
      ))[0]!.count)).toBe(1);
      expect(asNumber((await primaryDb.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM a2a_registry_audit WHERE action = 'trust-anchor.revoked'",
      ))[0]!.count)).toBe(1);
    } finally {
      await app.close();
    }
  });

  it("serializes credential rotation and enforces active-pointer coherence in PostgreSQL", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Credential concurrency admin");
    const targetResponse = await createDiscoveryTarget(
      primaryApp, admin.token, "pg-credential-target", "https://pg-credential.example",
    );
    expect(targetResponse.statusCode).toBe(201);
    const target = targetResponse.json() as { id: number; canonical_origin: string };
    const created = await primaryApp.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        submission_id: "pg-credential-create", origin: target.canonical_origin,
        scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1",
        secret_reference: "vault://pg-credential/v1",
      },
    });
    expect(created.statusCode).toBe(201);
    const binding = created.json() as { id: number };
    const rotations = await Promise.all([
      primaryApp.inject({
        method: "POST", url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/rotate`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          submission_id: "pg-credential-rotate-a", expected_version: 1,
          provider: "vault", external_version: "v2-a", secret_reference: "vault://pg-credential/v2-a",
        },
      }),
      secondaryApp.inject({
        method: "POST", url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/rotate`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          submission_id: "pg-credential-rotate-b", expected_version: 1,
          provider: "vault", external_version: "v2-b", secret_reference: "vault://pg-credential/v2-b",
        },
      }),
    ]);
    expect(rotations.map((response) => response.statusCode).sort((a, b) => a - b)).toEqual([200, 409]);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(`SELECT COUNT(*) AS count
      FROM a2a_credential_revisions WHERE binding_id = $1 AND state = 'active'`, [binding.id]))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>(`SELECT COUNT(*) AS count
      FROM a2a_credential_active_revisions WHERE binding_id = $1`, [binding.id]))[0]!.count)).toBe(1);
    const row = (await primaryDb.query<{ active_revision_id: unknown; row_version: unknown }>(
      "SELECT active_revision_id, row_version FROM a2a_credential_bindings WHERE id = $1", [binding.id],
    ))[0]!;
    expect(asNumber(row.row_version)).toBe(2);
    await expect(primaryDb.execute(
      "UPDATE a2a_credential_revisions SET state = 'revoked' WHERE id = $1", [asNumber(row.active_revision_id)],
    )).rejects.toThrow(/credential revision|revision link/u);
    expect(asString((await primaryDb.query<{ state: unknown }>(
      "SELECT state FROM a2a_credential_bindings WHERE id = $1", [binding.id],
    ))[0]!.state)).toBe("active");
  });

  it("serializes concurrent vote changes so score equals the final vote", async () => {
    const author = await enroll(primaryApp, "Discussion author");
    const voter = await enroll(primaryApp, "Voter");
    const postId = await createPost(primaryApp, author.token, "discussions");
    const headers = { authorization: `Bearer ${voter.token}` };
    expect((await primaryApp.inject({ method: "POST", url: `/api/v1/network/posts/${postId}/votes`, headers, payload: { value: 1 } })).statusCode).toBe(200);
    const responses = await Promise.all([
      primaryApp.inject({ method: "POST", url: `/api/v1/network/posts/${postId}/votes`, headers, payload: { value: -1 } }),
      secondaryApp.inject({ method: "POST", url: `/api/v1/network/posts/${postId}/votes`, headers, payload: { value: -1 } }),
    ]);
    expect(responses.map((response) => response.statusCode)).toEqual([200, 200]);
    const post = await primaryApp.inject({ method: "GET", url: `/api/v1/network/posts/${postId}`, headers });
    expect((post.json() as { score: number }).score).toBe(-1);
  });

  it("charges deletion reputation exactly once under concurrent deletes", async () => {
    const author = await enroll(primaryApp, "Deletion author");
    const postId = await createPost(primaryApp, author.token, "discussions");
    const headers = { authorization: `Bearer ${author.token}` };
    const responses = await Promise.all([
      primaryApp.inject({ method: "DELETE", url: `/api/v1/network/posts/${postId}`, headers }),
      secondaryApp.inject({ method: "DELETE", url: `/api/v1/network/posts/${postId}`, headers }),
    ]);
    expect(responses.map((response) => response.statusCode).sort((left, right) => left - right)).toEqual([204, 404]);
    const me = await primaryApp.inject({ method: "GET", url: "/api/v1/me", headers });
    expect((me.json() as { contribution_tokens: string }).contribution_tokens).toBe("0");
  });

  it("permits exactly one trusted card for a canonical interface without false loser audit", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Registry admin");
    const signer = agentCardSigner("pg-interface-key");
    const anchor = await createAgentCardAnchor(primaryApp, admin.token, signer);
    const first = agentCard("1.0.0", "https://PG-AGENT.example.test:443/a2a");
    const second = agentCard("2.0.0", "https://pg-agent.example.test/a2a");
    signer.signCard(first);
    signer.signCard(second);
    const firstId = (await importAgentCard(primaryApp, admin.token, first, "pg-import-1")).card.id;
    const secondId = (await importAgentCard(secondaryApp, admin.token, second, "pg-import-2")).card.id;
    const responses = await Promise.all([firstId, secondId].map((id, index) => (index === 0 ? primaryApp : secondaryApp).inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${id}/review`, headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: `pg-review-${index}`, expected_version: 1, decision: "trusted", reason: "Concurrent approval" },
    })));
    expect(responses.map((response) => response.statusCode).sort((left, right) => left - right)).toEqual([200, 409]);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_card_registry WHERE state = 'trusted'"))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit WHERE action = 'agent-card.trusted'"))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE operation = 'agent-card.review'"))[0]!.count)).toBe(1);

    const winnerIndex = responses.findIndex((response) => response.statusCode === 200);
    const winnerId = [firstId, secondId][winnerIndex]!;
    const revoked = await primaryApp.inject({
      method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchor.id}/revoke`, headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: "pg-interface-anchor-revoke", expected_version: anchor.row_version, reason: "Replay proof" },
    });
    expect(revoked.statusCode).toBe(200);
    const replay = await secondaryApp.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${winnerId}/review`, headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: `pg-review-${winnerIndex}`, expected_version: 1, decision: "trusted", reason: "Concurrent approval" },
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ state: "trusted", row_version: 2 });
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_card_observations WHERE provenance_kind = 'admin-review'"))[0]!.count)).toBe(1);
  });

  it("rolls back the stale CAS loser without audit or idempotency residue", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "CAS admin");
    const imported = await importAgentCard(primaryApp, admin.token, agentCard("unsigned"), "pg-cas-import");
    const responses = await Promise.all([primaryApp, secondaryApp].map((app, index) => app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${imported.card.id}/review`, headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: `pg-cas-review-${index}`, expected_version: 1, decision: "rejected", reason: "Concurrent rejection" },
    })));
    expect(responses.map((response) => response.statusCode).sort((left, right) => left - right)).toEqual([200, 409]);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit WHERE action = 'agent-card.rejected'"))[0]!.count)).toBe(1);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE operation = 'agent-card.review'"))[0]!.count)).toBe(1);
  });

  it("linearizes import admission with concurrent trust-anchor revocation", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Linearization admin");
    const signer = agentCardSigner("pg-linear-key");
    const anchor = await createAgentCardAnchor(primaryApp, admin.token, signer);
    const value = agentCard("linear");
    signer.signCard(value);
    const [importResponse, revokeResponse] = await Promise.all([
      secondaryApp.inject({
        method: "POST", url: "/api/v1/admin/a2a/cards/import", headers: { authorization: `Bearer ${admin.token}` },
        payload: { submission_id: "pg-linear-import", card: value, provenance: { kind: "api", source: "postgres-concurrency" } },
      }),
      primaryApp.inject({
        method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchor.id}/revoke`, headers: { authorization: `Bearer ${admin.token}` },
        payload: { submission_id: "pg-linear-revoke", expected_version: anchor.row_version, reason: "Concurrent retirement" },
      }),
    ]);
    expect(revokeResponse.statusCode).toBe(200);
    expect([201, 422]).toContain(importResponse.statusCode);
    const auditRows = await primaryDb.query<{ id: unknown; action: unknown }>("SELECT id, action FROM a2a_registry_audit ORDER BY id");
    const revokedId = asNumber(auditRows.find((row) => row.action === "trust-anchor.revoked")!.id);
    if (importResponse.statusCode === 201) {
      const admission = (importResponse.json() as { admission: { trust_state: string } }).admission;
      expect(admission.trust_state).toBe("trusted");
      const observedId = asNumber(auditRows.find((row) => row.action === "agent-card.observed")!.id);
      expect(observedId).toBeLessThan(revokedId);
    } else {
      expect(importResponse.json()).toMatchObject({ code: "signature-key-revoked" });
      expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'pg-linear-import'"))[0]!.count)).toBe(0);
    }

    const before = (await primaryDb.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`))[0]!;
    const rejected = await secondaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import", headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: "pg-revoked-import", card: value, provenance: { kind: "api", source: "postgres-concurrency" } },
    });
    expect(rejected.statusCode).toBe(422);
    expect(rejected.json()).toMatchObject({ code: "signature-key-revoked" });
    const after = (await primaryDb.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`))[0]!;
    expect([asNumber(after.documents), asNumber(after.observations), asNumber(after.audit)]).toEqual([
      asNumber(before.documents), asNumber(before.observations), asNumber(before.audit),
    ]);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'pg-revoked-import'"))[0]!.count)).toBe(0);
  });

  it("replays a successful import after anchor revocation before evaluating current trust", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Replay admin");
    const signer = agentCardSigner("pg-replay-key");
    const anchor = await createAgentCardAnchor(primaryApp, admin.token, signer);
    const value = agentCard("replay-after-revoke");
    signer.signCard(value);
    const payload = {
      submission_id: "pg-import-replay", card: value,
      provenance: { kind: "api", source: "postgres-concurrency" },
    };
    const imported = await primaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { authorization: `Bearer ${admin.token}` }, payload,
    });
    expect(imported.statusCode).toBe(201);
    const originalBody = imported.json();
    expect((await primaryApp.inject({
      method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchor.id}/revoke`,
      headers: { authorization: `Bearer ${admin.token}` },
      payload: { submission_id: "pg-replay-revoke", expected_version: anchor.row_version, reason: "Retired" },
    })).statusCode).toBe(200);

    const replay = await secondaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { authorization: `Bearer ${admin.token}` }, payload,
    });
    expect(replay.statusCode).toBe(201);
    expect(replay.json()).toEqual(originalBody);

    const before = (await primaryDb.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`))[0]!;
    const denied = await secondaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { authorization: `Bearer ${admin.token}` },
      payload: { ...payload, submission_id: "pg-import-after-revoke" },
    });
    expect(denied.statusCode).toBe(422);
    expect(denied.json()).toEqual({ code: "signature-key-revoked", detail: "Agent Card admission failed: signature-key-revoked" });
    const after = (await primaryDb.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`))[0]!;
    expect(after).toEqual(before);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'pg-import-after-revoke'"))[0]!.count)).toBe(0);
  });

  it("holds a history snapshot until a complete observation and verification commit", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "History admin");
    const imported = await importAgentCard(primaryApp, admin.token, agentCard("history-lock"), "pg-history-import");
    const employee = (await primaryDb.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [admin.employeeCode]))[0]!;
    const registry = (await primaryDb.query<{ document_id: unknown }>("SELECT document_id FROM a2a_card_registry WHERE id = $1", [imported.card.id]))[0]!;
    const document = (await primaryDb.query<{ document_sha256: unknown; payload_sha256: unknown }>(
      "SELECT document_sha256, payload_sha256 FROM a2a_card_documents WHERE id = $1", [asNumber(registry.document_id)],
    ))[0]!;
    let releaseWriter!: () => void;
    const release = new Promise<void>((resolve) => { releaseWriter = resolve; });
    let observationInserted!: () => void;
    const inserted = new Promise<void>((resolve) => { observationInserted = resolve; });
    const writer = primaryDb.transaction(async (tx) => {
      await tx.execute("SELECT id FROM a2a_card_registry WHERE id = $1 FOR UPDATE", [imported.card.id]);
      const observation = (await tx.query<{ id: unknown }>(`INSERT INTO a2a_card_observations
        (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
        VALUES ($1, $2, 'pg-history-observation', 'migration', 'history-test', NULL, $3) RETURNING id`, [
        imported.card.id, asNumber(employee.id), new Date().toISOString(),
      ]))[0]!;
      observationInserted();
      await release;
      await tx.execute(`INSERT INTO a2a_card_verifications
        (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
          document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
        VALUES ($1, $2, NULL, 'discovered', NULL, $3, $4, '[]', $5)`, [
        asNumber(observation.id), asNumber(registry.document_id), String(document.document_sha256),
        String(document.payload_sha256), new Date().toISOString(),
      ]);
    });
    await inserted;
    const historyPromise = secondaryApp.inject({
      method: "GET", url: `/api/v1/admin/a2a/cards/${imported.card.id}/history`,
      headers: { authorization: `Bearer ${admin.token}` },
    });
    let lockObserved = false;
    for (let attempt = 0; attempt < 100 && !lockObserved; attempt += 1) {
      const row = (await primaryDb.query<{ waiting: unknown }>(`SELECT EXISTS (
        SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
        AND wait_event_type = 'Lock' AND query LIKE '%a2a_card_registry%FOR SHARE%'
      ) AS waiting`))[0]!;
      lockObserved = row.waiting === true;
      if (!lockObserved) await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(lockObserved).toBe(true);
    releaseWriter();
    await writer;
    const history = await historyPromise;
    expect(history.statusCode).toBe(200);
    const body = history.json() as {
      observations: { items: Array<{ id: number }> };
      verifications: { items: Array<{ observation_id: number }> };
    };
    expect(body.observations.items).toHaveLength(2);
    expect(body.verifications.items).toHaveLength(2);
    expect(body.observations.items.map((item) => item.id).sort((a, b) => a - b))
      .toEqual(body.verifications.items.map((item) => item.observation_id).sort((a, b) => a - b));
  });

  it("rejects normalized preferred-interface expansion without PostgreSQL persistence", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "URI admin");
    const response = await primaryApp.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { authorization: `Bearer ${admin.token}` },
      payload: {
        submission_id: "pg-expanded-uri",
        card: agentCard("expanded-uri", `https://pg-agent.example.test/${"가".repeat(680)}`),
        provenance: { kind: "api", source: "postgres-concurrency" },
      },
    });
    expect(response.statusCode).toBe(422);
    expect(response.json()).toEqual({ code: "agent-card-invalid", detail: "Agent Card is invalid" });
    for (const table of ["a2a_card_documents", "a2a_card_registry", "a2a_card_observations", "a2a_card_verifications", "a2a_registry_audit", "a2a_mutation_submissions"]) {
      expect(asNumber((await primaryDb.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count), table).toBe(0);
    }
  });

  it("does not misclassify non-unique PostgreSQL failures as anchor conflicts", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Failure admin");
    const employee = (await primaryDb.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [admin.employeeCode]))[0]!;
    const injectedFailure = new Error("injected postgres storage failure");
    const failingDb: SqlDatabase = {
      dialect: primaryDb.dialect,
      query: primaryDb.query.bind(primaryDb),
      execute: primaryDb.execute.bind(primaryDb),
      close: async () => {},
      transaction: (work) => primaryDb.transaction((tx) => work({
        dialect: tx.dialect,
        execute: tx.execute.bind(tx),
        close: async () => {},
        transaction: tx.transaction.bind(tx),
        query: (sql, params) => sql.includes("INSERT INTO a2a_trust_anchors")
          ? Promise.reject(injectedFailure)
          : tx.query(sql, params),
      })),
    };
    const signer = agentCardSigner("pg-storage-key");
    await expect(createTrustAnchor(failingDb, { id: asNumber(employee.id), employeeCode: admin.employeeCode }, {
      submissionId: "pg-storage-failure", keyId: signer.keyId, algorithm: "ES256", publicKeyPem: signer.publicKeyPem,
    })).rejects.toBe(injectedFailure);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'pg-storage-failure'"))[0]!.count)).toBe(0);
    expect(asNumber((await primaryDb.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit"))[0]!.count)).toBe(0);
  });

  it("enforces G002 row-version, provenance, and verification coherence in PostgreSQL", async () => {
    const admin = await enrollAdmin(primaryApp, primaryDb, "Invariant admin");
    const signer = agentCardSigner("pg-invariant-key");
    const anchor = await createAgentCardAnchor(primaryApp, admin.token, signer);
    const value = agentCard("invariant");
    signer.signCard(value);
    const imported = await importAgentCard(primaryApp, admin.token, value, "pg-invariant-import");
    const employee = (await primaryDb.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [admin.employeeCode]))[0]!;
    const registry = (await primaryDb.query<{ document_id: unknown }>("SELECT document_id FROM a2a_card_registry WHERE id = $1", [imported.card.id]))[0]!;
    const observation = (await primaryDb.query<{ id: unknown }>("SELECT id FROM a2a_card_observations WHERE registry_id = $1", [imported.card.id]))[0]!;
    const document = (await primaryDb.query<{ document_sha256: unknown; payload_sha256: unknown }>("SELECT document_sha256, payload_sha256 FROM a2a_card_documents WHERE id = $1", [asNumber(registry.document_id)]))[0]!;
    await expect(primaryDb.execute("UPDATE a2a_trust_anchors SET row_version = 0 WHERE id = $1", [anchor.id])).rejects.toThrow();
    await expect(primaryDb.execute("UPDATE a2a_card_registry SET row_version = 0 WHERE id = $1", [imported.card.id])).rejects.toThrow();
    await expect(primaryDb.execute(`INSERT INTO a2a_card_observations
      (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
      VALUES ($1, $2, 'pg-invalid-provenance', 'network', 'test', NULL, $3)`, [
      imported.card.id, asNumber(employee.id), new Date().toISOString(),
    ])).rejects.toThrow();
    await expect(primaryDb.execute(`INSERT INTO a2a_card_verifications
      (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
        document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
      VALUES ($1, $2, $3, 'trusted', $4, $5, $6, '[]', $7)`, [
      asNumber(observation.id), asNumber(registry.document_id), anchor.id, signer.keyId,
      String(document.document_sha256), String(document.payload_sha256), new Date().toISOString(),
    ])).rejects.toThrow();
    await expect(primaryDb.transaction(async (tx) => {
      const testObservation = (await tx.query<{ id: unknown }>(`INSERT INTO a2a_card_observations
        (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
        VALUES ($1, $2, 'pg-coherence-observation', 'migration', 'constraint-test', NULL, $3) RETURNING id`, [
        imported.card.id, asNumber(employee.id), new Date().toISOString(),
      ]))[0]!;
      await tx.execute(`INSERT INTO a2a_card_verifications
        (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
          document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
        VALUES ($1, $2, $3, 'discovered', $4, $5, $6, '[]', $7)`, [
        asNumber(testObservation.id), asNumber(registry.document_id), anchor.id, signer.keyId,
        String(document.document_sha256), String(document.payload_sha256), new Date().toISOString(),
      ]);
    })).rejects.toThrow();
  });
});
