import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { canonicalizeAgentCardPayload } from "../src/a2a/agent-card-registry.js";
import { createTrustAnchor } from "../src/a2a/agent-card-store.js";
import type { Settings } from "../src/config.js";
import { asNumber, createDatabase, type SqlDatabase } from "../src/db.js";

const postgresUrl = process.env.AGENT_HUB_TEST_POSTGRES_URL;
const describePostgres = postgresUrl === undefined ? describe.skip : describe;

type Enrollment = { token: string; employeeCode: string };

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

describePostgres("PostgreSQL concurrency contracts", () => {
  let primaryDb: SqlDatabase;
  let secondaryDb: SqlDatabase;
  let primaryApp: Awaited<ReturnType<typeof buildApp>>;
  let secondaryApp: Awaited<ReturnType<typeof buildApp>>;
  const settings: Settings = {
    databaseUrl: postgresUrl ?? "postgresql://unused",
    host: "127.0.0.1",
    port: 8000,
    logLevel: "silent",
    rateLimitPerIpPerMinute: 1_000,
    signupRateLimitPerIpPerMinute: 1_000,
    trustedProxyIps: [],
    corsOrigins: ["http://localhost:5174"],
    tlsHstsMaxAge: 0,
  };

  beforeAll(async () => {
    primaryDb = createDatabase(postgresUrl!);
    secondaryDb = createDatabase(postgresUrl!);
    [primaryApp, secondaryApp] = await Promise.all([
      buildApp({ database: primaryDb, settings }),
      buildApp({ database: secondaryDb, settings }),
    ]);
  });

  beforeEach(async () => {
    await primaryDb.execute(`TRUNCATE TABLE a2a_mutation_submissions, a2a_registry_audit,
      a2a_card_verifications, a2a_card_observations, a2a_card_registry, a2a_card_documents,
      a2a_trust_anchors, network_votes, network_comments, network_posts, api_keys,
      agent_identities, employees, departments, signup_challenges RESTART IDENTITY CASCADE`);
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
