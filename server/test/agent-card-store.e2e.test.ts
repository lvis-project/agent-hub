import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalizeAgentCardPayload, EXACT_SEND_REPLAY_EXTENSION_URI } from "../src/a2a/agent-card-registry.js";
import { createTrustAnchor } from "../src/a2a/agent-card-store.js";
import { buildApp } from "../src/app.js";
import type { Settings } from "../src/config.js";
import { asNumber, createDatabase, type SqlDatabase } from "../src/db.js";
import { migrate } from "../src/migrations.js";

const settings: Settings = {
  databaseUrl: "sqlite://:memory:", postgresTls: { mode: "disabled", caFile: null }, host: "127.0.0.1", port: 8000, logLevel: "silent",
  rateLimitPerIpPerMinute: 1_000, signupRateLimitPerIpPerMinute: 100,
  trustedProxyIps: [], corsOrigins: ["http://localhost:5174"], tlsHstsMaxAge: 0,
  credentialReferenceHmacKey: "test-only-credential-reference-key-0001",
};

function signer(keyId = "admin-work-key") {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    keyId,
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    signCard(value: Record<string, unknown>) {
      const payload = canonicalizeAgentCardPayload(value);
      const protectedHeader = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JOSE" })).toString("base64url");
      const signature = sign("sha256", Buffer.from(`${protectedHeader}.${payload.toString("base64url")}`, "ascii"), {
        key: pair.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64url");
      value.signatures = [{ protected: protectedHeader, signature }];
    },
  };
}

function card(version = "1.0.0", preferredInterface = "https://AGENT.example.test:443/a2a"):
Record<string, unknown> {
  return {
    name: "Durable Work Assistant",
    description: "A bounded administrator-reviewed work assistant.",
    version,
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    skills: [{
      id: "delegate-work", name: "Delegate work", description: "Run one bounded work item.",
      tags: ["delegation"], inputModes: ["text/plain"], outputModes: ["text/plain"],
    }],
    supportedInterfaces: [{ url: preferredInterface, protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"],
    securitySchemes: { bearerAuth: { httpAuthSecurityScheme: { scheme: "bearer", bearerFormat: "opaque" } } },
    securityRequirements: [{ schemes: { bearerAuth: { list: [] } } }],
  };
}

async function seedActor(db: SqlDatabase, employeeCode: string, role: "employee" | "admin", token: string): Promise<number> {
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
  await db.execute(`INSERT INTO api_keys
    (employee_id, label, key_hash, key_prefix, role, created_at, expires_at, revoked_at)
    VALUES ($1, 'test', $2, $3, $4, $5, NULL, NULL)`, [
    employeeId, createHash("sha256").update(token).digest("hex"), token.slice(0, 16), role, timestamp,
  ]);
  return employeeId;
}

async function fixture(logs?: string[]) {
  const db = createDatabase("sqlite://:memory:");
  await migrate(db);
  const adminId = await seedActor(db, "admin-agent", "admin", "admin-token");
  await seedActor(db, "regular-agent", "employee", "employee-token");
  const app = await buildApp({
    database: db,
    settings: logs === undefined ? settings : { ...settings, logLevel: "info" },
    migrate: false,
    ...(logs === undefined ? {} : {
      logger: { level: "info", stream: { write(message: string) { logs.push(message); } } },
    }),
  });
  return {
    db, app, adminId,
    admin: { authorization: "Bearer admin-token" },
    employee: { authorization: "Bearer employee-token" },
  };
}

async function createAnchor(app: Awaited<ReturnType<typeof buildApp>>, auth: Record<string, string>, testSigner: ReturnType<typeof signer>, submissionId = "anchor-1") {
  return app.inject({
    method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: auth,
    payload: { submission_id: submissionId, key_id: testSigner.keyId, algorithm: "ES256", public_key_pem: testSigner.publicKeyPem },
  });
}

async function importCard(app: Awaited<ReturnType<typeof buildApp>>, auth: Record<string, string>, value: unknown, submissionId: string) {
  return app.inject({
    method: "POST", url: "/api/v1/admin/a2a/cards/import", headers: auth,
    payload: { submission_id: submissionId, card: value, provenance: { kind: "manual", source: "test-suite" } },
  });
}

describe("G002 durable Agent Card registry", () => {
  const close: Array<() => Promise<void>> = [];
  afterEach(async () => { await Promise.all(close.splice(0).map((work) => work())); });

  it("runs all migrations twice and serializes re-entrant SQLite transactions", async () => {
    const db = createDatabase("sqlite://:memory:");
    close.push(() => db.close());
    await migrate(db);
    await migrate(db);
    expect((await db.query<{ version: string }>("SELECT version FROM schema_migrations ORDER BY version")).map((row) => row.version))
      .toEqual([
        "0001_public_network",
        "0002_agent_card_registry",
        "0003_a2a_discovery_connectivity",
        "0004_a2a_direct_route_control_plane",
        "0005_a2a_verified_route_evidence",
        "0006_a2a_domain_free_identifier_contract",
        "0007_a2a_served_spec_source_provenance",
      ]);

    await db.execute("CREATE TABLE transaction_counter (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)");
    await db.execute("INSERT INTO transaction_counter (id, value) VALUES (1, 0)");
    await Promise.all(Array.from({ length: 24 }, () => db.transaction(async (tx) => {
      const before = asNumber((await tx.query<{ value: unknown }>("SELECT value FROM transaction_counter WHERE id = 1"))[0]!.value);
      await Promise.resolve();
      await tx.transaction(async (nested) => nested.execute("UPDATE transaction_counter SET value = $1 WHERE id = 1", [before + 1]));
    })));
    expect(asNumber((await db.query<{ value: unknown }>("SELECT value FROM transaction_counter WHERE id = 1"))[0]!.value)).toBe(24);
  });

  it("preserves opaque legacy evidence while enforcing the current identifier on new SQLite writes", async () => {
    const db = createDatabase("sqlite://:memory:");
    close.push(() => db.close());
    await migrate(db);
    const adminId = await seedActor(db, "migration-admin", "admin", "migration-admin-token");
    const timestamp = "2026-07-17T00:00:00.000Z";
    const legacyIdentifier = new URL(
      "/a2a/extensions/exact-send-replay/v1",
      `https://${["legacy", "example", "test"].join(".")}`,
    ).href;
    const body = Buffer.from("legacy-spec-bytes", "utf8");
    const signedPayload = Buffer.from("legacy-signed-payload", "utf8");
    const signature = Buffer.from("legacy-signature", "utf8");
    const digest = createHash("sha256").update(body).digest("hex");

    for (const table of ["a2a_served_spec_observations", "a2a_wire_conformance_evidence"]) {
      await db.execute(`DROP TRIGGER ${table}_identifier_contract_insert`);
    }
    await db.execute(`INSERT INTO a2a_evidence_signers
      (key_id, algorithm, public_key_pem, key_fingerprint_sha256, created_by_employee_id, created_at)
      VALUES ('legacy-signer', 'Ed25519', 'legacy-public-key', $1, $2, $3)`, ["1".repeat(64), adminId, timestamp]);
    const signerId = asNumber((await db.query<{ id: unknown }>("SELECT id FROM a2a_evidence_signers WHERE key_id = 'legacy-signer'"))[0]!.id);
    await db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
      legacyIdentifier, digest, body.length, body, "2".repeat(64), adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ]);
    const observationId = asNumber((await db.query<{ id: unknown }>("SELECT id FROM a2a_served_spec_observations"))[0]!.id);
    await db.execute(`INSERT INTO a2a_wire_conformance_evidence
      (signer_id, served_spec_observation_id, artifact_id, artifact_digest_sha256,
        signed_payload_blob, signature_blob, schema_version,
        agent_hub_head_sha, lvis_app_head_sha, remote_server_head_sha,
        a2a_tck_tag, a2a_tck_commit_sha,
        agent_hub_lock_digest_sha256, lvis_app_lock_digest_sha256,
        remote_server_lock_digest_sha256, a2a_tck_lock_digest_sha256,
        a2a_specification_uri, extension_spec_uri, extension_spec_digest_sha256,
        agent_card_digest_sha256, test_vectors_total, test_vectors_passed,
        test_vectors_failed, test_vectors_skipped, verification_state,
        verified_by_employee_id, verified_at)
      VALUES ($1, $2, 'legacy-artifact', $3, $4, $5, 'lvis-wire-conformance-bundle/v1',
        $6, $7, $8, '1.0.0.alpha2', $9, $10, $11, $12, $13,
        'https://a2a-protocol.org/v1.0.0/specification/', $14, $15, $16,
        1, 1, 0, 0, 'passed', $17, $18)`, [
      signerId, observationId, "3".repeat(64), signedPayload, signature,
      "4".repeat(40), "5".repeat(40), "6".repeat(40), "7".repeat(40),
      "8".repeat(64), "9".repeat(64), "a".repeat(64), "b".repeat(64),
      legacyIdentifier, digest, "c".repeat(64), adminId, timestamp,
    ]);
    const wireId = asNumber((await db.query<{ id: unknown }>("SELECT id FROM a2a_wire_conformance_evidence"))[0]!.id);
    await db.execute(`INSERT INTO a2a_served_spec_revocations
      (served_spec_observation_id, revoked_by_employee_id, revoked_at, revoke_reason)
      VALUES ($1, $2, $3, 'legacy contract retired')`, [observationId, adminId, timestamp]);
    await db.execute(`INSERT INTO a2a_wire_conformance_revocations
      (wire_conformance_evidence_id, revoked_by_employee_id, revoked_at, revoke_reason)
      VALUES ($1, $2, $3, 'legacy contract retired')`, [wireId, adminId, timestamp]);
    await db.execute(`DELETE FROM schema_migrations WHERE version IN
      ('0006_a2a_domain_free_identifier_contract', '0007_a2a_served_spec_source_provenance')`);

    await migrate(db);

    const preservedSpec = (await db.query<Record<string, unknown>>(
      "SELECT spec_uri, body_blob FROM a2a_served_spec_observations WHERE id = $1", [observationId],
    ))[0]!;
    const preservedWire = (await db.query<Record<string, unknown>>(
      "SELECT extension_spec_uri, signed_payload_blob, signature_blob FROM a2a_wire_conformance_evidence WHERE id = $1", [wireId],
    ))[0]!;
    expect(preservedSpec.spec_uri).toBe(legacyIdentifier);
    expect(Buffer.from(preservedSpec.body_blob as Uint8Array)).toEqual(body);
    expect(preservedWire.extension_spec_uri).toBe(legacyIdentifier);
    expect(Buffer.from(preservedWire.signed_payload_blob as Uint8Array)).toEqual(signedPayload);
    expect(Buffer.from(preservedWire.signature_blob as Uint8Array)).toEqual(signature);
    expect(await db.query("PRAGMA foreign_key_check")).toEqual([]);
    expect(asNumber((await db.query<{ foreign_keys: unknown }>("PRAGMA foreign_keys"))[0]!.foreign_keys)).toBe(1);
    await expect(db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
      legacyIdentifier, digest, body.length, body, "d".repeat(64), adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ])).rejects.toThrow(/identifier is not current/u);
    await db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, source_url, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
      EXACT_SEND_REPLAY_EXTENSION_URI, "https://spec.example.test/exact-replay",
      digest, body.length, body, "e".repeat(64), adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ]);
    await expect(db.execute(
      "UPDATE a2a_served_spec_observations SET observed_at = $1 WHERE id = $2", ["2026-07-18T00:00:00.000Z", observationId],
    )).rejects.toThrow(/append-only/u);
  });

  it("upgrades an already-applied 0006 schema with forward-only source provenance", async () => {
    const db = createDatabase("sqlite://:memory:");
    close.push(() => db.close());
    await migrate(db);
    const adminId = await seedActor(db, "source-migration-admin", "admin", "source-migration-token");
    const timestamp = "2026-07-17T00:00:00.000Z";
    const body = Buffer.from("pre-0007-spec", "utf8");
    const digest = createHash("sha256").update(body).digest("hex");

    await db.execute("DROP TRIGGER a2a_served_spec_observations_identifier_contract_insert");
    await db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, source_url, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
      EXACT_SEND_REPLAY_EXTENSION_URI, "https://old.example.test/spec", digest, body.length,
      body, "f".repeat(64), adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ]);
    await db.execute("DELETE FROM schema_migrations WHERE version = '0007_a2a_served_spec_source_provenance'");
    await db.execute("ALTER TABLE a2a_served_spec_observations DROP COLUMN source_url");

    await migrate(db);
    await migrate(db);

    const columns = await db.query<{ name: unknown }>("PRAGMA table_info(a2a_served_spec_observations)");
    expect(columns.map((column) => String(column.name))).toContain("source_url");
    expect((await db.query<{ source_url: unknown }>(
      "SELECT source_url FROM a2a_served_spec_observations",
    ))[0]!.source_url).toBeNull();
    expect(await db.query(
      "SELECT version FROM schema_migrations WHERE version = '0007_a2a_served_spec_source_provenance'",
    )).toHaveLength(1);
    await expect(db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [
      EXACT_SEND_REPLAY_EXTENSION_URI, digest, body.length, body, "e".repeat(64),
      adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ])).rejects.toThrow(/identifier is not current/u);
    await db.execute(`INSERT INTO a2a_served_spec_observations
      (spec_uri, source_url, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
      EXACT_SEND_REPLAY_EXTENSION_URI, "https://new.example.test/spec", digest, body.length,
      body, "d".repeat(64), adminId, timestamp, "2099-01-01T00:00:00.000Z",
    ]);
  });

  it("requires an administrator for every registry endpoint", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const routes = [
      { method: "POST", url: "/api/v1/admin/a2a/trust-anchors", payload: {} },
      { method: "GET", url: "/api/v1/admin/a2a/trust-anchors" },
      { method: "POST", url: "/api/v1/admin/a2a/trust-anchors/999/revoke", payload: {} },
      { method: "POST", url: "/api/v1/admin/a2a/cards/import", payload: {} },
      { method: "GET", url: "/api/v1/admin/a2a/cards" },
      { method: "GET", url: "/api/v1/admin/a2a/cards/999" },
      { method: "GET", url: "/api/v1/admin/a2a/cards/999/history" },
      { method: "POST", url: "/api/v1/admin/a2a/cards/999/review", payload: {} },
      { method: "POST", url: "/api/v1/admin/a2a/cards/999/revoke", payload: {} },
      { method: "GET", url: "/api/v1/admin/a2a/audit" },
    ] as const;
    for (const route of routes) {
      const missing = await setup.app.inject(route);
      const forbidden = await setup.app.inject({ ...route, headers: setup.employee });
      expect(missing.statusCode, `${route.method} ${route.url} missing auth`).toBe(401);
      expect(forbidden.statusCode, `${route.method} ${route.url} employee auth`).toBe(403);
    }
  });

  it("sanitizes malformed and oversized JSON without touching persistent state", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const malformed = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { ...setup.admin, "content-type": "application/json" }, payload: '{"submission_id":"broken"',
    });
    expect(malformed.statusCode).toBe(400);
    expect(malformed.json()).toEqual({ detail: "Malformed request" });
    expect(malformed.body).not.toContain("submission_id");

    const oversizedPayload = JSON.stringify({
      submission_id: "oversized", card: { description: "x".repeat(1_100_000) },
      provenance: { kind: "manual", source: "test" },
    });
    const oversized = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { ...setup.admin, "content-type": "application/json" }, payload: oversizedPayload,
    });
    expect(oversized.statusCode).toBe(413);
    expect(oversized.json()).toEqual({ detail: "Request body too large" });
    expect(oversized.body).not.toContain("xxxx");
    for (const table of ["a2a_card_documents", "a2a_card_observations", "a2a_registry_audit", "a2a_mutation_submissions"]) {
      expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count), table).toBe(0);
    }
  });

  it("imports as discovered, is idempotent, trusts explicitly, and cascades anchor revocation atomically", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const testSigner = signer();
    const createdAnchor = await createAnchor(setup.app, setup.admin, testSigner);
    expect(createdAnchor.statusCode).toBe(201);
    const anchor = createdAnchor.json() as { id: number; row_version: number; state: string };

    const value = card();
    testSigner.signCard(value);
    const imported = await importCard(setup.app, setup.admin, value, "import-1");
    expect(imported.statusCode).toBe(201);
    const importBody = imported.json() as {
      card: { id: number; state: string; row_version: number; preferred_interface_uri: string; routable: boolean };
      observation_id: number;
      admission: { trust_state: string; verified_key_id: string | null; document_sha256: string; payload_sha256: string };
    };
    expect(importBody.card).toMatchObject({ state: "discovered", row_version: 1, preferred_interface_uri: "https://agent.example.test/a2a", routable: false });
    expect(importBody.admission).toMatchObject({ trust_state: "trusted", verified_key_id: testSigner.keyId });
    await expect(setup.db.execute("UPDATE a2a_trust_anchors SET row_version = 0 WHERE id = $1", [anchor.id])).rejects.toThrow();
    await expect(setup.db.execute("UPDATE a2a_card_registry SET row_version = 0 WHERE id = $1", [importBody.card.id])).rejects.toThrow();
    const documentId = asNumber((await setup.db.query<{ document_id: unknown }>("SELECT document_id FROM a2a_card_registry WHERE id = $1", [importBody.card.id]))[0]!.document_id);
    await expect(setup.db.execute(`INSERT INTO a2a_card_observations
      (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
      VALUES ($1, $2, 'invalid-provenance', 'network', 'test', NULL, $3)`, [
      importBody.card.id, setup.adminId, new Date().toISOString(),
    ])).rejects.toThrow();
    await expect(setup.db.execute(`INSERT INTO a2a_card_verifications
      (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
        document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
      VALUES ($1, $2, $3, 'trusted', $4, $5, $6, '[]', $7)`, [
      importBody.observation_id, documentId, anchor.id, testSigner.keyId,
      importBody.admission.document_sha256, importBody.admission.payload_sha256, new Date().toISOString(),
    ])).rejects.toThrow();
    await expect(setup.db.transaction(async (tx) => {
      const testObservation = (await tx.query<{ id: unknown }>(`INSERT INTO a2a_card_observations
        (registry_id, actor_id, submission_id, provenance_kind, provenance_source, provenance_detail, observed_at)
        VALUES ($1, $2, 'coherence-observation', 'migration', 'constraint-test', NULL, $3) RETURNING id`, [
        importBody.card.id, setup.adminId, new Date().toISOString(),
      ]))[0]!;
      await tx.execute(`INSERT INTO a2a_card_verifications
        (observation_id, document_id, trust_anchor_id, admission_trust_state, verified_key_id,
          document_sha256, payload_sha256, trust_anchor_snapshot_json, verified_at)
        VALUES ($1, $2, $3, 'discovered', $4, $5, $6, '[]', $7)`, [
        asNumber(testObservation.id), documentId, anchor.id, testSigner.keyId,
        importBody.admission.document_sha256, importBody.admission.payload_sha256, new Date().toISOString(),
      ]);
    })).rejects.toThrow();

    const replay = await importCard(setup.app, setup.admin, value, "import-1");
    expect(replay.statusCode).toBe(201);
    expect((replay.json() as { observation_id: number }).observation_id).toBe(importBody.observation_id);
    const mismatch = await importCard(setup.app, setup.admin, card("different"), "import-1");
    expect(mismatch.statusCode).toBe(409);

    const observedAgain = await importCard(setup.app, setup.admin, value, "import-2");
    expect((observedAgain.json() as { card: { id: number; state: string } }).card).toMatchObject({ id: importBody.card.id, state: "discovered" });
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_card_observations"))[0]!.count)).toBe(2);

    const trusted = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${importBody.card.id}/review`, headers: setup.admin,
      payload: { submission_id: "review-1", expected_version: 1, decision: "trusted", reason: "Approved explicit local key" },
    });
    expect(trusted.statusCode).toBe(200);
    expect(trusted.json()).toMatchObject({ state: "trusted", row_version: 2, trusted_anchor_id: anchor.id, verified_key_id: testSigner.keyId, routable: false });

    const revoked = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchor.id}/revoke`, headers: setup.admin,
      payload: { submission_id: "anchor-revoke-1", expected_version: anchor.row_version, reason: "Key retired" },
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json()).toMatchObject({ state: "revoked", row_version: 2, cascaded_card_ids: [importBody.card.id] });
    const cardAfter = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/cards/${importBody.card.id}`, headers: setup.admin });
    expect(cardAfter.json()).toMatchObject({ state: "revoked", row_version: 3, trusted_anchor_id: anchor.id, verified_key_id: testSigner.keyId, routable: false });

    const importReplayAfterRevoke = await importCard(setup.app, setup.admin, value, "import-1");
    expect(importReplayAfterRevoke.statusCode).toBe(201);
    expect(importReplayAfterRevoke.json()).toEqual(importBody);

    const replayedTrust = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${importBody.card.id}/review`, headers: setup.admin,
      payload: { submission_id: "review-1", expected_version: 1, decision: "trusted", reason: "Approved explicit local key" },
    });
    expect(replayedTrust.statusCode).toBe(200);
    expect(replayedTrust.json()).toMatchObject({ state: "trusted", row_version: 2, trusted_anchor_id: anchor.id });

    const terminal = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${importBody.card.id}/review`, headers: setup.admin,
      payload: { submission_id: "review-terminal", expected_version: 3, decision: "rejected", reason: "Cannot resurrect" },
    });
    expect(terminal.statusCode).toBe(409);

    const rejectedImportCounts = await setup.db.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`);
    const reimport = await importCard(setup.app, setup.admin, value, "import-after-revoke");
    expect(reimport.statusCode).toBe(422);
    expect(reimport.json()).toMatchObject({ code: "signature-key-revoked" });
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'import-after-revoke'"))[0]!.count)).toBe(0);
    const countsAfterRejectedImport = (await setup.db.query<{ documents: unknown; observations: unknown; audit: unknown }>(`SELECT
      (SELECT COUNT(*) FROM a2a_card_documents) AS documents,
      (SELECT COUNT(*) FROM a2a_card_observations) AS observations,
      (SELECT COUNT(*) FROM a2a_registry_audit) AS audit`))[0]!;
    expect([
      asNumber(countsAfterRejectedImport.documents), asNumber(countsAfterRejectedImport.observations), asNumber(countsAfterRejectedImport.audit),
    ]).toEqual([
      asNumber(rejectedImportCounts[0]!.documents), asNumber(rejectedImportCounts[0]!.observations), asNumber(rejectedImportCounts[0]!.audit),
    ]);

    const unsignedAfterRevoke = await importCard(setup.app, setup.admin, card("unsigned-after-revoke"), "unsigned-after-revoke");
    expect(unsignedAfterRevoke.statusCode).toBe(201);
    const unsignedCardId = (unsignedAfterRevoke.json() as { card: { id: number } }).card.id;
    const unsignedHistory = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/cards/${unsignedCardId}/history`, headers: setup.admin });
    const unsignedSnapshot = (unsignedHistory.json() as { verifications: { items: Array<{ trust_anchor_snapshot: Array<Record<string, unknown>> }> } })
      .verifications.items[0]!.trust_anchor_snapshot;
    expect(unsignedSnapshot).toEqual([]);
    const history = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/cards/${importBody.card.id}/history`, headers: setup.admin });
    const historyBody = history.json() as {
      observations: { items: Array<{ id: number; provenance: { kind: string } }>; next_after_id: number | null };
      verifications: { items: Array<{ observation_id: number; trust_anchor_snapshot: Array<Record<string, unknown>> }>; next_after_id: number | null };
      audit: { items: Array<{ action: string }>; next_after_id: number | null };
    };
    expect(historyBody.observations.items).toHaveLength(3);
    expect(historyBody.verifications.items).toHaveLength(3);
    const reviewObservation = historyBody.observations.items.find((entry) => entry.provenance.kind === "admin-review")!;
    expect(historyBody.verifications.items.some((entry) => entry.observation_id === reviewObservation.id)).toBe(true);
    expect(historyBody.verifications.items.every((entry) => entry.trust_anchor_snapshot.length === 1)).toBe(true);
    expect(historyBody.verifications.items.every((entry) => Object.keys(entry.trust_anchor_snapshot[0] ?? {}).sort().join(",")
      === "algorithm,id,key_fingerprint_sha256,key_id,row_version")).toBe(true);
    expect(historyBody.verifications.items.every((entry) => !("public_key_pem" in (entry.trust_anchor_snapshot[0] ?? {})))).toBe(true);
    expect(historyBody.audit.items.map((entry) => entry.action)).toContain("agent-card.revoked-by-anchor");

    await expect(setup.db.execute("UPDATE a2a_card_documents SET name = 'tampered' WHERE id = 1")).rejects.toThrow("append-only");
    await expect(setup.db.execute("DELETE FROM a2a_registry_audit")).rejects.toThrow("append-only");
  });

  it("persists nothing for malformed admission and leaves no false audit on stale rejection", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const malformed = await importCard(setup.app, setup.admin, { name: "not-a-card" }, "malformed-1");
    expect(malformed.statusCode).toBe(422);
    for (const table of ["a2a_card_documents", "a2a_card_registry", "a2a_card_observations", "a2a_card_verifications", "a2a_registry_audit", "a2a_mutation_submissions"]) {
      expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count), table).toBe(0);
    }

    const imported = await importCard(setup.app, setup.admin, card("unsigned"), "unsigned-import");
    const cardId = (imported.json() as { card: { id: number } }).card.id;
    const auditBefore = asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit"))[0]!.count);
    const stale = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${cardId}/review`, headers: setup.admin,
      payload: { submission_id: "stale-review", expected_version: 2, decision: "rejected", reason: "Stale" },
    });
    expect(stale.statusCode).toBe(409);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit"))[0]!.count)).toBe(auditBefore);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'stale-review'"))[0]!.count)).toBe(0);

    const rejected = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${cardId}/review`, headers: setup.admin,
      payload: { submission_id: "reject-review", expected_version: 1, decision: "rejected", reason: "Policy mismatch" },
    });
    expect(rejected.json()).toMatchObject({ state: "rejected", row_version: 2, trusted_anchor_id: null, verified_key_id: null, routable: false });
    const terminal = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${cardId}/revoke`, headers: setup.admin,
      payload: { submission_id: "reject-revoke", expected_version: 2, reason: "No transition" },
    });
    expect(terminal.statusCode).toBe(409);
  });

  it("maps only real unique collisions to conflict and preserves unrelated database failures", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const testSigner = signer("unique-key");
    expect((await createAnchor(setup.app, setup.admin, testSigner, "unique-anchor-1")).statusCode).toBe(201);
    expect((await createAnchor(setup.app, setup.admin, testSigner, "unique-anchor-2")).statusCode).toBe(409);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit"))[0]!.count)).toBe(1);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions"))[0]!.count)).toBe(1);

    const injectedFailure = new Error("injected storage failure");
    const failingDb: SqlDatabase = {
      dialect: setup.db.dialect,
      query: setup.db.query.bind(setup.db),
      execute: setup.db.execute.bind(setup.db),
      close: async () => {},
      transaction: (work) => setup.db.transaction((tx) => work({
        dialect: tx.dialect,
        execute: tx.execute.bind(tx),
        close: async () => {},
        transaction: tx.transaction.bind(tx),
        query: (sql, params) => {
          if (sql.includes("INSERT INTO a2a_trust_anchors")) return Promise.reject(injectedFailure);
          return tx.query(sql, params);
        },
      })),
    };
    const otherSigner = signer("storage-key");
    await expect(createTrustAnchor(failingDb, { id: setup.adminId, employeeCode: "admin-agent" }, {
      submissionId: "storage-failure", keyId: otherSigner.keyId, algorithm: "ES256", publicKeyPem: otherSigner.publicKeyPem,
    })).rejects.toBe(injectedFailure);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'storage-failure'"))[0]!.count)).toBe(0);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit"))[0]!.count)).toBe(1);
  });

  it("rejects private-key PEM without persisting or echoing secret material", async () => {
    const logs: string[] = [];
    const setup = await fixture(logs);
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const privateSentinel = "PRIVATE_KEY_SECRET_SENTINEL";
    const response = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: setup.admin,
      payload: { submission_id: "private-key", key_id: "secret-key", algorithm: "ES256", public_key_pem: `${privateKeyPem}\n${privateSentinel}` },
    });
    expect(response.statusCode).toBe(422);
    expect(response.json()).toMatchObject({ code: "trust-anchor-key-invalid" });
    expect(response.body).not.toContain(privateKeyPem.slice(0, 32));
    expect(response.body).not.toContain(privateSentinel);

    const cardSentinel = "MALFORMED_CARD_SECRET_SENTINEL";
    const malformedCard = await importCard(setup.app, setup.admin, { name: cardSentinel }, "secret-card");
    expect(malformedCard.statusCode).toBe(422);
    expect(malformedCard.body).not.toContain(cardSentinel);
    const jsonSentinel = "MALFORMED_JSON_SECRET_SENTINEL";
    const malformedJson = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/cards/import",
      headers: { ...setup.admin, "content-type": "application/json" },
      payload: `{"submission_id":"${jsonSentinel}"`,
    });
    expect(malformedJson.statusCode).toBe(400);
    expect(malformedJson.body).not.toContain(jsonSentinel);
    const unknownKeySentinel = "UNKNOWN_REQUEST_KEY_SECRET_SENTINEL";
    const unknownKey = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: setup.admin,
      payload: {
        submission_id: "unknown-key", key_id: "unknown-key", algorithm: "ES256",
        public_key_pem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
        [unknownKeySentinel]: "raw-rejected-value",
      },
    });
    expect(unknownKey.statusCode).toBe(422);
    expect(unknownKey.json()).toEqual({ code: "invalid-request", detail: "Request validation failed" });
    expect(unknownKey.body).not.toContain(unknownKeySentinel);
    const logText = logs.join("\n");
    for (const secret of [privateSentinel, cardSentinel, jsonSentinel, unknownKeySentinel, "raw-rejected-value", privateKeyPem.slice(0, 32)]) {
      expect(logText).not.toContain(secret);
    }
    for (const table of ["a2a_trust_anchors", "a2a_registry_audit", "a2a_mutation_submissions"]) {
      expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count), table).toBe(0);
    }
  });

  it("bounds card and history pages with explicit cursors", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    for (const version of ["page-1", "page-2", "page-3"]) {
      expect((await importCard(setup.app, setup.admin, card(version), `import-${version}`)).statusCode).toBe(201);
    }
    const first = await setup.app.inject({ method: "GET", url: "/api/v1/admin/a2a/cards?limit=2", headers: setup.admin });
    const firstBody = first.json() as { items: Array<{ id: number }>; next_after_id: number | null };
    expect(firstBody.items).toHaveLength(2);
    expect(firstBody.next_after_id).toBe(firstBody.items[1]!.id);
    const second = await setup.app.inject({
      method: "GET", url: `/api/v1/admin/a2a/cards?limit=2&after_id=${firstBody.next_after_id}`, headers: setup.admin,
    });
    expect(second.json()).toMatchObject({ items: [{ id: 3 }], next_after_id: null });

    const history = await setup.app.inject({
      method: "GET", url: "/api/v1/admin/a2a/cards/1/history?limit=1", headers: setup.admin,
    });
    expect(history.json()).toMatchObject({
      observations: { items: [{ id: 1 }], next_after_id: null },
      verifications: { items: [{ id: 1 }], next_after_id: null },
    });
  });

  it("rejects preferred-interface URI expansion before persistence", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const expanded = card("expanded-uri", `https://agent.example.test/${"가".repeat(680)}`);
    const response = await importCard(setup.app, setup.admin, expanded, "expanded-uri");
    expect(response.statusCode).toBe(422);
    expect(response.json()).toEqual({ code: "agent-card-invalid", detail: "Agent Card is invalid" });
    for (const table of ["a2a_card_documents", "a2a_card_registry", "a2a_card_observations", "a2a_card_verifications", "a2a_registry_audit", "a2a_mutation_submissions"]) {
      expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count), table).toBe(0);
    }
  });

  it("allows only one trusted card per canonical preferred interface under concurrency", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const testSigner = signer("interface-key");
    expect((await createAnchor(setup.app, setup.admin, testSigner)).statusCode).toBe(201);
    const firstCard = card("1.0.0", "https://AGENT.example.test:443/a2a");
    const secondCard = card("2.0.0", "https://agent.example.test/a2a");
    testSigner.signCard(firstCard);
    testSigner.signCard(secondCard);
    const firstId = ((await importCard(setup.app, setup.admin, firstCard, "race-import-1")).json() as { card: { id: number } }).card.id;
    const secondId = ((await importCard(setup.app, setup.admin, secondCard, "race-import-2")).json() as { card: { id: number } }).card.id;
    const responses = await Promise.all([firstId, secondId].map((id, index) => setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/cards/${id}/review`, headers: setup.admin,
      payload: { submission_id: `race-review-${index}`, expected_version: 1, decision: "trusted", reason: "Concurrent approval" },
    })));
    expect(responses.map((response) => response.statusCode).sort()).toEqual([200, 409]);
    const states = await setup.app.inject({ method: "GET", url: "/api/v1/admin/a2a/cards", headers: setup.admin });
    const items = (states.json() as { items: Array<{ state: string; preferred_interface_uri: string; routable: boolean }> }).items;
    expect(items.filter((item) => item.state === "trusted")).toHaveLength(1);
    expect(items.every((item) => item.preferred_interface_uri === "https://agent.example.test/a2a" && item.routable === false)).toBe(true);
    expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_registry_audit WHERE action = 'agent-card.trusted'"))[0]!.count)).toBe(1);
  });

  it("linearizes import verification against concurrent local anchor revocation", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const testSigner = signer("linear-key");
    const anchor = (await createAnchor(setup.app, setup.admin, testSigner)).json() as { id: number; row_version: number };
    const value = card("linear");
    testSigner.signCard(value);
    const [imported, revoked] = await Promise.all([
      importCard(setup.app, setup.admin, value, "linear-import"),
      setup.app.inject({
        method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${anchor.id}/revoke`, headers: setup.admin,
        payload: { submission_id: "linear-revoke", expected_version: anchor.row_version, reason: "Concurrent retirement" },
      }),
    ]);
    expect(revoked.statusCode).toBe(200);
    expect([201, 422]).toContain(imported.statusCode);
    const audits = await setup.db.query<{ id: unknown; action: unknown }>("SELECT id, action FROM a2a_registry_audit ORDER BY id");
    const revokedId = asNumber(audits.find((row) => row.action === "trust-anchor.revoked")!.id);
    if (imported.statusCode === 201) {
      const admission = (imported.json() as { admission: { trust_state: string } }).admission;
      expect(admission.trust_state).toBe("trusted");
      const observedId = asNumber(audits.find((row) => row.action === "agent-card.observed")!.id);
      expect(observedId).toBeLessThan(revokedId);
    } else {
      expect(imported.json()).toMatchObject({ code: "signature-key-revoked" });
      expect(asNumber((await setup.db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM a2a_mutation_submissions WHERE submission_id = 'linear-import'"))[0]!.count)).toBe(0);
    }
  });

  it("keeps the persistent registry free of hidden network, filesystem, process, tool, or runner I/O", async () => {
    const source = await readFile(new URL("../src/a2a/agent-card-store.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/node:(?:fs|child_process)|\bfetch\s*\(|\bspawn\s*\(|\bexec\s*\(|tool|runner/i);
  });
});
