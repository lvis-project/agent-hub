import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalizeAgentCardPayload } from "../src/a2a/agent-card-registry.js";
import {
  DiscoveryBoundaryError,
  type DiscoveryTransport,
  type DiscoveryTransportRequest,
  type DiscoveryTransportResponse,
} from "../src/a2a/discovery-egress.js";
import { claimRevalidation, completeDiscoveryFailure } from "../src/a2a/discovery-store.js";
import { buildApp } from "../src/app.js";
import type { Settings } from "../src/config.js";
import { asNumber, asString, createDatabase, type SqlDatabase } from "../src/db.js";
import { migrate } from "../src/migrations.js";

const settings: Settings = {
  databaseUrl: "sqlite://:memory:", host: "127.0.0.1", port: 8000, logLevel: "silent",
  rateLimitPerIpPerMinute: 1_000, signupRateLimitPerIpPerMinute: 100,
  trustedProxyIps: [], corsOrigins: ["http://localhost:5174"], tlsHstsMaxAge: 0,
  credentialReferenceHmacKey: "test-only-credential-reference-key-0001",
};

function card(version = "1.0.0"): Record<string, unknown> {
  return {
    name: "Discovered Work Assistant",
    description: "Metadata-only discovery fixture.",
    version,
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    skills: [{
      id: "delegate-work", name: "Delegate work", description: "Run one bounded work item.",
      tags: ["delegation"], inputModes: ["text/plain"], outputModes: ["text/plain"],
    }],
    supportedInterfaces: [{ url: "https://runtime.example.test/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"],
    securitySchemes: { bearerAuth: { httpAuthSecurityScheme: { scheme: "bearer", bearerFormat: "opaque" } } },
    securityRequirements: [{ schemes: { bearerAuth: { list: [] } } }],
  };
}

function transportResponse(
  body: string,
  overrides: Partial<DiscoveryTransportResponse> = {},
): DiscoveryTransportResponse {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json", "cache-control": "max-age=60" },
    body: Buffer.from(body),
    ...overrides,
  };
}

type TransportStep = DiscoveryTransportResponse | Error | ((input: DiscoveryTransportRequest) => DiscoveryTransportResponse | Promise<DiscoveryTransportResponse>);

class ScriptedTransport implements DiscoveryTransport {
  readonly inputs: DiscoveryTransportRequest[] = [];
  constructor(readonly steps: TransportStep[]) {}
  async request(input: DiscoveryTransportRequest): Promise<DiscoveryTransportResponse> {
    this.inputs.push(input);
    const step = this.steps.shift();
    if (step === undefined) throw new Error("Unexpected discovery network request");
    if (step instanceof Error) throw step;
    return typeof step === "function" ? step(input) : step;
  }
}

class MutableClock {
  constructor(public value: number, public monotonicValue = 0) {}
  wallNow() { return this.value; }
  monotonicNow() { return this.monotonicValue; }
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

async function fixture(input: { transport?: DiscoveryTransport; clock?: MutableClock } = {}) {
  const db = createDatabase("sqlite://:memory:");
  await migrate(db);
  const adminId = await seedActor(db, "admin-discovery", "admin", "admin-token");
  await seedActor(db, "employee-discovery", "employee", "employee-token");
  const app = await buildApp({
    database: db, settings, migrate: false,
    testOnlyDiscoveryDependencies: {
      transport: input.transport,
      clock: input.clock,
      resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 }]; } },
    },
  });
  return {
    db, app, adminId,
    admin: { authorization: "Bearer admin-token" },
    employee: { authorization: "Bearer employee-token" },
  };
}

async function count(db: SqlDatabase, table: string): Promise<number> {
  return asNumber((await db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM ${table}`))[0]!.count);
}

async function createTarget(setup: Awaited<ReturnType<typeof fixture>>, submissionId = "target-1", origin = "https://agent.example") {
  return setup.app.inject({
    method: "POST", url: "/api/v1/admin/a2a/discovery-targets", headers: setup.admin,
    payload: { submission_id: submissionId, origin },
  });
}

async function revalidate(setup: Awaited<ReturnType<typeof fixture>>, targetId: number, submissionId: string, expectedVersion = 1) {
  return setup.app.inject({
    method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${targetId}/revalidate`, headers: setup.admin,
    payload: { submission_id: submissionId, expected_version: expectedVersion },
  });
}

function signedCardAndJwks(jku = "https://agent.example/keys.jwks") {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const keyId = "agent-signing-key";
  const value = card();
  const protectedHeader = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JOSE", jku })).toString("base64url");
  const payload = canonicalizeAgentCardPayload(value);
  const signature = sign("sha256", Buffer.from(`${protectedHeader}.${payload.toString("base64url")}`, "ascii"), {
    key: pair.privateKey, dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  value.signatures = [{ protected: protectedHeader, signature }];
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  return {
    card: value,
    jwks: { keys: [{ ...publicJwk, kid: keyId, alg: "ES256", use: "sig", key_ops: ["verify"] }] },
  };
}

describe("G003 bounded Agent Card discovery and metadata health", () => {
  const close: Array<() => Promise<void>> = [];
  afterEach(async () => { await Promise.all(close.splice(0).map((work) => work())); });

  it("rejects discovery dependency overrides outside the test runtime", async () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      await expect(buildApp({
        testOnlyDiscoveryDependencies: {
          resolver: { async resolve() { return [{ address: "8.8.8.8", family: 4 }]; } },
        },
      })).rejects.toThrow("Discovery dependency overrides are test-only");
    } finally {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    }
  });

  it("authenticates every G003 route before parsing and leaves zero G003 state", async () => {
    const transport = new ScriptedTransport([]);
    const setup = await fixture({ transport });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const malformed = '{"submission_id":"broken"';
    const routes = [
      { method: "POST", url: "/api/v1/admin/a2a/discovery-targets", payload: malformed },
      { method: "GET", url: "/api/v1/admin/a2a/discovery-targets?limit=invalid" },
      { method: "POST", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/disable", payload: malformed },
      { method: "POST", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/revalidate", payload: malformed },
      { method: "GET", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/attempts?limit=invalid" },
      { method: "GET", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/discovery-health" },
      { method: "GET", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/key-revisions?limit=invalid" },
      { method: "POST", url: "/api/v1/admin/a2a/key-revisions/not-a-number/activate", payload: malformed },
      { method: "POST", url: "/api/v1/admin/a2a/key-revisions/not-a-number/revoke", payload: malformed },
      { method: "POST", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/credential-bindings", payload: malformed },
      { method: "GET", url: "/api/v1/admin/a2a/discovery-targets/not-a-number/credential-bindings?limit=invalid" },
      { method: "POST", url: "/api/v1/admin/a2a/credential-bindings/not-a-number/rotate", payload: malformed },
      { method: "POST", url: "/api/v1/admin/a2a/credential-bindings/not-a-number/revoke", payload: malformed },
    ] as const;
    for (const route of routes) {
      for (const headers of [undefined, setup.employee]) {
        const response = await setup.app.inject({
          method: route.method, url: route.url,
          ...(headers === undefined ? {} : { headers: { ...headers, "content-type": "application/json" } }),
          ...("payload" in route ? { payload: route.payload } : {}),
        });
        expect(response.statusCode, `${route.method} ${route.url}`).toBe(headers === undefined ? 401 : 403);
      }
    }
    expect(transport.inputs).toHaveLength(0);
    for (const table of ["a2a_admin_operations", "a2a_discovery_targets", "a2a_discovery_attempts", "a2a_discovery_health", "a2a_g003_audit"]) {
      expect(await count(setup.db, table), table).toBe(0);
    }
  });

  it("canonicalizes target identity before UNIQUE and enforces global submission identity without network I/O", async () => {
    const transport = new ScriptedTransport([]);
    const setup = await fixture({ transport });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const created = await createTarget(setup, "global-submission", "https://BÜCHER.Example.");
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({
      canonical_origin: "https://xn--bcher-kva.example",
      canonical_domain: "xn--bcher-kva.example",
      card_url: "https://xn--bcher-kva.example/.well-known/agent-card.json",
      state: "active", routable: false,
    });
    const replay = await createTarget(setup, "global-submission", "https://xn--bcher-kva.example");
    expect(replay.statusCode).toBe(201);
    expect(replay.json()).toEqual(created.json());

    const mismatch = await createTarget(setup, "global-submission", "https://other.example");
    expect(mismatch.statusCode).toBe(409);
    expect(mismatch.json()).toMatchObject({ code: "submission-mismatch" });
    const crossOperation = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${created.json().id as number}/disable`, headers: setup.admin,
      payload: { submission_id: "global-submission", expected_version: 1, reason: "must conflict" },
    });
    expect(crossOperation.statusCode).toBe(409);
    expect(await count(setup.db, "a2a_admin_operations")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_targets")).toBe(1);
    expect(transport.inputs).toHaveLength(0);

    const operation = (await setup.db.query<Record<string, unknown>>("SELECT * FROM a2a_admin_operations"))[0]!;
    expect(asString(operation.operation_kind)).toBe("discovery-target.create");
    expect(asString(operation.semantic_request_hash)).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("shares the canonical employee submission namespace with P4-2 in both directions", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const publicKey = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey
      .export({ type: "spki", format: "pem" }).toString();
    const p4First = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: setup.admin,
      payload: {
        submission_id: "cross-phase-p4-first", key_id: "cross-phase-p4-first",
        algorithm: "ES256", public_key_pem: publicKey,
      },
    });
    expect(p4First.statusCode).toBe(201);
    const g003Loser = await createTarget(setup, "cross-phase-p4-first", "https://cross-phase-one.example");
    expect(g003Loser.statusCode).toBe(409);
    expect(g003Loser.json()).toMatchObject({ code: "submission-mismatch" });
    expect(await count(setup.db, "a2a_admin_operations")).toBe(0);
    expect(await count(setup.db, "a2a_discovery_targets")).toBe(0);

    const g003First = await createTarget(setup, "cross-phase-g003-first", "https://cross-phase-two.example");
    expect(g003First.statusCode).toBe(201);
    const p4Loser = await setup.app.inject({
      method: "POST", url: "/api/v1/admin/a2a/trust-anchors", headers: setup.admin,
      payload: {
        submission_id: "cross-phase-g003-first", key_id: "cross-phase-g003-first",
        algorithm: "ES256", public_key_pem: publicKey,
      },
    });
    expect(p4Loser.statusCode).toBe(409);
    expect(p4Loser.json()).toMatchObject({ code: "submission-mismatch" });
    expect(await count(setup.db, "a2a_trust_anchors")).toBe(1);
    expect(await count(setup.db, "a2a_admin_operations")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_targets")).toBe(1);
  });

  it("commits unsigned metadata as discovered, derives freshness, and makes exact replay zero-I/O", async () => {
    const clock = new MutableClock(Date.parse("2026-07-16T00:00:00.000Z"));
    const transport = new ScriptedTransport([
      transportResponse(JSON.stringify(card()), { headers: { "content-type": "application/json", "cache-control": "max-age=60", etag: '"card-v1"' } }),
    ]);
    const setup = await fixture({ transport, clock });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    clock.value += 1_000;
    const discovered = await revalidate(setup, target.id, "discover-1");
    expect(discovered.statusCode, discovered.body).toBe(200);
    expect(discovered.json()).toMatchObject({ outcome: "succeeded", metadata_health: "healthy", routable: false });
    expect(transport.inputs).toHaveLength(1);
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_documents")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_cache_entries")).toBe(1);
    expect(asString((await setup.db.query<{ state: unknown }>("SELECT state FROM a2a_card_registry"))[0]!.state)).toBe("discovered");

    const replay = await revalidate(setup, target.id, "discover-1");
    expect(replay.json()).toEqual(discovered.json());
    expect(transport.inputs).toHaveLength(1);
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(1);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(1);

    const healthy = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/discovery-health`, headers: setup.admin });
    expect(healthy.json()).toMatchObject({ metadata_health: "healthy", semantics: "Agent Card/JWKS metadata endpoint only", routable: false });
    clock.value += 60_000;
    const stale = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/discovery-health`, headers: setup.admin });
    expect(stale.json()).toMatchObject({ metadata_health: "stale", last_observed_health: "healthy", reason_code: "metadata-stale", routable: false });
  });

  it("maps endpoint and representation failures exactly and replays failures without a second attempt", async () => {
    const clock = new MutableClock(Date.parse("2026-07-16T01:00:00.000Z"));
    const transport = new ScriptedTransport([
      new DiscoveryBoundaryError("connect-rejected", 502),
      new DiscoveryBoundaryError("headers-too-large", 502),
    ]);
    const setup = await fixture({ transport, clock });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const firstTarget = (await createTarget(setup, "target-failure-1", "https://one.example")).json() as { id: number };
    const unreachable = await revalidate(setup, firstTarget.id, "failure-unreachable");
    expect(unreachable.json()).toMatchObject({ code: "connect-rejected", metadata_health: "unreachable", routable: false });
    const replay = await revalidate(setup, firstTarget.id, "failure-unreachable");
    expect(replay.json()).toEqual(unreachable.json());
    expect(transport.inputs).toHaveLength(1);

    const secondTarget = (await createTarget(setup, "target-failure-2", "https://two.example")).json() as { id: number };
    const invalid = await revalidate(setup, secondTarget.id, "failure-invalid");
    expect(invalid.json()).toMatchObject({ code: "headers-too-large", metadata_health: "invalid", routable: false });
    expect(transport.inputs).toHaveLength(2);
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(2);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(2);
  });

  it("terminalizes pre-network claim rejection, single-flight, and expired recovery without endpoint evidence", async () => {
    const clock = new MutableClock(Date.parse("2026-07-16T01:30:00.000Z"));
    const transport = new ScriptedTransport([]);
    const setup = await fixture({ transport, clock });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };

    const missing = await revalidate(setup, 999_999, "claim-missing");
    expect(missing.statusCode).toBe(404);
    expect(missing.json()).toMatchObject({ code: "target-not-found", routable: false });
    const stale = await revalidate(setup, target.id, "claim-stale", 2);
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toMatchObject({ code: "stale-version", routable: false });
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(0);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(0);
    expect(transport.inputs).toHaveLength(0);

    const claimed = await claimRevalidation(setup.db, { id: setup.adminId, employeeCode: "admin-discovery" }, {
      targetId: target.id, submissionId: "lease-owner", expectedVersion: 1, nowMs: clock.value,
    });
    expect(claimed.claim).not.toBeNull();
    const busy = await revalidate(setup, target.id, "lease-contender");
    expect(busy.statusCode).toBe(409);
    expect(busy.json()).toMatchObject({ code: "target-busy" });
    const disable = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/disable`, headers: setup.admin,
      payload: { submission_id: "disable-busy", expected_version: 1, reason: "must wait" },
    });
    expect(disable.statusCode).toBe(409);
    expect(disable.json()).toMatchObject({ code: "target-busy" });

    clock.value += 120_001;
    const recovered = await revalidate(setup, target.id, "lease-owner");
    expect(recovered.statusCode).toBe(500);
    expect(recovered.json()).toMatchObject({ code: "persistence-failed", routable: false });
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(0);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(0);
    expect(transport.inputs).toHaveLength(0);
    await expect(completeDiscoveryFailure(setup.db, {
      claim: claimed.claim!, errorCode: "connect-rejected", completedAtMs: clock.value,
    })).rejects.toMatchObject({ statusCode: 409, code: "operation-fenced" });
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(0);
  });

  it("rejects a corrupted stored target identity before DNS or endpoint I/O", async () => {
    const transport = new ScriptedTransport([]);
    const setup = await fixture({ transport });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    await setup.db.execute("DROP TRIGGER a2a_discovery_targets_identity_immutable");
    await setup.db.execute("UPDATE a2a_discovery_targets SET card_url = 'https://attacker.example/card' WHERE id = $1", [target.id]);
    const result = await revalidate(setup, target.id, "target-corrupted");
    expect(result.statusCode).toBe(422);
    expect(result.json()).toMatchObject({ code: "target-invalid", routable: false });
    expect(transport.inputs).toHaveLength(0);
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(0);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(0);
  });

  it("reuses exact cached bytes on 304, rejects cache tampering, and never falls back to P4-2 bytes", async () => {
    const clock = new MutableClock(Date.parse("2026-07-16T02:00:00.000Z"));
    const serialized = JSON.stringify(card());
    const transport = new ScriptedTransport([
      transportResponse(serialized, { headers: { "content-type": "application/json", etag: '"v1"', "cache-control": "max-age=60" } }),
      (input) => {
        expect(input.headers["If-None-Match"]).toBe('"v1"');
        return transportResponse("", { statusCode: 304, headers: { etag: '"v1"', "cache-control": "max-age=120" }, body: Buffer.alloc(0) });
      },
      transportResponse("", { statusCode: 304, headers: { etag: '"v1"', "cache-control": "max-age=120" }, body: Buffer.alloc(0) }),
    ]);
    const setup = await fixture({ transport, clock });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    expect((await revalidate(setup, target.id, "cache-200")).statusCode).toBe(200);
    const original = (await setup.db.query<{ id: unknown; body_sha256: unknown; body_blob: unknown }>("SELECT id, body_sha256, body_blob FROM a2a_discovery_documents"))[0]!;
    clock.value += 1_000;
    const notModified = await revalidate(setup, target.id, "cache-304");
    expect(notModified.json()).toMatchObject({ outcome: "not_modified", metadata_health: "healthy" });
    expect(await count(setup.db, "a2a_discovery_documents")).toBe(1);
    const attempts = await setup.db.query<{ card_sha256: unknown }>("SELECT card_sha256 FROM a2a_discovery_attempts ORDER BY id");
    expect(attempts.map((row) => asString(row.card_sha256))).toEqual([asString(original.body_sha256), asString(original.body_sha256)]);

    await setup.db.execute("DROP TRIGGER a2a_discovery_documents_no_update");
    await setup.db.execute("UPDATE a2a_discovery_documents SET body_blob = $1 WHERE id = $2", [Buffer.from("{}"), asNumber(original.id)]);
    clock.value += 1_000;
    const tampered = await revalidate(setup, target.id, "cache-tampered");
    expect(tampered.json()).toMatchObject({ code: "cache-miss", routable: false });
    expect(await count(setup.db, "a2a_discovery_attempts")).toBe(2);
    expect(await count(setup.db, "a2a_discovery_health")).toBe(2);
    expect(transport.inputs).toHaveLength(3);
  });

  it("honors no-store without G003 blobs while still importing P4-2 discovered business state", async () => {
    const clock = new MutableClock(Date.parse("2026-07-16T03:00:00.000Z"));
    const transport = new ScriptedTransport([
      transportResponse(JSON.stringify(card()), { headers: { "content-type": "application/json", "cache-control": "no-store", etag: '"must-not-store"' } }),
    ]);
    const setup = await fixture({ transport, clock });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    const result = await revalidate(setup, target.id, "no-store");
    expect(result.statusCode).toBe(200);
    expect(await count(setup.db, "a2a_discovery_documents")).toBe(0);
    expect(await count(setup.db, "a2a_discovery_cache_entries")).toBe(0);
    expect(await count(setup.db, "a2a_card_documents")).toBe(1);
    const health = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/discovery-health`, headers: setup.admin });
    expect(health.json()).toMatchObject({ metadata_health: "stale", last_observed_health: "healthy" });
  });

  it("observes signed JWKS keys, requires explicit activation, blocks direct anchor revoke, and cascades managed revoke", async () => {
    const signed = signedCardAndJwks();
    const transport = new ScriptedTransport([
      transportResponse(JSON.stringify(signed.card)),
      transportResponse(JSON.stringify(signed.jwks)),
    ]);
    const setup = await fixture({ transport });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    const discovery = await revalidate(setup, target.id, "signed-discovery");
    expect(discovery.statusCode, discovery.body).toBe(200);
    const keys = await setup.app.inject({ method: "GET", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/key-revisions`, headers: setup.admin });
    const revision = (keys.json() as { items: Array<{ id: number; state: string; row_version: number; linked_trust_anchor_id: number | null }> }).items[0]!;
    expect(revision).toMatchObject({ state: "observed", row_version: 1, linked_trust_anchor_id: null });

    const activated = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/key-revisions/${revision.id}/activate`, headers: setup.admin,
      payload: { submission_id: "key-activate", expected_version: 1, reason: "  approve discovered key  " },
    });
    expect(activated.statusCode).toBe(200);
    const activeRevision = activated.json() as { row_version: number; linked_trust_anchor_id: number; state: string; decision_reason: string };
    expect(activeRevision).toMatchObject({ state: "active", row_version: 2, decision_reason: "approve discovered key" });
    const activationReplay = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/key-revisions/${revision.id}/activate`, headers: setup.admin,
      payload: { submission_id: "key-activate", expected_version: 1, reason: "approve discovered key" },
    });
    expect(activationReplay.statusCode).toBe(200);
    expect(activationReplay.json()).toEqual(activated.json());
    const activationDrift = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/key-revisions/${revision.id}/activate`, headers: setup.admin,
      payload: { submission_id: "key-activate", expected_version: 1, reason: "different approval basis" },
    });
    expect(activationDrift.statusCode).toBe(409);
    expect(asString((await setup.db.query<{ decision_reason: unknown }>(
      "SELECT decision_reason FROM a2a_managed_key_revisions WHERE id = $1", [revision.id],
    ))[0]!.decision_reason)).toBe("approve discovered key");
    expect(asString((await setup.db.query<{ reason: unknown }>(
      "SELECT reason FROM a2a_g003_audit WHERE action = 'managed-key.activated'", [],
    ))[0]!.reason)).toBe("approve discovered key");

    const directRevoke = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/trust-anchors/${activeRevision.linked_trust_anchor_id}/revoke`, headers: setup.admin,
      payload: { submission_id: "direct-anchor-revoke", expected_version: 1, reason: "must be managed" },
    });
    expect(directRevoke.statusCode).toBe(409);
    expect(directRevoke.json()).toMatchObject({ code: "managed-anchor-revoke-required" });

    const disabled = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/disable`, headers: setup.admin,
      payload: { submission_id: "disable-before-key-revoke", expected_version: 1, reason: "metadata endpoint retired" },
    });
    expect(disabled.statusCode).toBe(200);

    const revoked = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/key-revisions/${revision.id}/revoke`, headers: setup.admin,
      payload: { submission_id: "key-revoke", expected_version: 2, reason: "retire observed key" },
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json()).toMatchObject({ state: "revoked", row_version: 3 });
    expect(asString((await setup.db.query<{ state: unknown }>("SELECT state FROM a2a_trust_anchors WHERE id = $1", [activeRevision.linked_trust_anchor_id]))[0]!.state)).toBe("revoked");
  });

  it("isolates changed same-kid material, audits the finding, and blocks activation after target disable", async () => {
    const firstSigned = signedCardAndJwks();
    const changedSigned = signedCardAndJwks();
    const transport = new ScriptedTransport([
      transportResponse(JSON.stringify(firstSigned.card)),
      transportResponse(JSON.stringify(firstSigned.jwks)),
      transportResponse(JSON.stringify(changedSigned.card)),
      transportResponse(JSON.stringify(changedSigned.jwks)),
    ]);
    const setup = await fixture({ transport });
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number };
    expect((await revalidate(setup, target.id, "same-kid-first")).statusCode).toBe(200);
    const changed = await revalidate(setup, target.id, "same-kid-changed");
    expect(changed.statusCode).toBe(200);
    expect(changed.json()).toMatchObject({
      key_findings: [{ code: "same-kid-material-changed", key_id: "agent-signing-key" }],
      routable: false,
    });
    const revisions = await setup.db.query<{ id: unknown; state: unknown }>(
      "SELECT id, state FROM a2a_managed_key_revisions ORDER BY id",
    );
    expect(revisions).toHaveLength(2);
    expect(revisions.map((row) => asString(row.state))).toEqual(["observed", "observed"]);
    expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM a2a_g003_audit
      WHERE action = 'managed-key.material-changed' AND reason = 'same-kid-material-changed'`))[0]!.count)).toBe(1);
    expect(await count(setup.db, "a2a_trust_anchors")).toBe(0);

    const disabled = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/disable`, headers: setup.admin,
      payload: { submission_id: "disable-before-key-activation", expected_version: 1, reason: "target retired" },
    });
    expect(disabled.statusCode).toBe(200);
    const activation = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/key-revisions/${asNumber(revisions[1]!.id)}/activate`, headers: setup.admin,
      payload: { submission_id: "activate-disabled-target", expected_version: 1, reason: "approve changed key" },
    });
    expect(activation.statusCode).toBe(409);
    expect(activation.json()).toMatchObject({ code: "target-disabled" });
    expect(await count(setup.db, "a2a_trust_anchors")).toBe(0);
  });

  it("keeps credential secrets opaque across API/audit and enforces exactly one active same-binding revision", async () => {
    const setup = await fixture();
    close.push(async () => { await setup.app.close(); await setup.db.close(); });
    const target = (await createTarget(setup)).json() as { id: number; canonical_origin: string };
    const firstSecret = "vault://agent.example/credential/v1";
    const created = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`, headers: setup.admin,
      payload: {
        submission_id: "credential-create", origin: target.canonical_origin,
        scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1",
        secret_reference: firstSecret,
      },
    });
    expect(created.statusCode).toBe(201);
    expect(created.body).not.toContain(firstSecret);
    expect(created.json()).toMatchObject({ provider: "vault", external_version: "v1", routable: false });
    const binding = created.json() as { id: number; row_version: number; active_revision_id: number };
    const replay = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`, headers: setup.admin,
      payload: {
        submission_id: "credential-create", origin: target.canonical_origin,
        scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1",
        secret_reference: firstSecret,
      },
    });
    expect(replay.statusCode).toBe(201);
    expect(replay.json()).toMatchObject({ id: binding.id, provider: "vault", external_version: "v1" });
    const metadataConflict = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`, headers: setup.admin,
      payload: {
        submission_id: "credential-create", origin: target.canonical_origin,
        scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1-drift",
        secret_reference: firstSecret,
      },
    });
    expect(metadataConflict.statusCode).toBe(409);
    const storedRevision = (await setup.db.query<{
      provider: unknown; external_version: unknown; secret_reference_hmac_sha256: unknown;
    }>(
      "SELECT provider, external_version, secret_reference_hmac_sha256 FROM a2a_credential_revisions WHERE binding_id = $1",
      [binding.id],
    ))[0]!;
    expect(storedRevision).toMatchObject({ provider: "vault", external_version: "v1" });
    const storedHmac = asString(storedRevision.secret_reference_hmac_sha256);
    expect(storedHmac).toBe(createHmac("sha256", settings.credentialReferenceHmacKey!).update(firstSecret).digest("hex"));
    expect(storedHmac).not.toBe(createHmac("sha256", "different-test-audit-key-0000000001").update(firstSecret).digest("hex"));
    const secondSecret = "vault://agent.example/credential/v2";
    const rotated = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/rotate`, headers: setup.admin,
      payload: {
        submission_id: "credential-rotate", expected_version: 1,
        provider: "vault", external_version: "v2", secret_reference: secondSecret,
      },
    });
    expect(rotated.statusCode).toBe(200);
    expect(rotated.body).not.toContain(secondSecret);
    expect(rotated.json()).toMatchObject({ provider: "vault", external_version: "v2", routable: false });
    const listed = await setup.app.inject({
      method: "GET", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`, headers: setup.admin,
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.json()).toMatchObject({ items: [{ id: binding.id, provider: "vault", external_version: "v2" }] });
    expect(await count(setup.db, "a2a_credential_revisions")).toBe(2);
    expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM a2a_credential_revisions
      WHERE binding_id = $1 AND state = 'active'`, [binding.id]))[0]!.count)).toBe(1);
    expect(await count(setup.db, "a2a_credential_active_revisions")).toBe(1);
    const activeRevisionId = asNumber((await setup.db.query<{ active_revision_id: unknown }>(
      "SELECT active_revision_id FROM a2a_credential_bindings WHERE id = $1", [binding.id],
    ))[0]!.active_revision_id);
    await expect(setup.db.execute(
      "UPDATE a2a_credential_revisions SET state = 'revoked' WHERE id = $1", [activeRevisionId],
    )).rejects.toThrow(/credential revision link mismatch/u);
    const auditText = JSON.stringify(await setup.db.query("SELECT metadata_json FROM a2a_g003_audit"));
    const operationText = JSON.stringify(await setup.db.query("SELECT response_json FROM a2a_admin_operations"));
    for (const secret of [firstSecret, secondSecret, createHash("sha256").update(firstSecret).digest("hex"), createHash("sha256").update(secondSecret).digest("hex")]) {
      expect(auditText).not.toContain(secret);
      expect(operationText).not.toContain(secret);
    }

    const disabled = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/disable`, headers: setup.admin,
      payload: { submission_id: "disable-before-credential-revoke", expected_version: 1, reason: "target retired" },
    });
    expect(disabled.statusCode).toBe(200);
    const blockedRotation = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/rotate`, headers: setup.admin,
      payload: {
        submission_id: "credential-rotate-disabled", expected_version: 2,
        provider: "vault", external_version: "v3", secret_reference: "vault://agent.example/credential/v3",
      },
    });
    expect(blockedRotation.statusCode).toBe(409);
    expect(blockedRotation.json()).toMatchObject({ code: "target-disabled" });
    expect(await count(setup.db, "a2a_credential_revisions")).toBe(2);

    const revoked = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/revoke`, headers: setup.admin,
      payload: { submission_id: "credential-revoke", expected_version: 2, reason: "credential retired" },
    });
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json()).toMatchObject({
      state: "revoked", row_version: 3, active_revision_id: null,
      provider: "vault", external_version: "v2", routable: false,
    });
    const revokedList = await setup.app.inject({
      method: "GET",
      url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings?state=revoked`,
      headers: setup.admin,
    });
    expect(revokedList.statusCode).toBe(200);
    expect(revokedList.json()).toMatchObject({
      items: [{ id: binding.id, provider: "vault", external_version: "v2", routable: false }],
    });
    expect(asNumber((await setup.db.query<{ count: unknown }>(`SELECT COUNT(*) AS count FROM a2a_credential_revisions
      WHERE binding_id = $1 AND state = 'active'`, [binding.id]))[0]!.count)).toBe(0);
    expect(await count(setup.db, "a2a_credential_active_revisions")).toBe(0);
  });

  it("fails every credential mutation and replay closed when the dedicated HMAC key is unavailable", async () => {
    const setup = await fixture();
    const target = (await createTarget(setup)).json() as { id: number; canonical_origin: string };
    const created = await setup.app.inject({
      method: "POST", url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`, headers: setup.admin,
      payload: {
        submission_id: "credential-keyed-create", origin: target.canonical_origin,
        scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1",
        secret_reference: "vault://agent.example/keyed/v1",
      },
    });
    expect(created.statusCode).toBe(201);
    const binding = created.json() as { id: number };
    await setup.app.close();
    const noKeyApp = await buildApp({
      database: setup.db,
      settings: { ...settings, credentialReferenceHmacKey: null },
      migrate: false,
    });
    close.push(async () => { await noKeyApp.close(); await setup.db.close(); });
    const requests = [
      {
        method: "POST" as const,
        url: `/api/v1/admin/a2a/discovery-targets/${target.id}/credential-bindings`,
        payload: {
          submission_id: "credential-keyed-create", origin: target.canonical_origin,
          scheme_name: "bearerAuth", scope: "agent.invoke", provider: "vault", external_version: "v1",
          secret_reference: "vault://agent.example/keyed/v1",
        },
      },
      {
        method: "POST" as const,
        url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/rotate`,
        payload: {
          submission_id: "credential-no-key-rotate", expected_version: 1,
          provider: "vault", external_version: "v2", secret_reference: "vault://agent.example/keyed/v2",
        },
      },
      {
        method: "POST" as const,
        url: `/api/v1/admin/a2a/credential-bindings/${binding.id}/revoke`,
        payload: { submission_id: "credential-no-key-revoke", expected_version: 1, reason: "must fail closed" },
      },
    ];
    for (const request of requests) {
      const response = await noKeyApp.inject({ ...request, headers: setup.admin });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toMatchObject({ code: "credential-key-unavailable" });
    }
    expect(await count(setup.db, "a2a_admin_operations")).toBe(2);
    expect(await count(setup.db, "a2a_credential_revisions")).toBe(1);
    expect(asString((await setup.db.query<{ state: unknown }>(
      "SELECT state FROM a2a_credential_bindings WHERE id = $1", [binding.id],
    ))[0]!.state)).toBe("active");
  });
});
