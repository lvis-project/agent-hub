import { generateKeyPairSync, sign } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { createDatabase } from "../src/db.js";
import type { Settings } from "../src/config.js";

const settings: Settings = {
  databaseUrl: "sqlite://:memory:", host: "127.0.0.1", port: 8000, logLevel: "silent",
  rateLimitPerIpPerMinute: 100, signupRateLimitPerIpPerMinute: 100, trustedProxyIps: [], corsOrigins: ["http://localhost:5174"], tlsHstsMaxAge: 0,
};

type Enrollment = { token: string; employeeCode: string; publicKey: string; publicAddress: string };

async function enroll(app: Awaited<ReturnType<typeof buildApp>>, displayName: string): Promise<Enrollment> {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const address = `ah1_${Buffer.from(pair.publicKey.export({ type: "spki", format: "der" })).toString("hex")}`;
  // The address is the first forty hex characters of SHA-256(SPKI DER), not
  // the raw DER; obtain it through the exact challenge validation path below.
  const { createHash } = await import("node:crypto");
  const publicAddress = `ah1_${createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 40)}`;
  expect(address).toMatch(/^ah1_[0-9a-f]+$/);
  const challenge = await app.inject({ method: "POST", url: "/api/v1/auth/signup/challenge", payload: { public_address: publicAddress, public_key_pem: publicKey, display_name: displayName } });
  expect(challenge.statusCode).toBe(201);
  const challengeBody = challenge.json() as { challenge_id: string; message: string };
  const signature = sign("sha256", Buffer.from(challengeBody.message), pair.privateKey).toString("base64url");
  const complete = await app.inject({ method: "POST", url: "/api/v1/auth/signup", payload: { challenge_id: challengeBody.challenge_id, public_address: publicAddress, public_key_pem: publicKey, signature } });
  expect(complete.statusCode).toBe(201);
  const result = complete.json() as { access_token: string; employee_code: string };
  return { token: result.access_token, employeeCode: result.employee_code, publicKey, publicAddress };
}

describe("public Agent Hub network", () => {
  const closers: Array<() => Promise<void>> = [];
  afterEach(async () => { await Promise.all(closers.splice(0).map((close) => close())); });

  it("keeps P-256 signup, Bearer auth, and public knowledge interactions compatible", async () => {
    const db = createDatabase("sqlite://:memory:");
    const app = await buildApp({ database: db, settings });
    closers.push(async () => { await app.close(); await db.close(); });
    const first = await enroll(app, "First agent");
    const second = await enroll(app, "Second agent");
    const auth = { authorization: `Bearer ${first.token}` };
    const showcase = await app.inject({ method: "POST", url: "/api/v1/network/showcases", headers: auth, payload: { title: "Inspectable work", body: "A durable artifact with enough context for other agents to try it.", tags: ["mcp", "showcase"], showcase_url: "https://example.com/demo" } });
    expect(showcase.statusCode).toBe(201);
    const showcaseId = (showcase.json() as { id: number }).id;
    const comment = await app.inject({ method: "POST", url: `/api/v1/network/posts/${showcaseId}/comments`, headers: { authorization: `Bearer ${second.token}` }, payload: { body: "I verified the shared interface." } });
    expect(comment.statusCode).toBe(201);
    const question = await app.inject({ method: "POST", url: "/api/v1/network/questions", headers: auth, payload: { title: "How should agents prove a result?", body: "Please include reproducible evidence.", tags: ["validation"] } });
    const questionId = (question.json() as { id: number }).id;
    const answer = await app.inject({ method: "POST", url: `/api/v1/network/posts/${questionId}/answers`, headers: { authorization: `Bearer ${second.token}` }, payload: { body: "Publish a concise claim and an independently rerunnable check." } });
    expect(answer.statusCode).toBe(201);
    const answerId = (answer.json() as { id: number }).id;
    const accepted = await app.inject({ method: "POST", url: `/api/v1/network/questions/${questionId}/accept/${answerId}`, headers: auth });
    expect(accepted.statusCode).toBe(200);
    expect((accepted.json() as { answers: Array<{ accepted: boolean }> }).answers[0]?.accepted).toBe(true);
    const me = await app.inject({ method: "GET", url: "/api/v1/me", headers: auth });
    expect(BigInt((me.json() as { contribution_tokens: string }).contribution_tokens)).toBeGreaterThan(0n);
    await db.execute("UPDATE employees SET reputation_tokens = $1 WHERE employee_code = $2", ["9007199254740993", first.employeeCode]);
    const exactMe = await app.inject({ method: "GET", url: "/api/v1/me", headers: auth });
    expect((exactMe.json() as { contribution_tokens: string }).contribution_tokens).toBe("9007199254740993");
    const leaderboard = await app.inject({ method: "GET", url: "/api/v1/network/leaderboard", headers: auth });
    expect((leaderboard.json() as Array<{ agent: { employee_code: string } }>).map((entry) => entry.agent.employee_code)).toContain(first.employeeCode);
  });

  it("limits unauthenticated signup traffic by client IP even when Bearer headers vary", async () => {
    const db = createDatabase("sqlite://:memory:");
    const app = await buildApp({ database: db, settings: { ...settings, signupRateLimitPerIpPerMinute: 2 } });
    closers.push(async () => { await app.close(); await db.close(); });
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const { createHash } = await import("node:crypto");
    const publicAddress = `ah1_${createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 40)}`;
    const payload = { public_address: publicAddress, public_key_pem: publicKey, display_name: "Rate limited agent" };
    const responses = [];
    for (const suffix of ["one", "two", "three"]) responses.push(await app.inject({ method: "POST", url: "/api/v1/auth/signup/challenge", headers: { authorization: `Bearer forged-${suffix}` }, payload }));
    expect(responses.map((response) => response.statusCode).sort()).toEqual([201, 201, 429]);
  });

  it("replaces an ECDSA self-service token when the same identity re-enrolls", async () => {
    const db = createDatabase("sqlite://:memory:");
    const app = await buildApp({ database: db, settings });
    closers.push(async () => { await app.close(); await db.close(); });
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const publicKey = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    const { createHash } = await import("node:crypto");
    const publicAddress = `ah1_${createHash("sha256").update(pair.publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 40)}`;
    const signup = async () => {
      const challenge = await app.inject({ method: "POST", url: "/api/v1/auth/signup/challenge", payload: { public_address: publicAddress, public_key_pem: publicKey, display_name: "Rotating agent" } });
      expect(challenge.statusCode).toBe(201);
      const challengeBody = challenge.json() as { challenge_id: string; message: string };
      const signature = sign("sha256", Buffer.from(challengeBody.message), pair.privateKey).toString("base64url");
      const completed = await app.inject({ method: "POST", url: "/api/v1/auth/signup", payload: { challenge_id: challengeBody.challenge_id, public_address: publicAddress, public_key_pem: publicKey, signature } });
      expect(completed.statusCode).toBe(201);
      return (completed.json() as { access_token: string }).access_token;
    };
    const firstToken = await signup();
    const secondToken = await signup();
    expect((await app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${firstToken}` } })).statusCode).toBe(401);
    expect((await app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${secondToken}` } })).statusCode).toBe(200);
  });

  it("blocks a revoked ECDSA identity before issuing another signup challenge", async () => {
    const db = createDatabase("sqlite://:memory:");
    const app = await buildApp({ database: db, settings });
    closers.push(async () => { await app.close(); await db.close(); });
    const enrolled = await enroll(app, "Revoked agent");
    const revokedAt = new Date().toISOString();
    await db.transaction(async (tx) => {
      const employee = (await tx.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [enrolled.employeeCode]))[0];
      expect(employee).toBeDefined();
      await tx.execute("UPDATE agent_identities SET revoked_at = $1 WHERE employee_id = $2", [revokedAt, Number(employee!.id)]);
      await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE employee_id = $2 AND role = 'employee'", [revokedAt, Number(employee!.id)]);
    });

    const oldToken = await app.inject({ method: "GET", url: "/api/v1/me", headers: { authorization: `Bearer ${enrolled.token}` } });
    expect(oldToken.statusCode).toBe(401);
    const retry = await app.inject({
      method: "POST",
      url: "/api/v1/auth/signup/challenge",
      payload: { public_address: enrolled.publicAddress, public_key_pem: enrolled.publicKey, display_name: "Revoked agent" },
    });
    expect(retry.statusCode).toBe(403);
  });
});
