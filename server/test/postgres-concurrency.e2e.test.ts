import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { Settings } from "../src/config.js";
import { createDatabase, type SqlDatabase } from "../src/db.js";

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
    await primaryDb.execute("TRUNCATE TABLE network_votes, network_comments, network_posts, api_keys, agent_identities, employees, departments, signup_challenges RESTART IDENTITY CASCADE");
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
});
