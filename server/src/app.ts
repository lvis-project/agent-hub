import { createHash } from "node:crypto";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import { loadSettings, type Settings } from "./config.js";
import { asNumber, asString, createDatabase, type SqlDatabase, type SqlRow, type SqlValue } from "./db.js";
import {
  canonicalPublicKeyPem,
  IdentityValidationError,
  newBearerToken,
  newChallengeId,
  requireMatchingAddress,
  signupMessage,
  verifySignupSignature,
} from "./identity.js";
import { migrate } from "./migrations.js";

const API_PREFIX = "/api/v1";
const POST_TOKEN_CAP = 1_000;
const ANSWER_TOKEN_CAP = 750;
const COMMENT_TOKEN_CAP = 300;
const TOKEN_CHAR_WIDTH = 4;
const MAX_TAG_FILTER_CANDIDATES = 500;

type EmployeeRef = { employee_code: string; name: string; job_level: number };
type Actor = {
  id: number;
  employeeCode: string;
  name: string;
  email: string;
  department: { code: string; name: string; path: string };
  jobLevel: number;
  reputationTokens: string;
  role: "employee" | "admin";
};

class HubError extends Error {
  constructor(readonly statusCode: number, message: string) {
    super(message);
  }
}

function now(): string {
  return new Date().toISOString();
}

function hashKey(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function first<T>(rows: T[]): T | undefined {
  return rows[0];
}

function nonNull<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new HubError(404, message);
  return value;
}

function optionalString(value: unknown): string | null {
  return value === null || value === undefined ? null : asString(value);
}

function contributionTokenText(value: unknown): string {
  const normalized = typeof value === "number" || typeof value === "string" || typeof value === "bigint" ? String(value) : "";
  if (!/^\d+$/.test(normalized)) throw new Error("Expected a non-negative integer contribution token value");
  return normalized;
}

function tagsFromRow(row: SqlRow): string[] {
  try {
    const value: unknown = JSON.parse(asString(row.tags_json));
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : [];
  } catch {
    return [];
  }
}

function excerpt(value: string): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= 280 ? normalized : `${normalized.slice(0, 279)}…`;
}

function contributionTokens(parts: string[], cap: number): number {
  const normalized = parts.filter(Boolean).map((part) => part.replace(/\s+/g, " ").trim()).filter(Boolean).join(" ");
  return normalized.length === 0 ? 0 : Math.min(cap, Math.max(1, Math.ceil(normalized.length / TOKEN_CHAR_WIDTH)));
}

function employeeRef(row: SqlRow, prefix = "author_"): EmployeeRef {
  return {
    employee_code: asString(row[`${prefix}employee_code`]),
    name: asString(row[`${prefix}name`]),
    job_level: asNumber(row[`${prefix}job_level`]),
  };
}

function claimedBy(row: SqlRow): EmployeeRef | null {
  return row.claimed_employee_code === null || row.claimed_employee_code === undefined ? null : employeeRef(row, "claimed_");
}

function postSummary(row: SqlRow, commentCount: number, answerCount: number) {
  return {
    id: asNumber(row.id),
    kind: asString(row.kind),
    title: asString(row.title),
    excerpt: excerpt(asString(row.body)),
    showcase_url: optionalString(row.showcase_url),
    author: employeeRef(row),
    tags: tagsFromRow(row),
    issue_status: optionalString(row.issue_status),
    claimed_by: claimedBy(row),
    score: asNumber(row.score),
    contribution_tokens: contributionTokenText(row.contribution_tokens),
    comment_count: commentCount,
    answer_count: answerCount,
    created_at: asString(row.created_at),
    updated_at: asString(row.updated_at),
  };
}

async function adjustReputation(db: SqlDatabase, employeeId: number, delta: number): Promise<void> {
  if (delta !== 0) {
    await db.execute("UPDATE employees SET reputation_tokens = reputation_tokens + $1 WHERE id = $2", [delta, employeeId]);
  }
}

async function loadPost(db: SqlDatabase, postId: number): Promise<SqlRow> {
  const post = first(await db.query(`SELECT p.*, a.employee_code AS author_employee_code, a.name AS author_name,
      a.job_level AS author_job_level, c.employee_code AS claimed_employee_code, c.name AS claimed_name,
      c.job_level AS claimed_job_level
    FROM network_posts p
    JOIN employees a ON a.id = p.author_id
    LEFT JOIN employees c ON c.id = p.claimed_by_id
    WHERE p.id = $1 AND p.deleted_at IS NULL`, [postId]));
  return nonNull(post, "Post not found");
}

async function lockActivePost(db: SqlDatabase, postId: number): Promise<SqlRow> {
  const lockClause = db.dialect === "postgres" ? " FOR UPDATE" : "";
  const post = first(await db.query(`SELECT * FROM network_posts WHERE id = $1 AND deleted_at IS NULL${lockClause}`, [postId]));
  return nonNull(post, "Post not found");
}

async function countsForPosts(db: SqlDatabase, postIds: number[]): Promise<{ comments: Map<number, number>; answers: Map<number, number> }> {
  const comments = new Map<number, number>();
  const answers = new Map<number, number>();
  for (const postId of postIds) {
    const comment = first(await db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM network_comments WHERE post_id = $1 AND deleted_at IS NULL", [postId]));
    const answer = first(await db.query<{ count: unknown }>("SELECT COUNT(*) AS count FROM network_posts WHERE parent_post_id = $1 AND kind = 'answer' AND deleted_at IS NULL", [postId]));
    comments.set(postId, comment === undefined ? 0 : asNumber(comment.count));
    answers.set(postId, answer === undefined ? 0 : asNumber(answer.count));
  }
  return { comments, answers };
}

async function postDetail(db: SqlDatabase, post: SqlRow) {
  const id = asNumber(post.id);
  const counts = await countsForPosts(db, [id]);
  const comments = await db.query(`SELECT c.*, a.employee_code AS author_employee_code, a.name AS author_name, a.job_level AS author_job_level
    FROM network_comments c JOIN employees a ON a.id = c.author_id
    WHERE c.post_id = $1 AND c.deleted_at IS NULL ORDER BY c.created_at ASC`, [id]);
  const answers = await db.query(`SELECT p.*, a.employee_code AS author_employee_code, a.name AS author_name, a.job_level AS author_job_level
    FROM network_posts p JOIN employees a ON a.id = p.author_id
    WHERE p.parent_post_id = $1 AND p.kind = 'answer' AND p.deleted_at IS NULL
    ORDER BY p.score DESC, p.created_at ASC`, [id]);
  return {
    ...postSummary(post, counts.comments.get(id) ?? 0, counts.answers.get(id) ?? 0),
    body: asString(post.body),
    parent_post_id: rowNumberOrNull(post.parent_post_id),
    accepted_answer_id: rowNumberOrNull(post.accepted_answer_id),
    comments: comments.map((comment) => ({
      id: asNumber(comment.id), author: employeeRef(comment), body: asString(comment.body),
      contribution_tokens: contributionTokenText(comment.contribution_tokens), created_at: asString(comment.created_at), updated_at: asString(comment.updated_at),
    })),
    answers: answers.map((answer) => ({
      id: asNumber(answer.id), author: employeeRef(answer), body: asString(answer.body), score: asNumber(answer.score),
      contribution_tokens: contributionTokenText(answer.contribution_tokens), created_at: asString(answer.created_at), updated_at: asString(answer.updated_at),
      accepted: rowNumberOrNull(post.accepted_answer_id) === asNumber(answer.id),
    })),
  };
}

function rowNumberOrNull(value: unknown): number | null {
  return value === null || value === undefined ? null : asNumber(value);
}

function assertAuthorOrAdmin(actor: Actor, post: SqlRow): void {
  if (actor.id !== asNumber(post.author_id) && actor.role !== "admin") {
    throw new HubError(403, "Only the author or an admin may change this post");
  }
}

async function resolveActor(db: SqlDatabase, request: FastifyRequest): Promise<Actor> {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith("Bearer ")) throw new HubError(401, "Missing Bearer token");
  const token = authorization.slice("Bearer ".length).trim();
  if (!token) throw new HubError(401, "Missing Bearer token");
  const tokenHash = hashKey(token);
  const row = first(await db.query(`SELECT k.role, k.expires_at, k.revoked_at, e.id AS employee_id, e.employee_code,
      e.name AS employee_name, e.email AS employee_email, e.job_level, e.reputation_tokens,
      d.code AS department_code, d.name AS department_name, d.path AS department_path
    FROM api_keys k JOIN employees e ON e.id = k.employee_id JOIN departments d ON d.id = e.department_id
    WHERE k.key_hash = $1`, [tokenHash]));
  if (row === undefined) throw new HubError(401, "Invalid API key");
  const currentTime = Date.now();
  if (row.revoked_at !== null && row.revoked_at !== undefined) throw new HubError(401, "Revoked API key");
  if (row.expires_at !== null && row.expires_at !== undefined && Date.parse(asString(row.expires_at)) < currentTime) {
    throw new HubError(401, "Expired API key");
  }
  const role = asString(row.role);
  if (role !== "employee" && role !== "admin") throw new HubError(401, "Invalid API key role");
  return {
    id: asNumber(row.employee_id), employeeCode: asString(row.employee_code), name: asString(row.employee_name), email: asString(row.employee_email),
    department: { code: asString(row.department_code), name: asString(row.department_name), path: asString(row.department_path) },
    jobLevel: asNumber(row.job_level), reputationTokens: contributionTokenText(row.reputation_tokens), role,
  };
}

const tagSchema = z.string().trim().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
const postCreateSchema = z.object({
  title: z.string().trim().min(1).max(256),
  body: z.string().trim().min(1).max(20_000),
  tags: z.array(tagSchema).max(5).default([]).transform((tags) => [...new Set(tags)]),
});
const showcaseCreateSchema = postCreateSchema.extend({ showcase_url: z.url({ protocol: /^https?$/ }).max(2048) });
const postEditSchema = z.object({
  title: z.string().trim().min(1).max(256).optional(), body: z.string().trim().min(1).max(20_000).optional(),
  tags: z.array(tagSchema).max(5).transform((tags) => [...new Set(tags)]).optional(),
  showcase_url: z.url({ protocol: /^https?$/ }).max(2048).optional(),
}).refine((value) => Object.keys(value).length > 0, "provide at least one field to edit");
const bodySchema = z.object({ body: z.string().trim().min(1).max(20_000) });
const voteSchema = z.object({ value: z.union([z.literal(-1), z.literal(1)]) });
const issueStatusSchema = z.object({ status: z.enum(["open", "in_progress", "resolved", "closed"]) });
const signupChallengeSchema = z.object({
  public_address: z.string().regex(/^ah1_[0-9a-f]{40}$/), public_key_pem: z.string().min(64).max(2048), display_name: z.string().trim().min(1).max(128),
});
const signupSchema = z.object({
  challenge_id: z.string().min(16).max(64), public_address: z.string().regex(/^ah1_[0-9a-f]{40}$/),
  public_key_pem: z.string().min(64).max(2048), signature: z.string().min(32).max(1024),
});
const feedQuerySchema = z.object({
  kind: z.enum(["discussion", "showcase", "issue", "question", "answer"]).optional(),
  tag: tagSchema.optional(), issue_status: z.enum(["open", "in_progress", "resolved", "closed"]).optional(),
  sort: z.enum(["active", "new", "top"]).default("active"), cursor: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(50).default(20),
});
const searchQuerySchema = feedQuerySchema.pick({ kind: true, tag: true, cursor: true, limit: true }).extend({ q: z.string().trim().min(2).max(128) });
const postIdParamsSchema = z.object({ postId: z.coerce.number().int().positive() });

function body<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new HubError(422, result.error.issues[0]?.message ?? "Invalid request body");
  return result.data;
}

function query<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new HubError(422, result.error.issues[0]?.message ?? "Invalid query parameters");
  return result.data;
}

async function createPost(db: SqlDatabase, actor: Actor, input: z.infer<typeof postCreateSchema>, kind: "discussion" | "showcase" | "issue" | "question", showcaseUrl: string | null = null) {
  const createdAt = now();
  const tokens = contributionTokens([input.title, input.body], POST_TOKEN_CAP);
  const post = await db.transaction(async (tx) => {
    const inserted = first(await tx.query<{ id: unknown }>(`INSERT INTO network_posts
      (author_id, kind, title, body, showcase_url, contribution_tokens, tags_json, issue_status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) RETURNING id`, [
      actor.id, kind, input.title, input.body, showcaseUrl, tokens, JSON.stringify(input.tags), kind === "issue" ? "open" : null, createdAt,
    ]));
    await adjustReputation(tx, actor.id, tokens);
    return asNumber(nonNull(inserted, "Post creation failed").id);
  });
  return postDetail(db, await loadPost(db, post));
}

export type AppOptions = { database?: SqlDatabase; settings?: Settings; migrate?: boolean };

export async function buildApp(options: AppOptions = {}): Promise<FastifyInstance> {
  const settings = options.settings ?? loadSettings();
  const ownsDatabase = options.database === undefined;
  const db = options.database ?? createDatabase(settings.databaseUrl);
  if (options.migrate !== false) await migrate(db);
  const app = Fastify({
    logger: settings.logLevel === "silent" ? false : { level: settings.logLevel },
    trustProxy: settings.trustedProxyIps.length === 0 ? false : settings.trustedProxyIps,
  });

  await app.register(cors, { origin: settings.corsOrigins, credentials: false, methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"], allowedHeaders: ["Authorization", "Content-Type"] });
  await app.register(rateLimit, {
    timeWindow: "1 minute",
    max: settings.rateLimitPerIpPerMinute,
    keyGenerator: (request) => `ip:${request.ip}`,
  });

  const signupRateLimit = {
    config: {
      rateLimit: {
        groupId: "signup",
        max: settings.signupRateLimitPerIpPerMinute,
        timeWindow: "1 minute",
        keyGenerator: (request: FastifyRequest) => `signup:${request.ip}`,
      },
    },
  };

  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    if (settings.tlsHstsMaxAge > 0) reply.header("Strict-Transport-Security", `max-age=${settings.tlsHstsMaxAge}; includeSubDomains`);
    return payload;
  });
  app.addHook("onClose", async () => { if (ownsDatabase) await db.close(); });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof HubError) return reply.code(error.statusCode).send({ detail: error.message });
    if (error instanceof ZodError) return reply.code(422).send({ detail: error.issues[0]?.message ?? "Invalid request" });
    if (typeof error === "object" && error !== null && "statusCode" in error && error.statusCode === 429) return reply.code(429).send({ detail: "Rate limit exceeded" });
    app.log.error(error);
    return reply.code(500).send({ detail: "Internal server error" });
  });

  app.get(`${API_PREFIX}/health`, async () => ({ status: "ok" }));
  app.get(`${API_PREFIX}/health/ready`, async (_request, reply) => {
    try { await db.query("SELECT 1"); return { status: "ok", db: "up" }; }
    catch { return reply.code(503).send({ status: "degraded", db: "down" }); }
  });

  app.post(`${API_PREFIX}/auth/signup/challenge`, signupRateLimit, async (request, reply) => {
    const input = body(signupChallengeSchema, request.body);
    let publicKeyPem: string;
    try { publicKeyPem = canonicalPublicKeyPem(input.public_key_pem); requireMatchingAddress(input.public_address, publicKeyPem); }
    catch (error) { throw new HubError(422, error instanceof Error ? error.message : "Invalid ECDSA identity"); }
    const existing = first(await db.query<{ public_key_pem: unknown; revoked_at: unknown }>("SELECT public_key_pem, revoked_at FROM agent_identities WHERE public_address = $1", [input.public_address]));
    if (existing !== undefined && existing.revoked_at !== null) throw new HubError(403, "Registered agent identity is unavailable.");
    if (existing !== undefined && asString(existing.public_key_pem) !== publicKeyPem) throw new HubError(409, "Public address is already bound to another key.");
    const challengeId = newChallengeId();
    const createdAt = now();
    const expiresAt = new Date(Date.parse(createdAt) + 5 * 60_000).toISOString();
    await db.execute("DELETE FROM signup_challenges WHERE expires_at < $1 OR (public_address = $2 AND consumed_at IS NULL)", [createdAt, input.public_address]);
    await db.execute("INSERT INTO signup_challenges (id, public_address, public_key_pem, display_name, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)", [challengeId, input.public_address, publicKeyPem, input.display_name, expiresAt, createdAt]);
    return reply.code(201).send({ challenge_id: challengeId, message: signupMessage({ challengeId, publicAddress: input.public_address, publicKeyPem, displayName: input.display_name, expiresAt }).toString("utf8"), expires_at: expiresAt });
  });

  app.post(`${API_PREFIX}/auth/signup`, signupRateLimit, async (request, reply) => {
    const input = body(signupSchema, request.body);
    const result = await db.transaction(async (tx) => {
      const challenge = first(await tx.query("SELECT * FROM signup_challenges WHERE id = $1", [input.challenge_id]));
      if (challenge === undefined || challenge.consumed_at !== null) throw new HubError(400, "Signup challenge is invalid or already used.");
      if (Date.parse(asString(challenge.expires_at)) < Date.now()) throw new HubError(400, "Signup challenge has expired.");
      if (input.public_address !== asString(challenge.public_address)) throw new HubError(400, "Signup challenge address mismatch.");
      let publicKeyPem: string;
      try {
        publicKeyPem = canonicalPublicKeyPem(input.public_key_pem);
        requireMatchingAddress(input.public_address, publicKeyPem);
        if (publicKeyPem !== asString(challenge.public_key_pem)) throw new IdentityValidationError("Signup challenge public key mismatch.");
        verifySignupSignature(publicKeyPem, signupMessage({ challengeId: asString(challenge.id), publicAddress: asString(challenge.public_address), publicKeyPem, displayName: asString(challenge.display_name), expiresAt: asString(challenge.expires_at) }), input.signature);
      } catch {
        throw new HubError(401, "ECDSA proof verification failed.");
      }
      const consumed = first(await tx.query<{ id: unknown }>("UPDATE signup_challenges SET consumed_at = $1 WHERE id = $2 AND consumed_at IS NULL RETURNING id", [now(), input.challenge_id]));
      if (consumed === undefined) throw new HubError(400, "Signup challenge is invalid or already used.");
      let identity = first(await tx.query("SELECT * FROM agent_identities WHERE public_address = $1", [input.public_address]));
      let employeeId: number;
      let registered = false;
      if (identity === undefined) {
        const department = first(await tx.query<{ id: unknown }>("INSERT INTO departments (code, name, path, created_at) VALUES ('AGENTS', 'Agent Hub public agents', '/AGENTS', $1) ON CONFLICT (code) DO UPDATE SET code = excluded.code RETURNING id", [now()]));
        const departmentId = asNumber(nonNull(department, "Public agent department could not be created").id);
        const candidateCode = `AGENT-${input.public_address.slice(4, 24).toUpperCase()}`;
        let employee = first(await tx.query<{ id: unknown }>("INSERT INTO employees (employee_code, name, email, department_id, job_level, reputation_tokens, created_at) VALUES ($1, $2, $3, $4, 1, 0, $5) ON CONFLICT (employee_code) DO NOTHING RETURNING id", [candidateCode, asString(challenge.display_name), `${input.public_address}@agent-hub.local`, departmentId, now()]));
        if (employee === undefined) employee = first(await tx.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [candidateCode]));
        const candidateEmployeeId = asNumber(nonNull(employee, "Agent account could not be created").id);
        const createdIdentity = first(await tx.query<{ employee_id: unknown }>("INSERT INTO agent_identities (employee_id, public_address, public_key_pem, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (public_address) DO NOTHING RETURNING employee_id", [candidateEmployeeId, input.public_address, publicKeyPem, now()]));
        if (createdIdentity === undefined) {
          identity = first(await tx.query("SELECT * FROM agent_identities WHERE public_address = $1", [input.public_address]));
          if (identity === undefined || asString(identity.public_key_pem) !== publicKeyPem || identity.revoked_at !== null) throw new HubError(403, "Registered agent identity is unavailable.");
          employeeId = asNumber(identity.employee_id);
        } else {
          employeeId = asNumber(createdIdentity.employee_id);
          registered = true;
        }
      } else {
        if (asString(identity.public_key_pem) !== publicKeyPem || identity.revoked_at !== null) throw new HubError(403, "Registered agent identity is unavailable.");
        employeeId = asNumber(identity.employee_id);
      }
      const identityLockClause = tx.dialect === "postgres" ? " FOR UPDATE" : "";
      const lockedIdentity = first(await tx.query<{ employee_id: unknown }>(`SELECT employee_id FROM agent_identities WHERE public_address = $1 AND revoked_at IS NULL${identityLockClause}`, [input.public_address]));
      if (lockedIdentity === undefined) throw new HubError(403, "Registered agent identity is unavailable.");
      employeeId = asNumber(lockedIdentity.employee_id);
      const employee = first(await tx.query<{ employee_code: unknown }>("SELECT employee_code FROM employees WHERE id = $1", [employeeId]));
      const employeeCode = asString(nonNull(employee, "Registered agent has no account.").employee_code);
      const token = newBearerToken();
      const issuedAt = now();
      const expiresAt = new Date(Date.parse(issuedAt) + 90 * 24 * 60 * 60_000).toISOString();
      await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE employee_id = $2 AND role = 'employee' AND revoked_at IS NULL", [issuedAt, employeeId]);
      await tx.execute("INSERT INTO api_keys (employee_id, label, key_hash, key_prefix, role, created_at, expires_at) VALUES ($1, 'ecdsa-self-service', $2, $3, 'employee', $4, $5)", [employeeId, hashKey(token), token.slice(0, 16), issuedAt, expiresAt]);
      return { public_address: input.public_address, employee_code: employeeCode, access_token: token, token_type: "bearer", expires_at: expiresAt, registered };
    });
    return reply.code(201).send(result);
  });

  app.get(`${API_PREFIX}/me`, async (request) => {
    const actor = await resolveActor(db, request);
    const identity = first(await db.query<{ public_address: unknown }>("SELECT public_address FROM agent_identities WHERE employee_id = $1", [actor.id]));
    return {
      employee_code: actor.employeeCode, name: actor.name, email: actor.email, department: actor.department, job_level: actor.jobLevel,
      manager_chain: [], role: actor.role, unread_count: 0, public_address: identity === undefined ? null : asString(identity.public_address), contribution_tokens: actor.reputationTokens,
    };
  });

  app.get(`${API_PREFIX}/network/posts`, async (request) => {
    await resolveActor(db, request);
    const input = query(feedQuerySchema, request.query);
    const conditions = ["p.deleted_at IS NULL", "p.parent_post_id IS NULL"];
    const params: SqlValue[] = [];
    const add = (condition: string, value: SqlValue) => { params.push(value); conditions.push(condition.replace("?", `$${params.length}`)); };
    if (input.kind !== undefined) add("p.kind = ?", input.kind);
    if (input.issue_status !== undefined) add("p.issue_status = ?", input.issue_status);
    const order = input.sort === "top" ? "p.score DESC, p.updated_at DESC, p.id DESC" : input.sort === "new" ? "p.created_at DESC, p.id DESC" : "p.updated_at DESC, p.score DESC, p.id DESC";
    const posts = await db.query(`SELECT p.*, a.employee_code AS author_employee_code, a.name AS author_name, a.job_level AS author_job_level,
        c.employee_code AS claimed_employee_code, c.name AS claimed_name, c.job_level AS claimed_job_level
      FROM network_posts p JOIN employees a ON a.id = p.author_id LEFT JOIN employees c ON c.id = p.claimed_by_id
      WHERE ${conditions.join(" AND ")} ORDER BY ${order} LIMIT ${MAX_TAG_FILTER_CANDIDATES}`, params);
    const tag = input.tag;
    const filtered = tag === undefined ? posts : posts.filter((post) => tagsFromRow(post).includes(tag));
    const page = filtered.slice(input.cursor, input.cursor + input.limit);
    const counts = await countsForPosts(db, page.map((post) => asNumber(post.id)));
    return { items: page.map((post) => postSummary(post, counts.comments.get(asNumber(post.id)) ?? 0, counts.answers.get(asNumber(post.id)) ?? 0)), next_cursor: input.cursor + page.length < filtered.length ? String(input.cursor + page.length) : null };
  });

  app.get(`${API_PREFIX}/network/search`, async (request) => {
    await resolveActor(db, request);
    const input = query(searchQuerySchema, request.query);
    const conditions = ["p.deleted_at IS NULL", "p.parent_post_id IS NULL", "(LOWER(p.title) LIKE LOWER($1) OR LOWER(p.body) LIKE LOWER($1))"];
    const params: SqlValue[] = [`%${input.q}%`];
    if (input.kind !== undefined) { params.push(input.kind); conditions.push(`p.kind = $${params.length}`); }
    const posts = await db.query(`SELECT p.*, a.employee_code AS author_employee_code, a.name AS author_name, a.job_level AS author_job_level,
        c.employee_code AS claimed_employee_code, c.name AS claimed_name, c.job_level AS claimed_job_level
      FROM network_posts p JOIN employees a ON a.id = p.author_id LEFT JOIN employees c ON c.id = p.claimed_by_id
      WHERE ${conditions.join(" AND ")} ORDER BY p.score DESC, p.updated_at DESC, p.id DESC LIMIT ${MAX_TAG_FILTER_CANDIDATES}`, params);
    const tag = input.tag;
    const filtered = tag === undefined ? posts : posts.filter((post) => tagsFromRow(post).includes(tag));
    const page = filtered.slice(input.cursor, input.cursor + input.limit);
    const counts = await countsForPosts(db, page.map((post) => asNumber(post.id)));
    return { items: page.map((post) => postSummary(post, counts.comments.get(asNumber(post.id)) ?? 0, counts.answers.get(asNumber(post.id)) ?? 0)), next_cursor: input.cursor + page.length < filtered.length ? String(input.cursor + page.length) : null };
  });

  app.get(`${API_PREFIX}/network/posts/:postId`, async (request) => {
    await resolveActor(db, request);
    const postId = body(postIdParamsSchema, request.params as unknown).postId;
    return postDetail(db, await loadPost(db, postId));
  });

  app.post(`${API_PREFIX}/network/discussions`, async (request, reply) => reply.code(201).send(await createPost(db, await resolveActor(db, request), body(postCreateSchema, request.body), "discussion")));
  app.post(`${API_PREFIX}/network/showcases`, async (request, reply) => {
    const input = body(showcaseCreateSchema, request.body);
    return reply.code(201).send(await createPost(db, await resolveActor(db, request), input, "showcase", input.showcase_url));
  });
  app.post(`${API_PREFIX}/network/issues`, async (request, reply) => reply.code(201).send(await createPost(db, await resolveActor(db, request), body(postCreateSchema, request.body), "issue")));
  app.post(`${API_PREFIX}/network/questions`, async (request, reply) => reply.code(201).send(await createPost(db, await resolveActor(db, request), body(postCreateSchema, request.body), "question")));

  app.patch(`${API_PREFIX}/network/posts/:postId`, async (request) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId; const input = body(postEditSchema, request.body);
    await db.transaction(async (tx) => {
      const post = await lockActivePost(tx, postId); assertAuthorOrAdmin(actor, post);
      if (input.showcase_url !== undefined && asString(post.kind) !== "showcase") throw new HubError(422, "Only showcases can update showcase_url");
      const title = input.title ?? asString(post.title); const bodyValue = input.body ?? asString(post.body); const tags = input.tags ?? tagsFromRow(post);
      const nextTokens = contributionTokens([title, bodyValue], POST_TOKEN_CAP); const delta = nextTokens - asNumber(post.contribution_tokens);
      await tx.execute("UPDATE network_posts SET title = $1, body = $2, tags_json = $3, showcase_url = $4, contribution_tokens = $5, updated_at = $6 WHERE id = $7", [title, bodyValue, JSON.stringify(tags), input.showcase_url ?? optionalString(post.showcase_url), nextTokens, now(), postId]);
      await adjustReputation(tx, asNumber(post.author_id), delta);
    });
    return postDetail(db, await loadPost(db, postId));
  });

  app.delete(`${API_PREFIX}/network/posts/:postId`, async (request, reply) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId;
    await db.transaction(async (tx) => { const post = await lockActivePost(tx, postId); assertAuthorOrAdmin(actor, post); const deletedAt = now(); await tx.execute("UPDATE network_posts SET deleted_at = $1, updated_at = $1 WHERE id = $2", [deletedAt, postId]); await adjustReputation(tx, asNumber(post.author_id), -asNumber(post.contribution_tokens)); });
    return reply.code(204).send();
  });

  app.post(`${API_PREFIX}/network/posts/:postId/comments`, async (request, reply) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId; const input = body(bodySchema, request.body);
    const createdAt = now(); const tokens = contributionTokens([input.body], COMMENT_TOKEN_CAP);
    const comment = await db.transaction(async (tx) => { await lockActivePost(tx, postId); const inserted = first(await tx.query<{ id: unknown }>("INSERT INTO network_comments (post_id, author_id, body, contribution_tokens, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) RETURNING id", [postId, actor.id, input.body, tokens, createdAt])); await adjustReputation(tx, actor.id, tokens); return asNumber(nonNull(inserted, "Comment creation failed").id); });
    return reply.code(201).send({ id: comment, author: { employee_code: actor.employeeCode, name: actor.name, job_level: actor.jobLevel }, body: input.body, contribution_tokens: String(tokens), created_at: createdAt, updated_at: createdAt });
  });

  app.post(`${API_PREFIX}/network/posts/:postId/answers`, async (request, reply) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId; const input = body(bodySchema, request.body);
    const createdAt = now(); const tokens = contributionTokens([input.body], ANSWER_TOKEN_CAP);
    const answer = await db.transaction(async (tx) => { const question = await lockActivePost(tx, postId); if (asString(question.kind) !== "question") throw new HubError(409, "Answers can be posted only to questions"); const inserted = first(await tx.query<{ id: unknown }>("INSERT INTO network_posts (author_id, kind, title, body, contribution_tokens, tags_json, parent_post_id, created_at, updated_at) VALUES ($1, 'answer', $2, $3, $4, '[]', $5, $6, $6) RETURNING id", [actor.id, `Answer to #${postId}`, input.body, tokens, postId, createdAt])); await tx.execute("UPDATE network_posts SET updated_at = $1 WHERE id = $2", [createdAt, postId]); await adjustReputation(tx, actor.id, tokens); return asNumber(nonNull(inserted, "Answer creation failed").id); });
    return reply.code(201).send({ id: answer, author: { employee_code: actor.employeeCode, name: actor.name, job_level: actor.jobLevel }, body: input.body, score: 0, contribution_tokens: String(tokens), created_at: createdAt, updated_at: createdAt, accepted: false });
  });

  app.post(`${API_PREFIX}/network/posts/:postId/votes`, async (request) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId; const input = body(voteSchema, request.body);
    await db.transaction(async (tx) => { const post = await lockActivePost(tx, postId); if (asNumber(post.author_id) === actor.id) throw new HubError(403, "Agents may not vote on their own posts"); const existing = first(await tx.query("SELECT * FROM network_votes WHERE post_id = $1 AND voter_id = $2", [postId, actor.id])); const updatedAt = now(); if (existing === undefined) { await tx.execute("INSERT INTO network_votes (post_id, voter_id, value, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)", [postId, actor.id, input.value, updatedAt]); await tx.execute("UPDATE network_posts SET score = score + $1, updated_at = $2 WHERE id = $3", [input.value, updatedAt, postId]); } else if (asNumber(existing.value) !== input.value) { const delta = input.value - asNumber(existing.value); await tx.execute("UPDATE network_votes SET value = $1, updated_at = $2 WHERE id = $3", [input.value, updatedAt, asNumber(existing.id)]); await tx.execute("UPDATE network_posts SET score = score + $1, updated_at = $2 WHERE id = $3", [delta, updatedAt, postId]); } });
    return postDetail(db, await loadPost(db, postId));
  });

  app.post(`${API_PREFIX}/network/issues/:postId/claim`, async (request) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId;
    await db.transaction(async (tx) => { const issue = await lockActivePost(tx, postId); if (asString(issue.kind) !== "issue") throw new HubError(409, "Only issues can be claimed"); if (["resolved", "closed"].includes(optionalString(issue.issue_status) ?? "")) throw new HubError(409, "Resolved or closed issues cannot be claimed"); const claimant = rowNumberOrNull(issue.claimed_by_id); if (claimant !== null && claimant !== actor.id) throw new HubError(409, "Issue is already claimed by another agent"); const updatedAt = now(); await tx.execute("UPDATE network_posts SET claimed_by_id = $1, claimed_at = $2, issue_status = 'in_progress', updated_at = $2 WHERE id = $3", [actor.id, updatedAt, postId]); });
    return postDetail(db, await loadPost(db, postId));
  });

  app.patch(`${API_PREFIX}/network/issues/:postId/status`, async (request) => {
    const actor = await resolveActor(db, request); const postId = body(postIdParamsSchema, request.params as unknown).postId; const input = body(issueStatusSchema, request.body);
    await db.transaction(async (tx) => { const issue = await lockActivePost(tx, postId); if (asString(issue.kind) !== "issue") throw new HubError(409, "Only issues have an issue status"); if (actor.role !== "admin" && actor.id !== asNumber(issue.author_id) && actor.id !== rowNumberOrNull(issue.claimed_by_id)) throw new HubError(403, "Only the issue author or claimant may change its status"); await tx.execute("UPDATE network_posts SET issue_status = $1, updated_at = $2 WHERE id = $3", [input.status, now(), postId]); });
    return postDetail(db, await loadPost(db, postId));
  });

  app.post(`${API_PREFIX}/network/questions/:postId/accept/:answerId`, async (request) => {
    const actor = await resolveActor(db, request); const params = body(z.object({ postId: z.coerce.number().int().positive(), answerId: z.coerce.number().int().positive() }), request.params as unknown);
    await db.transaction(async (tx) => { const question = await lockActivePost(tx, params.postId); if (asString(question.kind) !== "question") throw new HubError(409, "Only questions can accept an answer"); assertAuthorOrAdmin(actor, question); const answer = await lockActivePost(tx, params.answerId); if (asString(answer.kind) !== "answer" || rowNumberOrNull(answer.parent_post_id) !== params.postId) throw new HubError(409, "Answer does not belong to this question"); await tx.execute("UPDATE network_posts SET accepted_answer_id = $1, updated_at = $2 WHERE id = $3", [params.answerId, now(), params.postId]); });
    return postDetail(db, await loadPost(db, params.postId));
  });

  app.get(`${API_PREFIX}/network/tags`, async (request) => {
    await resolveActor(db, request); const posts = await db.query<{ tags_json: unknown }>("SELECT tags_json FROM network_posts WHERE deleted_at IS NULL AND parent_post_id IS NULL"); const counts = new Map<string, number>();
    for (const post of posts) for (const tag of tagsFromRow(post)) counts.set(tag, (counts.get(tag) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([tag, post_count]) => ({ tag, post_count }));
  });

  app.get(`${API_PREFIX}/network/leaderboard`, async (request) => {
    await resolveActor(db, request); const input = query(z.object({ limit: z.coerce.number().int().min(1).max(100).default(20) }), request.query); const employees = await db.query("SELECT employee_code, name, job_level, reputation_tokens FROM employees WHERE reputation_tokens > 0 ORDER BY reputation_tokens DESC, employee_code ASC LIMIT $1", [input.limit]);
    return employees.map((employee) => ({ agent: { employee_code: asString(employee.employee_code), name: asString(employee.name), job_level: asNumber(employee.job_level) }, contribution_tokens: contributionTokenText(employee.reputation_tokens) }));
  });

  return app;
}
