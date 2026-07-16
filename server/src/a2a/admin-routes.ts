import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { SqlDatabase } from "../db.js";
import {
  AgentCardStoreError,
  createTrustAnchor,
  getAgentCard,
  getAgentCardHistory,
  importAgentCard,
  listAgentCards,
  listRegistryAudit,
  listTrustAnchors,
  reviewAgentCard,
  revokeAgentCard,
  revokeTrustAnchor,
  type RegistryActor,
} from "./agent-card-store.js";

const SUBMISSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const submissionIdSchema = z.string().regex(SUBMISSION_ID);
const reasonSchema = z.string().trim().min(1).max(1024);
const idParamsSchema = z.strictObject({ id: z.coerce.number().int().positive() });
const trustAnchorCreateSchema = z.strictObject({
  submission_id: submissionIdSchema,
  key_id: z.string().regex(KEY_ID),
  algorithm: z.enum(["ES256", "EdDSA"]),
  public_key_pem: z.string().min(1).max(16 * 1024),
});
const trustAnchorRevokeSchema = z.strictObject({
  submission_id: submissionIdSchema,
  expected_version: z.number().int().positive(),
  reason: reasonSchema,
});
const provenanceSchema = z.strictObject({
  kind: z.enum(["manual", "api", "migration"]),
  source: z.string().trim().min(1).max(256),
  detail: z.string().trim().min(1).max(1024).optional(),
});
const cardImportSchema = z.strictObject({
  submission_id: submissionIdSchema,
  card: z.unknown(),
  provenance: provenanceSchema,
});
const cardReviewSchema = z.strictObject({
  submission_id: submissionIdSchema,
  expected_version: z.number().int().positive(),
  decision: z.enum(["trusted", "rejected"]),
  reason: reasonSchema,
});
const cardRevokeSchema = trustAnchorRevokeSchema;
const pageSchema = {
  after_id: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(200).default(50),
} as const;
const anchorListQuerySchema = z.strictObject({
  state: z.enum(["active", "revoked"]).optional(),
  ...pageSchema,
});
const cardListQuerySchema = z.strictObject({
  state: z.enum(["discovered", "trusted", "rejected", "revoked"]).optional(),
  ...pageSchema,
});
const cardHistoryQuerySchema = z.strictObject({
  observations_after_id: z.coerce.number().int().min(0).default(0),
  verifications_after_id: z.coerce.number().int().min(0).default(0),
  audit_after_id: z.coerce.number().int().min(0).default(0),
  limit: pageSchema.limit,
});
const auditQuerySchema = z.strictObject({
  ...pageSchema,
});

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new AgentCardStoreError(422, "invalid-request", "Request validation failed");
  }
  return result.data;
}

async function sendMutation<T>(reply: FastifyReply, result: { status: number; body: T }) {
  return reply.code(result.status).send(result.body);
}

export async function registerAgentCardAdminRoutes(
  app: FastifyInstance,
  db: SqlDatabase,
  resolveAdmin: (request: FastifyRequest) => Promise<RegistryActor>,
): Promise<void> {
  const prefix = "/api/v1/admin/a2a";

  app.post(`${prefix}/trust-anchors`, async (request, reply) => {
    const actor = await resolveAdmin(request);
    const input = parse(trustAnchorCreateSchema, request.body);
    return sendMutation(reply, await createTrustAnchor(db, actor, {
      submissionId: input.submission_id,
      keyId: input.key_id,
      algorithm: input.algorithm,
      publicKeyPem: input.public_key_pem,
    }));
  });

  app.get(`${prefix}/trust-anchors`, async (request) => {
    await resolveAdmin(request);
    const input = parse(anchorListQuerySchema, request.query);
    return listTrustAnchors(db, { state: input.state, afterId: input.after_id, limit: input.limit });
  });

  app.post(`${prefix}/trust-anchors/:id/revoke`, async (request, reply) => {
    const actor = await resolveAdmin(request);
    const { id } = parse(idParamsSchema, request.params);
    const input = parse(trustAnchorRevokeSchema, request.body);
    return sendMutation(reply, await revokeTrustAnchor(db, actor, id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
    }));
  });

  app.post(`${prefix}/cards/import`, async (request, reply) => {
    const actor = await resolveAdmin(request);
    const input = parse(cardImportSchema, request.body);
    return sendMutation(reply, await importAgentCard(db, actor, {
      submissionId: input.submission_id,
      card: input.card,
      provenance: input.provenance,
    }));
  });

  app.get(`${prefix}/cards`, async (request) => {
    await resolveAdmin(request);
    const input = parse(cardListQuerySchema, request.query);
    return listAgentCards(db, { state: input.state, afterId: input.after_id, limit: input.limit });
  });

  app.get(`${prefix}/cards/:id`, async (request) => {
    await resolveAdmin(request);
    const { id } = parse(idParamsSchema, request.params);
    return getAgentCard(db, id);
  });

  app.get(`${prefix}/cards/:id/history`, async (request) => {
    await resolveAdmin(request);
    const { id } = parse(idParamsSchema, request.params);
    const input = parse(cardHistoryQuerySchema, request.query);
    return getAgentCardHistory(db, id, {
      observationsAfterId: input.observations_after_id,
      verificationsAfterId: input.verifications_after_id,
      auditAfterId: input.audit_after_id,
      limit: input.limit,
    });
  });

  app.post(`${prefix}/cards/:id/review`, async (request, reply) => {
    const actor = await resolveAdmin(request);
    const { id } = parse(idParamsSchema, request.params);
    const input = parse(cardReviewSchema, request.body);
    return sendMutation(reply, await reviewAgentCard(db, actor, id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      decision: input.decision,
      reason: input.reason,
    }));
  });

  app.post(`${prefix}/cards/:id/revoke`, async (request, reply) => {
    const actor = await resolveAdmin(request);
    const { id } = parse(idParamsSchema, request.params);
    const input = parse(cardRevokeSchema, request.body);
    return sendMutation(reply, await revokeAgentCard(db, actor, id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
    }));
  });

  app.get(`${prefix}/audit`, async (request) => {
    await resolveAdmin(request);
    const input = parse(auditQuerySchema, request.query);
    return listRegistryAudit(db, input.after_id, input.limit);
  });
}
