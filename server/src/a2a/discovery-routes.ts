import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { SqlDatabase } from "../db.js";
import type { RegistryActor } from "./agent-card-store.js";
import type { DiscoveryServiceDependencies } from "./discovery-service.js";
import { revalidateDiscoveryTarget } from "./discovery-service.js";
import {
  activateManagedKeyRevision,
  createCredentialBinding,
  createDiscoveryTarget,
  disableDiscoveryTarget,
  DiscoveryStoreError,
  getDiscoveryHealth,
  listCredentialBindings,
  listDiscoveryAttempts,
  listDiscoveryTargets,
  listManagedKeyRevisions,
  revokeCredentialBinding,
  revokeManagedKeyRevision,
  rotateCredentialBinding,
} from "./discovery-store.js";

const SUBMISSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const CREDENTIAL_PROVIDER = /^[a-z][a-z0-9._-]{0,63}$/u;
const CREDENTIAL_EXTERNAL_VERSION = /^[^\s\u0000-\u001f\u007f-\u009f]{1,256}$/u;
const submissionId = z.string().regex(SUBMISSION_ID);
const positiveId = z.coerce.number().int().positive();
const idParams = z.strictObject({ id: positiveId });
const targetIdParams = z.strictObject({ targetId: positiveId });
const createTargetSchema = z.strictObject({
  submission_id: submissionId,
  origin: z.string().min(1).max(2048),
});
const mutationSchema = z.strictObject({
  submission_id: submissionId,
  expected_version: z.number().int().positive(),
});
const reasonMutationSchema = mutationSchema.extend({ reason: z.string().trim().min(1).max(1024) });
const pageFields = {
  after_id: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(200).default(50),
} as const;
const targetListQuery = z.strictObject({ ...pageFields, state: z.enum(["active", "disabled"]).optional() });
const pageQuery = z.strictObject(pageFields);
const keyListQuery = z.strictObject({ ...pageFields, state: z.enum(["observed", "active", "revoked"]).optional() });
const credentialListQuery = z.strictObject({ ...pageFields, state: z.enum(["active", "revoked"]).optional() });
const credentialCreateSchema = z.strictObject({
  submission_id: submissionId,
  origin: z.string().min(1).max(2048),
  scheme_name: z.string().min(1).max(64),
  scope: z.string().min(1).max(256),
  provider: z.string().regex(CREDENTIAL_PROVIDER),
  external_version: z.string().regex(CREDENTIAL_EXTERNAL_VERSION),
  secret_reference: z.string().min(1).max(1024),
});
const credentialRotateSchema = mutationSchema.extend({
  provider: z.string().regex(CREDENTIAL_PROVIDER),
  external_version: z.string().regex(CREDENTIAL_EXTERNAL_VERSION),
  secret_reference: z.string().min(1).max(1024),
});

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new DiscoveryStoreError(422, "invalid-request", "Request validation failed");
  return result.data;
}

async function sendMutation<T>(reply: FastifyReply, result: { status: number; body: T }) {
  return reply.code(result.status).send(result.body);
}

export async function registerDiscoveryAdminRoutes(
  app: FastifyInstance,
  db: SqlDatabase,
  resolveAdmin: (request: FastifyRequest) => Promise<RegistryActor>,
  testOnlyDependencies: DiscoveryServiceDependencies = {},
  credentialReferenceHmacKey: string | null = null,
): Promise<void> {
  const prefix = "/api/v1/admin/a2a";
  const authenticatedActors = new WeakMap<FastifyRequest, RegistryActor>();
  const authenticateBeforeBodyParsing = async (request: FastifyRequest) => {
    authenticatedActors.set(request, await resolveAdmin(request));
  };
  const actor = (request: FastifyRequest): RegistryActor => {
    const resolved = authenticatedActors.get(request);
    if (resolved === undefined) throw new Error("Authenticated administrator was not attached to request");
    return resolved;
  };
  const routeOptions = { onRequest: authenticateBeforeBodyParsing } as const;

  app.post(`${prefix}/discovery-targets`, routeOptions, async (request, reply) => {
    const input = parse(createTargetSchema, request.body);
    return sendMutation(reply, await createDiscoveryTarget(db, actor(request), {
      submissionId: input.submission_id,
      origin: input.origin,
    }));
  });

  app.get(`${prefix}/discovery-targets`, routeOptions, async (request) => {
    const input = parse(targetListQuery, request.query);
    return listDiscoveryTargets(db, { afterId: input.after_id, limit: input.limit, state: input.state });
  });

  app.post(`${prefix}/discovery-targets/:id/disable`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(reasonMutationSchema, request.body);
    return sendMutation(reply, await disableDiscoveryTarget(db, actor(request), id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
    }));
  });

  app.post(`${prefix}/discovery-targets/:id/revalidate`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(mutationSchema, request.body);
    return sendMutation(reply, await revalidateDiscoveryTarget(db, actor(request), {
      targetId: id,
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
    }, testOnlyDependencies));
  });

  app.get(`${prefix}/discovery-targets/:id/attempts`, routeOptions, async (request) => {
    const { id } = parse(idParams, request.params);
    const input = parse(pageQuery, request.query);
    return listDiscoveryAttempts(db, id, { afterId: input.after_id, limit: input.limit });
  });

  app.get(`${prefix}/discovery-targets/:id/discovery-health`, routeOptions, async (request) => {
    const { id } = parse(idParams, request.params);
    return getDiscoveryHealth(db, id, testOnlyDependencies.clock?.wallNow());
  });

  app.get(`${prefix}/discovery-targets/:id/key-revisions`, routeOptions, async (request) => {
    const { id } = parse(idParams, request.params);
    const input = parse(keyListQuery, request.query);
    return listManagedKeyRevisions(db, id, { afterId: input.after_id, limit: input.limit, state: input.state });
  });

  app.post(`${prefix}/key-revisions/:id/activate`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(reasonMutationSchema, request.body);
    return sendMutation(reply, await activateManagedKeyRevision(db, actor(request), id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
    }));
  });

  app.post(`${prefix}/key-revisions/:id/revoke`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(reasonMutationSchema, request.body);
    return sendMutation(reply, await revokeManagedKeyRevision(db, actor(request), id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
    }));
  });

  app.post(`${prefix}/discovery-targets/:targetId/credential-bindings`, routeOptions, async (request, reply) => {
    const { targetId } = parse(targetIdParams, request.params);
    const input = parse(credentialCreateSchema, request.body);
    return sendMutation(reply, await createCredentialBinding(db, actor(request), targetId, {
      submissionId: input.submission_id,
      origin: input.origin,
      schemeName: input.scheme_name,
      scope: input.scope,
      provider: input.provider,
      externalVersion: input.external_version,
      secretReference: input.secret_reference,
      credentialReferenceHmacKey,
    }));
  });

  app.get(`${prefix}/discovery-targets/:targetId/credential-bindings`, routeOptions, async (request) => {
    const { targetId } = parse(targetIdParams, request.params);
    const input = parse(credentialListQuery, request.query);
    return listCredentialBindings(db, targetId, { afterId: input.after_id, limit: input.limit, state: input.state });
  });

  app.post(`${prefix}/credential-bindings/:id/rotate`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(credentialRotateSchema, request.body);
    return sendMutation(reply, await rotateCredentialBinding(db, actor(request), id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      provider: input.provider,
      externalVersion: input.external_version,
      secretReference: input.secret_reference,
      credentialReferenceHmacKey,
    }));
  });

  app.post(`${prefix}/credential-bindings/:id/revoke`, routeOptions, async (request, reply) => {
    const { id } = parse(idParams, request.params);
    const input = parse(reasonMutationSchema, request.body);
    return sendMutation(reply, await revokeCredentialBinding(db, actor(request), id, {
      submissionId: input.submission_id,
      expectedVersion: input.expected_version,
      reason: input.reason,
      credentialReferenceHmacKey,
    }));
  });
}
