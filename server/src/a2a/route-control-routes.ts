import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { SqlDatabase } from "../db.js";
import type { DiscoveryServiceDependencies } from "./discovery-service.js";
import {
  listCallerGenerations,
  listInterfaceHealth,
  listRoutePolicies,
  probeInterfaceHealth,
  provisionCallerGeneration,
  provisionRoutePolicy,
  resolveRouteSnapshot,
  revokeCallerGeneration,
  revokeRoutePolicy,
  RouteControlError,
  type RouteActor,
} from "./route-control-store.js";
import { EXACT_SEND_REPLAY_EXTENSION_URI } from "./agent-card-registry.js";

const BOUNDED_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const submissionId = z.string().regex(BOUNDED_ID);
const boundedId = z.string().regex(BOUNDED_ID);
const digest = z.string().regex(SHA256);
const positiveInteger = z.number().int().positive();
const coercedPositiveInteger = z.coerce.number().int().positive();
const numericIdParams = z.strictObject({ id: coercedPositiveInteger });
const stringIdParams = z.strictObject({ id: boundedId });
const pageQuery = z.strictObject({
  after_id: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
const callerPageQuery = z.strictObject({
  after_id: z.string().max(128).default(""),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
const mutationSchema = z.strictObject({
  submission_id: submissionId,
  expected_version: positiveInteger,
  reason: z.string().trim().min(1).max(1024),
});
const callerProvisionSchema = z.strictObject({
  submission_id: submissionId,
  caller_generation_id: boundedId,
  employee_id: positiveInteger,
  api_key_id: positiveInteger,
  host_id: boundedId,
});
const healthProbeSchema = z.strictObject({
  submission_id: submissionId,
  target_id: positiveInteger,
  card_registry_id: positiveInteger,
  interface_url: z.string().min(1).max(2048),
});
const operationKind = z.enum(["initial_send", "exact_initial_send_replay", "get_task", "continue_send", "cancel_task"]);
const policyProvisionSchema = z.strictObject({
  submission_id: submissionId,
  target_id: positiveInteger,
  card_registry_id: positiveInteger,
  managed_key_revision_id: positiveInteger,
  credential_binding_id: positiveInteger,
  caller_generation_id: boundedId,
  host_id: boundedId,
  operation_kind: operationKind,
  interface_url: z.string().min(1).max(2048),
  extension_spec_digest_sha256: digest,
  wire_conformance_artifact_id: boundedId,
  wire_conformance_artifact_digest_sha256: digest,
  route_policy_version: positiveInteger,
});
const resolveSchema = z.strictObject({
  operation_id: boundedId,
  attempt_id: boundedId,
  operation_kind: operationKind,
  a2a_method: z.enum(["SendMessage", "GetTask", "CancelTask"]),
  target_agent_id: positiveInteger,
  interface_url: z.string().min(1).max(2048),
  agent_card_digest_sha256: digest,
  trust_key_id: positiveInteger,
  credential_binding_id: positiveInteger,
  caller_generation_id: boundedId,
  route_policy_version: positiveInteger,
  route_policy_digest_sha256: digest,
  extension_uri: z.literal(EXACT_SEND_REPLAY_EXTENSION_URI),
  extension_spec_digest_sha256: digest,
  intended_credential_revision_id: positiveInteger,
  predecessor_credential_revision_id: positiveInteger.optional(),
});

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new RouteControlError(422, "invalid-request", "Request validation failed");
  }
  return parsed.data;
}

function sendMutation<T>(reply: FastifyReply, result: { status: number; body: T }) {
  return reply.code(result.status).send(result.body);
}

export async function registerRouteControlRoutes(
  app: FastifyInstance,
  db: SqlDatabase,
  resolveActor: (request: FastifyRequest) => Promise<RouteActor>,
  resolveAdmin: (request: FastifyRequest) => Promise<RouteActor>,
  probeDependencies: DiscoveryServiceDependencies = {},
): Promise<void> {
  const adminPrefix = "/api/v1/admin/a2a";
  const adminActors = new WeakMap<FastifyRequest, RouteActor>();
  const actors = new WeakMap<FastifyRequest, RouteActor>();
  const adminOptions = {
    onRequest: async (request: FastifyRequest) => {
      adminActors.set(request, await resolveAdmin(request));
    },
  } as const;
  const resolveOptions = {
    onRequest: async (request: FastifyRequest, reply: FastifyReply) => {
      reply.header("Cache-Control", "no-store, max-age=0");
      reply.header("Pragma", "no-cache");
      actors.set(request, await resolveActor(request));
    },
  } as const;
  const adminActor = (request: FastifyRequest) => adminActors.get(request) ?? (() => { throw new Error("Missing admin actor"); })();
  const actor = (request: FastifyRequest) => actors.get(request) ?? (() => { throw new Error("Missing route actor"); })();

  app.post(`${adminPrefix}/caller-generations`, adminOptions, async (request, reply) => {
    const input = parse(callerProvisionSchema, request.body);
    return sendMutation(reply, await provisionCallerGeneration(db, adminActor(request), {
      submissionId: input.submission_id, callerGenerationId: input.caller_generation_id,
      employeeId: input.employee_id, apiKeyId: input.api_key_id, hostId: input.host_id,
    }));
  });
  app.get(`${adminPrefix}/caller-generations`, adminOptions, async (request) => {
    const input = parse(callerPageQuery, request.query);
    return listCallerGenerations(db, input.after_id, input.limit);
  });
  app.post(`${adminPrefix}/caller-generations/:id/revoke`, adminOptions, async (request, reply) => {
    const { id } = parse(stringIdParams, request.params);
    const input = parse(mutationSchema, request.body);
    return sendMutation(reply, await revokeCallerGeneration(db, adminActor(request), id, {
      submissionId: input.submission_id, expectedVersion: input.expected_version, reason: input.reason,
    }));
  });

  app.post(`${adminPrefix}/advertised-interfaces/probe`, adminOptions, async (request, reply) => {
    const input = parse(healthProbeSchema, request.body);
    return sendMutation(reply, await probeInterfaceHealth(db, adminActor(request), {
      submissionId: input.submission_id, targetId: input.target_id,
      cardRegistryId: input.card_registry_id, interfaceUrl: input.interface_url,
    }, probeDependencies));
  });
  app.get(`${adminPrefix}/advertised-interfaces/health`, adminOptions, async (request) => {
    const input = parse(pageQuery, request.query);
    return listInterfaceHealth(db, input.after_id, input.limit);
  });

  app.post(`${adminPrefix}/route-policies`, adminOptions, async (request, reply) => {
    const input = parse(policyProvisionSchema, request.body);
    return sendMutation(reply, await provisionRoutePolicy(db, adminActor(request), {
      submissionId: input.submission_id, targetId: input.target_id, cardRegistryId: input.card_registry_id,
      managedKeyRevisionId: input.managed_key_revision_id, credentialBindingId: input.credential_binding_id,
      callerGenerationId: input.caller_generation_id, hostId: input.host_id,
      operationClass: input.operation_kind, interfaceUrl: input.interface_url,
      extensionSpecDigestSha256: input.extension_spec_digest_sha256,
      wireConformanceArtifactId: input.wire_conformance_artifact_id,
      wireConformanceDigestSha256: input.wire_conformance_artifact_digest_sha256,
      policyVersion: input.route_policy_version,
    }));
  });
  app.get(`${adminPrefix}/route-policies`, adminOptions, async (request) => {
    const input = parse(pageQuery, request.query);
    return listRoutePolicies(db, input.after_id, input.limit);
  });
  app.post(`${adminPrefix}/route-policies/:id/revoke`, adminOptions, async (request, reply) => {
    const { id } = parse(numericIdParams, request.params);
    const input = parse(mutationSchema, request.body);
    return sendMutation(reply, await revokeRoutePolicy(db, adminActor(request), id, {
      submissionId: input.submission_id, expectedVersion: input.expected_version, reason: input.reason,
    }));
  });

  app.post("/api/v1/a2a/routes/resolve", resolveOptions, async (request) => {
    const input = parse(resolveSchema, request.body);
    return resolveRouteSnapshot(db, actor(request), {
      operationId: input.operation_id, attemptId: input.attempt_id,
      operationKind: input.operation_kind, a2aMethod: input.a2a_method,
      targetAgentId: input.target_agent_id, interfaceUrl: input.interface_url,
      agentCardDigestSha256: input.agent_card_digest_sha256, trustKeyId: input.trust_key_id,
      credentialBindingId: input.credential_binding_id, callerGenerationId: input.caller_generation_id,
      routePolicyVersion: input.route_policy_version, routePolicyDigestSha256: input.route_policy_digest_sha256,
      extensionUri: input.extension_uri, extensionSpecDigestSha256: input.extension_spec_digest_sha256,
      intendedCredentialRevisionId: input.intended_credential_revision_id,
      ...(input.predecessor_credential_revision_id === undefined
        ? {}
        : { predecessorCredentialRevisionId: input.predecessor_credential_revision_id }),
    });
  });
}
