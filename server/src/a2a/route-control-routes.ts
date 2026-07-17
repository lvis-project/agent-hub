import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { SqlDatabase } from "../db.js";
import type { DiscoveryServiceDependencies } from "./discovery-service.js";
import {
  ingestWireConformanceEvidence,
  listCallerGenerations,
  listInterfaceHealth,
  listRoutePolicies,
  observeServedSpec,
  probeInterfaceHealth,
  provisionCallerGeneration,
  provisionEvidenceSigner,
  provisionRoutePolicy,
  resolveRouteSnapshot,
  revokeCallerGeneration,
  revokeEvidenceSigner,
  revokeRoutePolicy,
  revokeServedSpecObservation,
  revokeWireConformanceEvidence,
  RouteControlError,
  type RouteActor,
} from "./route-control-store.js";
import { EXACT_SEND_REPLAY_EXTENSION_URI } from "./agent-card-registry.js";
import { parseStrictJson } from "./strict-json.js";

const BOUNDED_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const WIRE_EVIDENCE_PAYLOAD_MAX_BYTES = 32 * 1024;
const WIRE_EVIDENCE_SIGNATURE_MAX_BYTES = 64;
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
  after_id: z.union([z.literal(""), boundedId]).default(""),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
const mutationSchema = z.strictObject({
  submission_id: submissionId,
  expected_version: positiveInteger,
  reason: z.string().trim().min(1).max(1024),
});
const evidenceRevokeSchema = z.strictObject({
  submission_id: submissionId,
  reason: z.string().trim().min(1).max(1024),
});
const evidenceSignerSchema = z.strictObject({
  submission_id: submissionId,
  key_id: boundedId,
  public_key_pem: z.string().min(1).max(4096),
});
const servedSpecObservationSchema = z.strictObject({
  submission_id: submissionId,
  source_url: z.string().min(1).max(2048),
});
const boundedCanonicalBase64 = (maxBytes: number) => z.string()
  .min(1)
  .max(Math.ceil(maxBytes / 3) * 4)
  .refine((value) => {
    if (!CANONICAL_BASE64.test(value)) return false;
    const decoded = Buffer.from(value, "base64");
    return decoded.length <= maxBytes && decoded.toString("base64") === value;
  });
const wireConformanceEvidenceSchema = z.strictObject({
  submission_id: submissionId,
  signer_id: positiveInteger,
  served_spec_observation_id: positiveInteger,
  signed_payload_base64: boundedCanonicalBase64(WIRE_EVIDENCE_PAYLOAD_MAX_BYTES),
  signature_base64: boundedCanonicalBase64(WIRE_EVIDENCE_SIGNATURE_MAX_BYTES),
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
  served_spec_observation_id: positiveInteger,
  extension_spec_digest_sha256: digest,
  wire_conformance_evidence_id: positiveInteger,
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
  app.removeContentTypeParser("application/json");
  app.addContentTypeParser("application/json", { parseAs: "buffer" }, (_request, rawBody, done) => {
    try {
      const text = typeof rawBody === "string"
        ? rawBody
        : new TextDecoder("utf-8", { fatal: true }).decode(rawBody);
      done(null, parseStrictJson(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text));
    } catch {
      const malformed = new Error("Malformed request") as Error & { statusCode: number };
      malformed.statusCode = 400;
      done(malformed);
    }
  });
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

  app.post(`${adminPrefix}/evidence-signers`, adminOptions, async (request, reply) => {
    const input = parse(evidenceSignerSchema, request.body);
    return sendMutation(reply, await provisionEvidenceSigner(db, adminActor(request), {
      submissionId: input.submission_id, keyId: input.key_id, publicKeyPem: input.public_key_pem,
    }));
  });
  app.post(`${adminPrefix}/evidence-signers/:id/revoke`, adminOptions, async (request, reply) => {
    const { id } = parse(numericIdParams, request.params);
    const input = parse(evidenceRevokeSchema, request.body);
    return sendMutation(reply, await revokeEvidenceSigner(db, adminActor(request), id, {
      submissionId: input.submission_id, reason: input.reason,
    }));
  });
  app.post(`${adminPrefix}/served-spec-observations`, adminOptions, async (request, reply) => {
    const input = parse(servedSpecObservationSchema, request.body);
    return sendMutation(reply, await observeServedSpec(db, adminActor(request), {
      submissionId: input.submission_id, sourceUrl: input.source_url,
    }, probeDependencies));
  });
  app.post(`${adminPrefix}/served-spec-observations/:id/revoke`, adminOptions, async (request, reply) => {
    const { id } = parse(numericIdParams, request.params);
    const input = parse(evidenceRevokeSchema, request.body);
    return sendMutation(reply, await revokeServedSpecObservation(db, adminActor(request), id, {
      submissionId: input.submission_id, reason: input.reason,
    }));
  });
  app.post(`${adminPrefix}/wire-conformance-evidence`, adminOptions, async (request, reply) => {
    const input = parse(wireConformanceEvidenceSchema, request.body);
    return sendMutation(reply, await ingestWireConformanceEvidence(db, adminActor(request), {
      submissionId: input.submission_id, signerId: input.signer_id,
      servedSpecObservationId: input.served_spec_observation_id,
      signedPayloadBase64: input.signed_payload_base64, signatureBase64: input.signature_base64,
    }));
  });
  app.post(`${adminPrefix}/wire-conformance-evidence/:id/revoke`, adminOptions, async (request, reply) => {
    const { id } = parse(numericIdParams, request.params);
    const input = parse(evidenceRevokeSchema, request.body);
    return sendMutation(reply, await revokeWireConformanceEvidence(db, adminActor(request), id, {
      submissionId: input.submission_id, reason: input.reason,
    }));
  });

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
      servedSpecObservationId: input.served_spec_observation_id,
      extensionSpecDigestSha256: input.extension_spec_digest_sha256,
      wireConformanceEvidenceId: input.wire_conformance_evidence_id,
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
