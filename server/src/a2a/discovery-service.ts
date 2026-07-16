import {
  admitPreparedAgentCardDocument,
  AgentCardAdmissionError,
  prepareAgentCardDocument,
  protectedAgentCardSignatureHints,
  type PreparedAgentCardDocument,
} from "./agent-card-registry.js";
import { AgentCardStoreError } from "./agent-card-store.js";
import {
  canonicalizeProtectedJku,
  DiscoveryBoundaryError,
  fetchBoundedJson,
  nodeDiscoveryResolver,
  nodeHttpsDiscoveryTransport,
  type BoundedJsonResult,
  type DiscoveryClock,
  type DiscoveryResolver,
  type DiscoveryTransport,
} from "./discovery-egress.js";
import {
  claimRevalidation,
  completeDiscoveryDomainFailure,
  completeDiscoveryFailure,
  completeDiscoveryPersistenceFailure,
  completeDiscoverySuccess,
  DiscoveryStoreError,
  loadDiscoveryCache,
  type CachedDiscoveryDocument,
  type DiscoveryActor,
  type SuccessfulDiscoveryDocumentInput,
} from "./discovery-store.js";
import {
  MissingObservedJwksKeyError,
  parseObservedJwks,
  requiredObservedKeys,
  type ObservedJwksKey,
} from "./jwks.js";
import { parseStrictJson, StrictJsonError } from "./strict-json.js";
import type { SqlDatabase } from "../db.js";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

/** Test-only dependency overrides. Production app construction never supplies these. */
export interface DiscoveryServiceDependencies {
  readonly resolver?: DiscoveryResolver;
  readonly transport?: DiscoveryTransport;
  readonly clock?: DiscoveryClock;
}

const systemClock: DiscoveryClock = {
  wallNow: () => Date.now(),
  monotonicNow: () => performance.now(),
};

function validationError(error: unknown): DiscoveryBoundaryError | null {
  if (error instanceof DiscoveryBoundaryError) return error;
  if (error instanceof StrictJsonError) {
    return new DiscoveryBoundaryError("json-rejected", 502);
  }
  if (error instanceof AgentCardAdmissionError) {
    return new DiscoveryBoundaryError("card-rejected", 502);
  }
  if (error instanceof AgentCardStoreError) {
    return error.code === "agent-card-invalid" || error.code.startsWith("signature-")
      ? new DiscoveryBoundaryError("card-rejected", 502)
      : null;
  }
  return null;
}

function cachedValue(cache: CachedDiscoveryDocument): unknown {
  if (createHash("sha256").update(cache.bodyBytes).digest("hex") !== cache.bodySha256) {
    throw new DiscoveryBoundaryError("cache-miss", 502);
  }
  let bodyText: string;
  try {
    bodyText = new TextDecoder("utf-8", { fatal: true }).decode(cache.bodyBytes);
  } catch {
    throw new DiscoveryBoundaryError("cache-miss", 502);
  }
  try {
    const value = parseStrictJson(bodyText.charCodeAt(0) === 0xfeff ? bodyText.slice(1) : bodyText);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new DiscoveryBoundaryError("cache-miss", 502);
    }
    return value;
  } catch (error) {
    if (error instanceof StrictJsonError) throw new DiscoveryBoundaryError("cache-miss", 502);
    throw error;
  }
}

async function fetchDocument(input: {
  readonly url: URL;
  readonly cache: CachedDiscoveryDocument | null;
  readonly dependencies: Required<DiscoveryServiceDependencies>;
  readonly forceRefresh?: boolean;
}): Promise<SuccessfulDiscoveryDocumentInput> {
  const matchingCache = input.cache?.sourceUrl === input.url.href ? input.cache : null;
  const conditional = input.forceRefresh === true ? null : matchingCache;
  const result = await fetchBoundedJson({
    url: input.url,
    resolver: input.dependencies.resolver,
    transport: input.dependencies.transport,
    clock: input.dependencies.clock,
    etag: conditional?.etag ?? null,
    lastModified: conditional?.lastModified ?? null,
    allowNotModified: conditional !== null,
  });
  if (result.status === 304) {
    if (matchingCache === null || result.noStore || result.cacheExpiresAt === null) {
      throw new DiscoveryBoundaryError("cache-miss", 502);
    }
    return {
      status: 304,
      sourceUrl: input.url.href,
      bodyBytes: Buffer.from(matchingCache.bodyBytes),
      bodyValue: cachedValue(matchingCache),
      bodySha256: matchingCache.bodySha256,
      existingDocumentId: matchingCache.documentId,
      noStore: false,
      etag: result.etag ?? matchingCache.etag,
      lastModified: result.lastModified ?? matchingCache.lastModified,
      cacheExpiresAt: result.cacheExpiresAt,
      freshnessMs: result.freshnessMs,
    };
  }
  if (result.bodyBytes === null || result.value === null || result.sha256 === null) {
    throw new DiscoveryBoundaryError("json-rejected", 502);
  }
  return {
    status: 200,
    sourceUrl: input.url.href,
    bodyBytes: Buffer.from(result.bodyBytes),
    bodyValue: result.value,
    bodySha256: result.sha256,
    existingDocumentId: null,
    noStore: result.noStore,
    etag: result.etag,
    lastModified: result.lastModified,
    cacheExpiresAt: result.cacheExpiresAt,
    freshnessMs: result.freshnessMs,
  };
}

function prepareCard(value: unknown): PreparedAgentCardDocument {
  try {
    return prepareAgentCardDocument(value);
  } catch (error) {
    const mapped = validationError(error);
    if (mapped !== null) throw mapped;
    throw error;
  }
}

function verifySelfPublishedSignatures(
  prepared: PreparedAgentCardDocument,
  observedKeys: readonly ObservedJwksKey[],
): void {
  try {
    const admitted = admitPreparedAgentCardDocument(prepared, {
      trustedKeys: observedKeys.map((key) => key.trustedDefinition),
    });
    if (admitted.admitted.trustState !== "trusted") {
      throw new DiscoveryBoundaryError("card-rejected", 502);
    }
  } catch (error) {
    const mapped = validationError(error);
    if (mapped !== null) throw mapped;
    throw error;
  }
}

function commitFreshness(document: SuccessfulDiscoveryDocumentInput, completedAtMs: number): SuccessfulDiscoveryDocumentInput {
  return {
    ...document,
    cacheExpiresAt: document.noStore ? null : new Date(completedAtMs + document.freshnessMs).toISOString(),
  };
}

function minimumEvidenceExpiry(documents: readonly SuccessfulDiscoveryDocumentInput[], completedAtMs: number): string {
  return new Date(completedAtMs + Math.min(...documents.map((document) => document.freshnessMs))).toISOString();
}

export async function revalidateDiscoveryTarget(
  db: SqlDatabase,
  actor: DiscoveryActor,
  input: { targetId: number; submissionId: string; expectedVersion: number },
  dependencies: DiscoveryServiceDependencies = {},
) {
  const resolvedDependencies: Required<DiscoveryServiceDependencies> = {
    resolver: dependencies.resolver ?? nodeDiscoveryResolver,
    transport: dependencies.transport ?? nodeHttpsDiscoveryTransport,
    clock: dependencies.clock ?? systemClock,
  };
  const claimResult = await claimRevalidation(db, actor, {
    targetId: input.targetId,
    submissionId: input.submissionId,
    expectedVersion: input.expectedVersion,
    nowMs: resolvedDependencies.clock.wallNow(),
  });
  if (claimResult.replay !== null) return claimResult.replay;
  const claim = claimResult.claim;
  if (claim === null) throw new Error("Discovery claim was not returned");

  try {
    const cache = await loadDiscoveryCache(db, claim.targetId);
    const cardUrl = new URL(claim.cardUrl);
    const card = await fetchDocument({
      url: cardUrl,
      cache: cache.get("agent-card") ?? null,
      dependencies: resolvedDependencies,
    });
    const prepared = prepareCard(card.bodyValue);
    const hints = protectedAgentCardSignatureHints(prepared);
    const jkuUrls = new Map<string, URL>();
    for (const hint of hints) {
      if (hint.jku === null) continue;
      const jku = canonicalizeProtectedJku(hint.jku, cardUrl);
      jkuUrls.set(jku.href, jku);
    }
    if (jkuUrls.size > 1) throw new DiscoveryBoundaryError("jwks-rejected", 502);

    let jwks: SuccessfulDiscoveryDocumentInput | null = null;
    let observedKeys: readonly ObservedJwksKey[] = [];
    const jku = [...jkuUrls.values()][0];
    if (jku !== undefined) {
      const cachedJwks = cache.get("jwks") ?? null;
      jwks = await fetchDocument({ url: jku, cache: cachedJwks, dependencies: resolvedDependencies });
      observedKeys = parseObservedJwks(jwks.bodyValue);
      let required: readonly ObservedJwksKey[];
      try {
        required = requiredObservedKeys(observedKeys, hints);
      } catch (error) {
        if (!(error instanceof MissingObservedJwksKeyError) || jwks.status !== 304) throw error;
        jwks = await fetchDocument({
          url: jku,
          cache: cachedJwks,
          dependencies: resolvedDependencies,
          forceRefresh: true,
        });
        observedKeys = parseObservedJwks(jwks.bodyValue);
        required = requiredObservedKeys(observedKeys, hints);
      }
      verifySelfPublishedSignatures(prepared, required);
    }

    const completedAtMs = resolvedDependencies.clock.wallNow();
    const committedCard = commitFreshness(card, completedAtMs);
    const committedJwks = jwks === null ? null : commitFreshness(jwks, completedAtMs);
    return await completeDiscoverySuccess(db, actor, {
      claim,
      card: committedCard,
      jwks: committedJwks,
      observedKeys,
      evidenceExpiresAt: minimumEvidenceExpiry(committedJwks === null ? [committedCard] : [committedCard, committedJwks], completedAtMs),
      completedAtMs,
    });
  } catch (error) {
    if (error instanceof DiscoveryStoreError) throw error;
    const mapped = validationError(error);
    if (mapped !== null && mapped.code !== "domain-invalid") {
      try {
        if (mapped.code === "cache-miss") {
          return await completeDiscoveryDomainFailure(db, {
            claim,
            errorCode: mapped.code,
            status: mapped.statusCode,
            completedAtMs: resolvedDependencies.clock.wallNow(),
          });
        }
        return await completeDiscoveryFailure(db, {
          claim,
          errorCode: mapped.code,
          completedAtMs: resolvedDependencies.clock.wallNow(),
        });
      } catch (persistenceError) {
        if (persistenceError instanceof DiscoveryStoreError) throw persistenceError;
        try {
          return await completeDiscoveryPersistenceFailure(db, {
            claim,
            completedAtMs: resolvedDependencies.clock.wallNow(),
          });
        } catch {
          throw persistenceError;
        }
      }
    }
    try {
      return await completeDiscoveryPersistenceFailure(db, {
        claim,
        completedAtMs: resolvedDependencies.clock.wallNow(),
      });
    } catch {
      throw error;
    }
  }
}
