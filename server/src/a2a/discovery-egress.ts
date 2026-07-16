import { createHash } from "node:crypto";
import { promises as dns, type LookupAddress } from "node:dns";
import { Agent, request as httpsRequest, type RequestOptions } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { performance } from "node:perf_hooks";
import { domainToASCII } from "node:url";
import { parseStrictJson, StrictJsonError } from "./strict-json.js";

export const DISCOVERY_DEADLINE_MS = 5_000;
export const DISCOVERY_MAX_HEADERS_BYTES = 16 * 1024;
export const DISCOVERY_MAX_BODY_BYTES = 64 * 1024;
export const DISCOVERY_DEFAULT_CACHE_MS = 5 * 60_000;
export const DISCOVERY_MAX_CACHE_MS = 15 * 60_000;

export type DiscoveryFailureCode =
  | "dns-rejected"
  | "connect-rejected"
  | "tls-rejected"
  | "redirect-rejected"
  | "http-rejected"
  | "timeout"
  | "headers-too-large"
  | "body-too-large"
  | "content-rejected"
  | "json-rejected"
  | "card-rejected"
  | "jwks-rejected";

export type DiscoveryErrorCode = DiscoveryFailureCode | "cache-miss" | "domain-invalid";

export class DiscoveryBoundaryError extends Error {
  constructor(readonly code: DiscoveryErrorCode, readonly statusCode = 422) {
    super("Discovery request failed");
    this.name = "DiscoveryBoundaryError";
  }
}

export type ResolvedAddress = { readonly address: string; readonly family: 4 | 6 };

export interface DiscoveryResolver {
  resolve(domain: string): Promise<readonly ResolvedAddress[]>;
}

export interface DiscoveryTransportRequest {
  readonly url: URL;
  readonly pinnedAddress: ResolvedAddress;
  readonly headers: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
}

export interface DiscoveryTransportResponse {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: Buffer;
}

export interface DiscoveryTransport {
  request(input: DiscoveryTransportRequest): Promise<DiscoveryTransportResponse>;
}

export interface DiscoveryClock {
  wallNow(): number;
  monotonicNow(): number;
}

export interface BoundedJsonResult {
  readonly status: 200 | 304;
  readonly bodyText: string | null;
  readonly bodyBytes: Buffer | null;
  readonly value: unknown | null;
  readonly sha256: string | null;
  readonly resolvedAddresses: readonly ResolvedAddress[];
  readonly etag: string | null;
  readonly lastModified: string | null;
  readonly cacheExpiresAt: string | null;
  readonly freshnessMs: number;
  readonly noStore: boolean;
}

export interface BoundedReachabilityResult {
  readonly resolvedAddresses: readonly ResolvedAddress[];
  readonly evidenceSha256: string;
}

export interface BoundedBytesResult {
  readonly bodyBytes: Buffer;
  readonly sha256: string;
  readonly resolvedAddresses: readonly ResolvedAddress[];
}

export interface NodeHttpsTransportOptions {
  readonly createConnection?: Agent["createConnection"];
}

const defaultClock: DiscoveryClock = {
  wallNow: () => Date.now(),
  monotonicNow: () => performance.now(),
};

function trimTrailingDot(value: string): string {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}

export function canonicalizeDiscoveryDomain(input: string): string {
  if (
    input !== input.trim() || input.length === 0 || input.length > 254 ||
    /[\s\u0000-\u001f\u007f-\u009f/@?#:\[\]\\]/u.test(input)
  ) {
    throw new DiscoveryBoundaryError("domain-invalid");
  }
  const ascii = trimTrailingDot(domainToASCII(input).toLowerCase());
  if (ascii.length === 0 || ascii.length > 253 || isIP(ascii) !== 0) {
    throw new DiscoveryBoundaryError("domain-invalid");
  }
  const labels = ascii.split(".");
  if (
    labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  ) {
    throw new DiscoveryBoundaryError("domain-invalid");
  }
  return ascii;
}

export function exactAgentCardUrl(domain: string): URL {
  return new URL(`https://${canonicalizeDiscoveryDomain(domain)}/.well-known/agent-card.json`);
}

export function canonicalizeProtectedJku(value: string, cardUrl: URL): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new DiscoveryBoundaryError("jwks-rejected");
  }
  let domain: string;
  try {
    domain = canonicalizeDiscoveryDomain(parsed.hostname);
  } catch {
    throw new DiscoveryBoundaryError("jwks-rejected");
  }
  if (
    parsed.protocol !== "https:" || parsed.port !== "" || parsed.username !== "" || parsed.password !== "" ||
    parsed.hash !== "" || isIP(parsed.hostname) !== 0 ||
    domain !== cardUrl.hostname || parsed.origin !== cardUrl.origin
  ) {
    throw new DiscoveryBoundaryError("jwks-rejected");
  }
  return parsed;
}

function ipv4Number(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    result = (result * 256) + value;
  }
  return result >>> 0;
}

function inV4Cidr(value: number, base: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function isPublicIpv4(address: string): boolean {
  const value = ipv4Number(address);
  if (value === null) return false;
  const globallyReachableExceptions: ReadonlyArray<readonly [string, number]> = [
    ["192.0.0.9", 32], ["192.0.0.10", 32], ["192.31.196.0", 24],
    ["192.52.193.0", 24], ["192.175.48.0", 24],
  ];
  if (globallyReachableExceptions.some(([base, prefix]) => inV4Cidr(value, ipv4Number(base)!, prefix))) {
    return true;
  }
  const specialPurpose: ReadonlyArray<readonly [string, number]> = [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
    ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
    ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
    ["198.51.100.0", 24], ["203.0.113.0", 24],
    ["224.0.0.0", 4], ["240.0.0.0", 4],
  ];
  return specialPurpose.every(([base, prefix]) => !inV4Cidr(value, ipv4Number(base)!, prefix));
}

function expandIpv6(address: string): bigint | null {
  const zone = address.indexOf("%");
  if (zone !== -1) return null;
  const lower = address.toLowerCase();
  const embeddedV4Index = lower.lastIndexOf(":");
  let normalized = lower;
  if (lower.includes(".")) {
    const embedded = lower.slice(embeddedV4Index + 1);
    const value = ipv4Number(embedded);
    if (value === null) return null;
    normalized = `${lower.slice(0, embeddedV4Index)}:${((value >>> 16) & 0xffff).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":");
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/u.test(part))) return null;
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const parts = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (parts.length !== 8) return null;
  return parts.reduce((result, part) => (result << 16n) | BigInt(`0x${part}`), 0n);
}

function inV6Cidr(value: bigint, base: bigint, prefix: number): boolean {
  const shift = BigInt(128 - prefix);
  return (value >> shift) === (base >> shift);
}

function isPublicIpv6(address: string): boolean {
  const value = expandIpv6(address);
  if (value === null) return false;
  const globallyReachableExceptions: ReadonlyArray<readonly [string, number]> = [
    ["64:ff9b::", 96],
    ["2001:1::1", 128], ["2001:1::2", 128], ["2001:1::3", 128],
    ["2001:3::", 32], ["2001:4:112::", 48], ["2001:20::", 28], ["2001:30::", 28],
    ["2620:4f:8000::", 48],
  ];
  if (globallyReachableExceptions.some(([base, prefix]) => inV6Cidr(value, expandIpv6(base)!, prefix))) {
    return true;
  }
  if (!inV6Cidr(value, expandIpv6("2000::")!, 3)) return false;
  const specialPurpose: ReadonlyArray<readonly [string, number]> = [
    ["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
    ["3fff::", 20], ["5f00::", 16],
  ];
  return specialPurpose.every(([base, prefix]) => !inV6Cidr(value, expandIpv6(base)!, prefix));
}

export function isGlobalDiscoveryAddress(address: ResolvedAddress): boolean {
  return address.family === 4 ? isPublicIpv4(address.address) : isPublicIpv6(address.address);
}

export const nodeDiscoveryResolver: DiscoveryResolver = {
  async resolve(domain) {
    let answers: LookupAddress[];
    try {
      answers = await dns.lookup(domain, { all: true, verbatim: true });
    } catch {
      throw new DiscoveryBoundaryError("dns-rejected", 502);
    }
    const values: ResolvedAddress[] = answers.map(({ address, family }) => ({
      address,
      family: family === 6 ? 6 : 4,
    }));
    if (values.length === 0) throw new DiscoveryBoundaryError("dns-rejected", 502);
    if (values.length > 8) throw new DiscoveryBoundaryError("dns-rejected", 502);
    return values;
  },
};

function singleHeader(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  name: string,
  duplicateCode: DiscoveryFailureCode = "headers-too-large",
): string | null {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
  const value = entry?.[1];
  if (Array.isArray(value)) {
    if (value.length > 1) throw new DiscoveryBoundaryError(duplicateCode, 502);
    return value[0] ?? null;
  }
  return typeof value === "string" ? value : null;
}

function boundedValidator(
  headers: DiscoveryTransportResponse["headers"],
  name: "etag" | "last-modified",
  maxLength: number,
): string | null {
  const value = singleHeader(headers, name, "http-rejected");
  if (value === null) return null;
  if (value.length > maxLength) {
    throw new DiscoveryBoundaryError("headers-too-large", 502);
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new DiscoveryBoundaryError("http-rejected", 502);
  }
  if (name === "last-modified" && !Number.isFinite(Date.parse(value))) {
    throw new DiscoveryBoundaryError("http-rejected", 502);
  }
  return value;
}

function rejectDuplicateHeaders(rawHeaders: readonly string[]): void {
  const boundedSingleHeaders = new Set([
    "content-type", "content-encoding", "content-length", "etag", "last-modified",
  ]);
  const counts = new Map<string, number>();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]!.toLowerCase();
    if (!boundedSingleHeaders.has(name)) continue;
    const count = (counts.get(name) ?? 0) + 1;
    counts.set(name, count);
    if (count > 1) {
      throw new DiscoveryBoundaryError(name === "etag" || name === "last-modified" ? "http-rejected" : "headers-too-large", 502);
    }
  }
}

function transportErrorCode(error: unknown): DiscoveryErrorCode {
  if (error instanceof DiscoveryBoundaryError) return error.code;
  const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
  if (code === "HPE_HEADER_OVERFLOW" || code === "UND_ERR_HEADERS_OVERFLOW") return "headers-too-large";
  if (
    code.startsWith("ERR_TLS") || code.startsWith("CERT_") || code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || code === "UNABLE_TO_GET_ISSUER_CERT"
  ) {
    return "tls-rejected";
  }
  return "connect-rejected";
}

export function createNodeHttpsDiscoveryTransport(options: NodeHttpsTransportOptions = {}): DiscoveryTransport {
  return {
    request(input) {
      return new Promise((resolve, reject) => {
        let settled = false;
        let lookupCalls = 0;
        const agent = new Agent({ keepAlive: false, maxSockets: 1 });
        if (options.createConnection !== undefined) agent.createConnection = options.createConnection;
        const finish = (result: DiscoveryTransportResponse | Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          agent.destroy();
          if (result instanceof Error) reject(result);
          else resolve(result);
        };
        const lookup: LookupFunction = (_hostname, lookupOptions, callback) => {
          lookupCalls += 1;
          if (lookupCalls !== 1) {
            callback(new Error("Pinned lookup was requested more than once"), "", 4);
            return;
          }
          if (lookupOptions.all === true) {
            callback(null, [{ address: input.pinnedAddress.address, family: input.pinnedAddress.family }]);
            return;
          }
          callback(null, input.pinnedAddress.address, input.pinnedAddress.family);
        };
        const request = httpsRequest({
          protocol: "https:", hostname: input.url.hostname, port: 443,
          path: `${input.url.pathname}${input.url.search}`, method: "GET", headers: input.headers,
          agent, lookup, servername: input.url.hostname, rejectUnauthorized: true,
          minVersion: "TLSv1.2", maxHeaderSize: DISCOVERY_MAX_HEADERS_BYTES,
        }, (response) => {
          const headers = response.headers as Record<string, string | readonly string[] | undefined>;
          try {
            rejectDuplicateHeaders(response.rawHeaders);
          } catch (error) {
            response.destroy(error instanceof Error ? error : new DiscoveryBoundaryError("headers-too-large", 502));
            return;
          }
          const encoding = singleHeader(headers, "content-encoding");
          if (encoding !== null && encoding.toLowerCase() !== "identity") {
            response.destroy(new DiscoveryBoundaryError("content-rejected", 502));
            return;
          }
          const contentLength = singleHeader(headers, "content-length");
          if (contentLength !== null && (!/^\d+$/u.test(contentLength) || Number(contentLength) > DISCOVERY_MAX_BODY_BYTES)) {
            response.destroy(new DiscoveryBoundaryError("body-too-large", 502));
            return;
          }
          const chunks: Buffer[] = [];
          let length = 0;
          response.on("data", (chunk: Buffer) => {
            length += chunk.length;
            if (length > DISCOVERY_MAX_BODY_BYTES) response.destroy(new DiscoveryBoundaryError("body-too-large", 502));
            else chunks.push(chunk);
          });
          response.on("error", (error) => finish(new DiscoveryBoundaryError(transportErrorCode(error), 502)));
          response.on("end", () => {
            if (lookupCalls !== 1) {
              finish(new DiscoveryBoundaryError("connect-rejected", 502));
              return;
            }
            finish({ statusCode: response.statusCode ?? 0, headers, body: Buffer.concat(chunks) });
          });
        });
        const timer = setTimeout(
          () => request.destroy(new DiscoveryBoundaryError("timeout", 504)),
          input.timeoutMs,
        );
        request.on("error", (error) => finish(new DiscoveryBoundaryError(transportErrorCode(error), error instanceof DiscoveryBoundaryError ? error.statusCode : 502)));
        request.end();
      });
    },
  };
}

export const nodeHttpsDiscoveryTransport = createNodeHttpsDiscoveryTransport();

async function deadline<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new DiscoveryBoundaryError("timeout", 504)), timeoutMs);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}

function cacheControlValues(headers: DiscoveryTransportResponse["headers"]): readonly string[] {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === "cache-control");
  const value = entry?.[1];
  if (value === undefined) return [];
  return typeof value === "string" ? [value] : value;
}

function cachePolicy(headers: DiscoveryTransportResponse["headers"], now: number) {
  const validators = {
    etag: boundedValidator(headers, "etag", 1024),
    lastModified: boundedValidator(headers, "last-modified", 256),
  };
  const values = cacheControlValues(headers);
  const directives = values.flatMap((value) => value.split(",")).map((part) => part.trim().toLowerCase());
  const noStore = directives.includes("no-store");
  const noCacheCount = values.reduce((count, value) => count + [
    ...value.matchAll(/(?:^|,)\s*no-cache(?=\s*(?:=|,|$))/giu),
  ].length, 0);
  const noStoreCount = directives.filter((part) => part === "no-store").length;
  const maxAgeDirectives = directives.filter((part) => part.startsWith("max-age"));
  const parsedMaxAges = maxAgeDirectives.map((part) => /^max-age=(?:"(\d+)"|(\d+))$/u.exec(part));
  const invalidFreshness = directives.some((part) => part === "")
    || noCacheCount > 1
    || noStoreCount > 1
    || maxAgeDirectives.length > 1
    || parsedMaxAges.some((match) => match === null)
    || (maxAgeDirectives.length > 0 && (noCacheCount > 0 || noStoreCount > 0));
  const parsedMaxAge = parsedMaxAges[0];
  const seconds = parsedMaxAge === undefined || parsedMaxAge === null
    ? null
    : Number(parsedMaxAge[1] ?? parsedMaxAge[2]);
  const requested = invalidFreshness || noCacheCount > 0 || noStore
    ? 0
    : seconds === null
      ? DISCOVERY_DEFAULT_CACHE_MS
      : seconds * 1_000;
  const duration = Math.min(Number.isSafeInteger(requested) ? requested : 0, DISCOVERY_MAX_CACHE_MS);
  return {
    noStore,
    etag: noStore ? null : validators.etag,
    lastModified: noStore ? null : validators.lastModified,
    cacheExpiresAt: noStore ? null : new Date(now + duration).toISOString(),
    freshnessMs: noStore ? 0 : duration,
  };
}

function sanitizedResolverFailure(error: unknown): never {
  if (error instanceof DiscoveryBoundaryError) throw error;
  throw new DiscoveryBoundaryError("dns-rejected", 502);
}

export async function fetchBoundedJson(input: {
  readonly url: URL;
  readonly resolver?: DiscoveryResolver;
  readonly transport?: DiscoveryTransport;
  readonly clock?: DiscoveryClock;
  readonly etag?: string | null;
  readonly lastModified?: string | null;
  readonly allowNotModified?: boolean;
}): Promise<BoundedJsonResult> {
  if (
    input.url.protocol !== "https:" || input.url.port !== "" || input.url.username !== "" || input.url.password !== "" ||
    input.url.hash !== ""
  ) {
    throw new DiscoveryBoundaryError("jwks-rejected");
  }
  const domain = canonicalizeDiscoveryDomain(input.url.hostname);
  const clock = input.clock ?? defaultClock;
  const deadlineAt = clock.monotonicNow() + DISCOVERY_DEADLINE_MS;
  const remainingDeadline = () => deadlineAt - clock.monotonicNow();
  let addresses: readonly ResolvedAddress[];
  try {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    addresses = await deadline((input.resolver ?? nodeDiscoveryResolver).resolve(domain), remaining);
  } catch (error) {
    sanitizedResolverFailure(error);
  }
  if (addresses.length === 0) throw new DiscoveryBoundaryError("dns-rejected", 502);
  if (addresses.length > 8) throw new DiscoveryBoundaryError("dns-rejected", 502);
  if (addresses.some((address) => !isGlobalDiscoveryAddress(address))) {
    throw new DiscoveryBoundaryError("dns-rejected");
  }
  const uniqueByAddress = new Map(addresses.map((address) => {
    const canonical = address.family === 4
      ? ipv4Number(address.address)?.toString(16)
      : expandIpv6(address.address)?.toString(16);
    return [`${address.family}:${canonical ?? address.address.toLowerCase()}`, address] as const;
  }));
  if (uniqueByAddress.size !== addresses.length) throw new DiscoveryBoundaryError("dns-rejected", 502);
  const unique = [...uniqueByAddress.values()];
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Accept-Encoding": "identity",
    Connection: "close",
  };
  if (input.etag) headers["If-None-Match"] = input.etag;
  else if (input.lastModified) headers["If-Modified-Since"] = input.lastModified;
  let response: DiscoveryTransportResponse | undefined;
  let finalConnectionError: DiscoveryBoundaryError | undefined;
  for (const pinnedAddress of unique) {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    try {
      response = await (input.transport ?? nodeHttpsDiscoveryTransport).request({
        url: input.url,
        pinnedAddress,
        headers,
        timeoutMs: remaining,
      });
      if (remainingDeadline() <= 0) throw new DiscoveryBoundaryError("timeout", 504);
      break;
    } catch (error) {
      const sanitized = error instanceof DiscoveryBoundaryError
        ? error
        : new DiscoveryBoundaryError("connect-rejected", 502);
      if (sanitized.code !== "connect-rejected" && sanitized.code !== "tls-rejected") throw sanitized;
      finalConnectionError = sanitized;
    }
  }
  if (response === undefined) throw finalConnectionError ?? new DiscoveryBoundaryError("connect-rejected", 502);
  if (response.statusCode >= 300 && response.statusCode < 400 && response.statusCode !== 304) {
    throw new DiscoveryBoundaryError("redirect-rejected", 502);
  }
  const policy = cachePolicy(response.headers, clock.wallNow());
  if (response.statusCode === 304) {
    if (
      input.allowNotModified !== true || (!input.etag && !input.lastModified) ||
      response.body.length !== 0
    ) {
      throw new DiscoveryBoundaryError("cache-miss", 502);
    }
    return {
      status: 304,
      bodyText: null,
      bodyBytes: null,
      value: null,
      sha256: null,
      resolvedAddresses: Object.freeze(unique),
      ...policy,
    };
  }
  if (response.statusCode !== 200) throw new DiscoveryBoundaryError("http-rejected", 502);
  const contentType = (singleHeader(response.headers, "content-type") ?? "").toLowerCase();
  if (!/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)(?:\s*;\s*charset\s*=\s*utf-8)?$/u.test(contentType)) {
    throw new DiscoveryBoundaryError("content-rejected", 502);
  }
  if (response.body.length > DISCOVERY_MAX_BODY_BYTES) throw new DiscoveryBoundaryError("body-too-large", 502);
  let bodyText: string;
  try {
    bodyText = new TextDecoder("utf-8", { fatal: true }).decode(response.body);
  } catch {
    throw new DiscoveryBoundaryError("content-rejected", 502);
  }
  let value: unknown;
  try {
    value = parseStrictJson(bodyText.charCodeAt(0) === 0xfeff ? bodyText.slice(1) : bodyText);
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new DiscoveryBoundaryError("json-rejected", 502);
    }
    throw new DiscoveryBoundaryError("json-rejected", 502);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DiscoveryBoundaryError("json-rejected", 502);
  }
  return {
    status: 200,
    bodyText,
    bodyBytes: Buffer.from(response.body),
    value,
    sha256: createHash("sha256").update(response.body).digest("hex"),
    resolvedAddresses: Object.freeze(unique),
    ...policy,
  };
}

/**
 * Fetches immutable protocol evidence bytes through the same credential-free,
 * public-network, DNS-pinned, redirect-free, bounded HTTPS boundary as discovery.
 */
export async function fetchBoundedBytes(input: {
  readonly url: URL;
  readonly resolver?: DiscoveryResolver;
  readonly transport?: DiscoveryTransport;
  readonly clock?: DiscoveryClock;
}): Promise<BoundedBytesResult> {
  if (
    input.url.protocol !== "https:" || input.url.port !== "" || input.url.username !== "" ||
    input.url.password !== "" || input.url.hash !== ""
  ) {
    throw new DiscoveryBoundaryError("http-rejected");
  }
  const domain = canonicalizeDiscoveryDomain(input.url.hostname);
  const clock = input.clock ?? defaultClock;
  const deadlineAt = clock.monotonicNow() + DISCOVERY_DEADLINE_MS;
  const remainingDeadline = () => deadlineAt - clock.monotonicNow();
  let addresses: readonly ResolvedAddress[];
  try {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    addresses = await deadline((input.resolver ?? nodeDiscoveryResolver).resolve(domain), remaining);
  } catch (error) {
    sanitizedResolverFailure(error);
  }
  if (
    addresses.length === 0 || addresses.length > 8 ||
    addresses.some((address) => !isGlobalDiscoveryAddress(address))
  ) {
    throw new DiscoveryBoundaryError("dns-rejected", 502);
  }
  const uniqueByAddress = new Map(addresses.map((address) => {
    const canonical = address.family === 4
      ? ipv4Number(address.address)?.toString(16)
      : expandIpv6(address.address)?.toString(16);
    return [`${address.family}:${canonical ?? address.address.toLowerCase()}`, address] as const;
  }));
  if (uniqueByAddress.size !== addresses.length) throw new DiscoveryBoundaryError("dns-rejected", 502);
  const unique = [...uniqueByAddress.values()];
  let response: DiscoveryTransportResponse | undefined;
  let finalConnectionError: DiscoveryBoundaryError | undefined;
  for (const pinnedAddress of unique) {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    try {
      response = await (input.transport ?? nodeHttpsDiscoveryTransport).request({
        url: input.url,
        pinnedAddress,
        headers: {
          Accept: "application/octet-stream, application/json, text/markdown, text/plain",
          "Accept-Encoding": "identity",
          Connection: "close",
        },
        timeoutMs: remaining,
      });
      if (remainingDeadline() <= 0) throw new DiscoveryBoundaryError("timeout", 504);
      break;
    } catch (error) {
      const sanitized = error instanceof DiscoveryBoundaryError
        ? error
        : new DiscoveryBoundaryError("connect-rejected", 502);
      if (sanitized.code !== "connect-rejected" && sanitized.code !== "tls-rejected") throw sanitized;
      finalConnectionError = sanitized;
    }
  }
  if (response === undefined) throw finalConnectionError ?? new DiscoveryBoundaryError("connect-rejected", 502);
  if (response.statusCode >= 300 && response.statusCode < 400) {
    throw new DiscoveryBoundaryError("redirect-rejected", 502);
  }
  if (response.statusCode !== 200) throw new DiscoveryBoundaryError("http-rejected", 502);
  const contentType = (singleHeader(response.headers, "content-type") ?? "").toLowerCase();
  if (!/^(?:application\/(?:json|octet-stream)|text\/(?:markdown|plain))(?:\s*;\s*charset\s*=\s*utf-8)?$/u.test(contentType)) {
    throw new DiscoveryBoundaryError("content-rejected", 502);
  }
  if (response.body.length === 0 || response.body.length > DISCOVERY_MAX_BODY_BYTES) {
    throw new DiscoveryBoundaryError("body-too-large", 502);
  }
  return {
    bodyBytes: Buffer.from(response.body),
    sha256: createHash("sha256").update(response.body).digest("hex"),
    resolvedAddresses: Object.freeze(unique),
  };
}

/**
 * Performs a credential-free reachability probe with the same public-network,
 * DNS pinning, TLS, redirect, header/body, proxy-free, and deadline boundary as
 * metadata discovery. Response bytes and status are reduced to a digest and are
 * never returned to the caller or persisted as route data.
 */
export async function probeBoundedHttpsReachability(input: {
  readonly url: URL;
  readonly resolver?: DiscoveryResolver;
  readonly transport?: DiscoveryTransport;
  readonly clock?: DiscoveryClock;
}): Promise<BoundedReachabilityResult> {
  // Keep this reducer separate from the content-fetch helpers above: a probe
  // deliberately accepts bounded 2xx-4xx responses, returns no response body,
  // and persists only a status-class/body digest. Sharing the public API would
  // blur those stricter data-retention and status semantics even though the
  // DNS pinning and transport steps are intentionally parallel.
  if (
    input.url.protocol !== "https:" || input.url.port !== "" || input.url.username !== "" ||
    input.url.password !== "" || input.url.hash !== ""
  ) {
    throw new DiscoveryBoundaryError("http-rejected");
  }
  const domain = canonicalizeDiscoveryDomain(input.url.hostname);
  const clock = input.clock ?? defaultClock;
  const deadlineAt = clock.monotonicNow() + DISCOVERY_DEADLINE_MS;
  const remainingDeadline = () => deadlineAt - clock.monotonicNow();
  let addresses: readonly ResolvedAddress[];
  try {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    addresses = await deadline((input.resolver ?? nodeDiscoveryResolver).resolve(domain), remaining);
  } catch (error) {
    sanitizedResolverFailure(error);
  }
  if (addresses.length === 0 || addresses.length > 8 || addresses.some((address) => !isGlobalDiscoveryAddress(address))) {
    throw new DiscoveryBoundaryError("dns-rejected", 502);
  }
  const uniqueByAddress = new Map(addresses.map((address) => {
    const canonical = address.family === 4
      ? ipv4Number(address.address)?.toString(16)
      : expandIpv6(address.address)?.toString(16);
    return [`${address.family}:${canonical ?? address.address.toLowerCase()}`, address] as const;
  }));
  if (uniqueByAddress.size !== addresses.length) throw new DiscoveryBoundaryError("dns-rejected", 502);
  const unique = [...uniqueByAddress.values()];
  let response: DiscoveryTransportResponse | undefined;
  let finalConnectionError: DiscoveryBoundaryError | undefined;
  for (const pinnedAddress of unique) {
    const remaining = remainingDeadline();
    if (remaining <= 0) throw new DiscoveryBoundaryError("timeout", 504);
    try {
      response = await (input.transport ?? nodeHttpsDiscoveryTransport).request({
        url: input.url,
        pinnedAddress,
        headers: { Accept: "application/json", "Accept-Encoding": "identity", Connection: "close" },
        timeoutMs: remaining,
      });
      if (remainingDeadline() <= 0) throw new DiscoveryBoundaryError("timeout", 504);
      break;
    } catch (error) {
      const sanitized = error instanceof DiscoveryBoundaryError
        ? error
        : new DiscoveryBoundaryError("connect-rejected", 502);
      if (sanitized.code !== "connect-rejected" && sanitized.code !== "tls-rejected") throw sanitized;
      finalConnectionError = sanitized;
    }
  }
  if (response === undefined) throw finalConnectionError ?? new DiscoveryBoundaryError("connect-rejected", 502);
  if (response.statusCode >= 300 && response.statusCode < 400) {
    throw new DiscoveryBoundaryError("redirect-rejected", 502);
  }
  if (response.statusCode < 200 || response.statusCode >= 500) {
    throw new DiscoveryBoundaryError("http-rejected", 502);
  }
  if (response.body.length > DISCOVERY_MAX_BODY_BYTES) {
    throw new DiscoveryBoundaryError("body-too-large", 502);
  }
  return {
    resolvedAddresses: Object.freeze(unique),
    evidenceSha256: createHash("sha256").update(stableProbeEvidence({
      url: input.url.href,
      addresses: [...uniqueByAddress.keys()].sort(),
      statusClass: Math.floor(response.statusCode / 100),
      bodySha256: createHash("sha256").update(response.body).digest("hex"),
    })).digest("hex"),
  };
}

function stableProbeEvidence(value: {
  readonly url: string;
  readonly addresses: readonly string[];
  readonly statusClass: number;
  readonly bodySha256: string;
}): string {
  return JSON.stringify({
    addresses: value.addresses,
    body_sha256: value.bodySha256,
    status_class: value.statusClass,
    url: value.url,
  });
}
