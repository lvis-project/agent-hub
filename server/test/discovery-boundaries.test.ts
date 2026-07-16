import { generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:https";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { describe, expect, it } from "vitest";
import {
  canonicalizeDiscoveryDomain,
  canonicalizeProtectedJku,
  createNodeHttpsDiscoveryTransport,
  DiscoveryBoundaryError,
  fetchBoundedJson,
  isGlobalDiscoveryAddress,
  type DiscoveryTransport,
  type DiscoveryTransportResponse,
  type ResolvedAddress,
} from "../src/a2a/discovery-egress.js";
import { parseObservedJwks } from "../src/a2a/jwks.js";
import { parseStrictJson, StrictJsonError } from "../src/a2a/strict-json.js";

const publicV4 = { address: "8.8.8.8", family: 4 as const };
const publicV6 = { address: "2606:4700:4700::1111", family: 6 as const };

const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDMXxDjv6nW0u/p
LQrgHIPWuePkSvTYwfN1wzxYklOzl8Ve1rGP3oWNunlOP1OLHtomQBsPDKQaJ2Fx
tWyiAUpLQNnM0Jh0h5Y+B82tA46eWtj7sDoh/1gJ51A7dDe+TqoCQ2SvCuwCRmO5
IcjJZ05Ku6j9GCKFCDoTs6sDp+JuAp0sOiQa8Sq6xLcWw7mxvFCC2Hwjvxnc6Kyw
3fQVhr7Vl2dC9mnD4IwjGodaKi3AAp8kXnqIz65bh9jcwxLUkx+WVocuOMAwH+V2
xZDv4yeZEJKFxDlIpTV+86z6Lk11Xnz3I/ipQWNFr+cZ5//HOwz4tP27l33l/5cX
Oj6D4YkLAgMBAAECggEBAJ+idjffgxNZKqqRU1hhDZ4RD3BIGF6jiL7opF9u1NCI
cVO2EXYWU220RYKYNnKJw85y7m/f6OLA9f1ywAr/RP/pBPdVzG/hZLrJL5/AEoug
3LIkIhRiNmtt8h6ulcgh++vOpnuP5W+VedmnCQZAmkgHs2UWkAgnt+2hvqgZX+Wa
355uTDL3+Obnkhq2munEjVkxxMqDNT8L5voFHIA/UU2NrIgYT84YaEmDLRudT8uU
uVysIkXVkUgR3JPGBd80nmELtV2OV4cwoSb5+Mu2C+85smD43/PW/NmixPVyjX9m
UcbbWxBDPav4N8rwIoUegFmj8k6cYMz1OUdMGBhLdxkCgYEA/y/wGPih7SXQpWsE
WHJNpzUY+3kZbg56BAVQ8ga4AVkGT+Zdz7pURQpDgOJUIraPB+Hgv8qO8fJaDLxI
3NHASyGpLcOhZ7iJUgak7LHvFr3/GiWbWGSKthHtNmIjdycxyqQHypJVMChNYpYU
BXc6V9q4ceraRTPEaCeCDENErB0CgYEAzQWyQO/o6chhTFW0MySPaqEDGXyvH72Q
RQhyWxJapusTiKSMrhvZoSDVgwvKPnYkngTZCnE9eY5QkLQHwzwWDw2A6hcpudOb
y44JgjZth2pLlmCnS8vW7CRRwi5dvzn/OQMvdC3D4L6HWa04fj/a1V9Bqd91U6d+
gk2vJdLBcUcCgYEAuo4qIadKgZs+kF/PGnXdrRqVO+qJG7s7mkrkpTsiM+IISkso
U99tEdfyB3vudD4wDFwmOS/1Fo3NJThUsBIrWQGvs4QsMC5pPW0cDun51w9pOo05
pwJBod8zIqnWMZqWvQTzqTUXUBB2mlcLJf/GyElew/EkRqkUsewIF7zprEUCgYEA
ylgp4m8lN75dUQJw89zMctdwgLIPAMuNXKSGgJ2vvHfb8os8kQXJl34ZW9nCBD2D
zDVKpES5AIRVvUsBMk3WE4snRWIQ+2b+pzqK5emj1fcxnLvNwT/v4WXDD1vFiFrM
Ks+bARW98cz5NqeATxHkf5wg6XAykpqHgED9cN39rzcCgYEAybGZFEJcD6WIwPUn
Id9jl0G3Mfki/vfINYo2XO73+8tmvBWaepZsCo1JwR53yyhTAUEJTxtzV1/j/2eZ
/69CQzFEPB4y7lYdb/ku87vskWCkrUGPisfr15+dsKUg5Q7KZbYNjhtNBgB5YgoG
vj375OAcTpIKFEhoMnvuFDFH8VA=
-----END PRIVATE KEY-----`;

const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUKiu19X1HbGbp89/ywcBy5PJkROIwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNYWdlbnQuZXhhbXBsZTAeFw0yNjA3MTYwMzM3MDRaFw0y
NjA3MTcwMzM3MDRaMBgxFjAUBgNVBAMMDWFnZW50LmV4YW1wbGUwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMXxDjv6nW0u/pLQrgHIPWuePkSvTYwfN1
wzxYklOzl8Ve1rGP3oWNunlOP1OLHtomQBsPDKQaJ2FxtWyiAUpLQNnM0Jh0h5Y+
B82tA46eWtj7sDoh/1gJ51A7dDe+TqoCQ2SvCuwCRmO5IcjJZ05Ku6j9GCKFCDoT
s6sDp+JuAp0sOiQa8Sq6xLcWw7mxvFCC2Hwjvxnc6Kyw3fQVhr7Vl2dC9mnD4Iwj
GodaKi3AAp8kXnqIz65bh9jcwxLUkx+WVocuOMAwH+V2xZDv4yeZEJKFxDlIpTV+
86z6Lk11Xnz3I/ipQWNFr+cZ5//HOwz4tP27l33l/5cXOj6D4YkLAgMBAAGjbTBr
MB0GA1UdDgQWBBQUAf7BAaSK4bfFPv4riz/7MhElDTAfBgNVHSMEGDAWgBQUAf7B
AaSK4bfFPv4riz/7MhElDTAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDWFn
ZW50LmV4YW1wbGUwDQYJKoZIhvcNAQELBQADggEBAKrS2XN8QvEAzBRbWinD51aY
zMukjNnN6jlDJ3HuEaSfmFFpw2kHdIYh/ha976uHhonxATAa2CzWXBZVfLP5UOlB
HPl4mQvsLlVHeAU/wlsG7V+rObzKjyznT60Z07i8TJduHoNyWZQ30VYY4GFn40HT
fNrpqqPNKM2DIJUwUjzLGwe+fffd4j7Cj6gyBxqQQxLfD27Y0I6RUQLZUK/IiquY
w5aWTTqqoK5VORzt/Ykd2AVjqLQH3Y8Q5dkEN7GewBG0jWYhSaMSR71DyvRVNmra
R9Kp7XUpZHTyN4pPuFYZFxDBxrOy/GeU2Z5Q/StiPrloACgV0tX7F/dO8rw+taI=
-----END CERTIFICATE-----`;

function response(
  body: string,
  overrides: Partial<DiscoveryTransportResponse> = {},
): DiscoveryTransportResponse {
  return {
    statusCode: 200,
    headers: { "content-type": "application/json" },
    body: Buffer.from(body),
    ...overrides,
  };
}

function boundaryCode(error: unknown): string {
  expect(error).toBeInstanceOf(DiscoveryBoundaryError);
  return (error as DiscoveryBoundaryError).code;
}

describe("G003 strict discovery boundaries", () => {
  it("canonicalizes IDNA/trailing-dot domains and allows only same-origin protected JKU queries", () => {
    expect(canonicalizeDiscoveryDomain("BÜCHER.Example.")).toBe("xn--bcher-kva.example");
    const card = new URL("https://agent.example/.well-known/agent-card.json");
    expect(canonicalizeProtectedJku("https://agent.example/keys.json?version=2", card).href)
      .toBe("https://agent.example/keys.json?version=2");
    expect(() => canonicalizeProtectedJku("https://keys.agent.example/keys.json", card)).toThrow(DiscoveryBoundaryError);
    expect(() => canonicalizeProtectedJku("https://agent.example:444/keys.json", card)).toThrow(DiscoveryBoundaryError);
    expect(() => canonicalizeProtectedJku("https://agent.example/keys.json#fragment", card)).toThrow(DiscoveryBoundaryError);
  });

  it.each([
    ["0.0.0.0", 4], ["10.0.0.1", 4], ["100.64.0.1", 4], ["127.0.0.1", 4],
    ["169.254.1.1", 4], ["172.16.0.1", 4], ["192.0.2.1", 4], ["198.51.100.1", 4],
    ["203.0.113.1", 4], ["224.0.0.1", 4], ["::", 6], ["::1", 6], ["::ffff:8.8.8.8", 6],
    ["2001:db8::1", 6], ["2002:0808:0808::1", 6],
    ["fc00::1", 6], ["fe80::1", 6], ["ff00::1", 6], ["3fff::1", 6],
  ] as const)("rejects IANA special-purpose address %s", (address, family) => {
    expect(isGlobalDiscoveryAddress({ address, family })).toBe(false);
  });

  it("accepts public IPv4 and IPv6 addresses", () => {
    expect(isGlobalDiscoveryAddress(publicV4)).toBe(true);
    expect(isGlobalDiscoveryAddress(publicV6)).toBe(true);
  });

  it.each([
    ["192.0.0.9", 4], ["192.0.0.10", 4], ["192.31.196.1", 4],
    ["192.52.193.1", 4], ["192.175.48.1", 4],
    ["64:ff9b::8.8.8.8", 6],
    ["2001:1::1", 6], ["2001:1::2", 6], ["2001:1::3", 6],
    ["2001:3::1", 6], ["2001:4:112::1", 6], ["2001:20::1", 6], ["2001:30::1", 6],
    ["2620:4f:8000::1", 6],
  ] as const)("accepts the IANA globally reachable special-purpose exception %s", (address, family) => {
    expect(isGlobalDiscoveryAddress({ address, family })).toBe(true);
  });

  it.each([
    ["192.0.0.8", 4], ["192.0.0.11", 4], ["2001::1", 6], ["2001:1::4", 6],
    ["64:ff9b:1::8.8.8.8", 6], ["2001:2::1", 6], ["2001:10::1", 6],
  ] as const)("keeps non-global neighbors of IANA exceptions rejected for %s", (address, family) => {
    expect(isGlobalDiscoveryAddress({ address, family })).toBe(false);
  });

  it("rejects a mixed public/private answer set and more than eight answers before connect", async () => {
    let connections = 0;
    const transport: DiscoveryTransport = { async request() { connections += 1; return response("{}"); } };
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [publicV4, { address: "127.0.0.1", family: 4 }]; } },
      transport,
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "dns-rejected");
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return Array.from({ length: 9 }, (_, index) => ({ address: `8.8.8.${index + 1}`, family: 4 as const })); } },
      transport,
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "dns-rejected");
    expect(connections).toBe(0);
  });

  it("rejects duplicate DNS answers instead of silently deduplicating", async () => {
    let connections = 0;
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [publicV4, publicV4]; } },
      transport: { async request() { connections += 1; return response("{}"); } },
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "dns-rejected");
    expect(connections).toBe(0);
  });

  it("canonicalizes IPv6 answers before duplicate rejection", async () => {
    let connections = 0;
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [
        { address: "2606:4700:4700::1111", family: 6 },
        { address: "2606:4700:4700:0:0:0:0:1111", family: 6 },
      ]; } },
      transport: { async request() { connections += 1; return response("{}"); } },
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "dns-rejected");
    expect(connections).toBe(0);
  });

  it("tries validated pinned addresses in deterministic order without resolver fallback", async () => {
    const attempts: ResolvedAddress[] = [];
    const transport: DiscoveryTransport = {
      async request(input) {
        attempts.push(input.pinnedAddress);
        if (attempts.length === 1) throw new DiscoveryBoundaryError("connect-rejected", 502);
        return response('{"ok":true}');
      },
    };
    const result = await fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [publicV6, publicV4]; } },
      transport,
    });
    expect(attempts).toEqual([publicV6, publicV4]);
    expect(result.value).toEqual({ ok: true });
  });

  it("preserves interleaved v6-v4-v6 resolver order with one resolver call and one fresh attempt per address", async () => {
    const secondV6 = { address: "2606:4700:4700::1001", family: 6 as const };
    const expected = [publicV6, publicV4, secondV6];
    const attempts: ResolvedAddress[] = [];
    let resolverCalls = 0;
    const result = await fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { resolverCalls += 1; return expected; } },
      transport: { async request(input) {
        attempts.push(input.pinnedAddress);
        if (attempts.length < expected.length) throw new DiscoveryBoundaryError("connect-rejected", 502);
        return response('{"ok":true}');
      } },
    });
    expect(resolverCalls).toBe(1);
    expect(attempts).toEqual(expected);
    expect(new Set(attempts.map((address) => `${address.family}:${address.address}`)).size).toBe(3);
    expect(result.value).toEqual({ ok: true });
  });

  it("uses one monotonic absolute deadline even when the wall clock rolls back", async () => {
    let wall = 10_000;
    let monotonic = 100;
    const timeouts: number[] = [];
    const attempts: ResolvedAddress[] = [];
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      clock: { wallNow: () => wall, monotonicNow: () => monotonic },
      resolver: { async resolve() {
        wall -= 100_000;
        monotonic += 2_000;
        return [publicV6, publicV4];
      } },
      transport: { async request(input) {
        attempts.push(input.pinnedAddress);
        timeouts.push(input.timeoutMs);
        wall -= 100_000;
        monotonic += 3_001;
        throw new DiscoveryBoundaryError("connect-rejected", 502);
      } },
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "timeout");
    expect(attempts).toEqual([publicV6]);
    expect(timeouts).toEqual([3_000]);
  });

  it("rejects a transport result that arrives after the monotonic deadline", async () => {
    let monotonic = 0;
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      clock: { wallNow: () => 1_000, monotonicNow: () => monotonic },
      resolver: { async resolve() { return [publicV4]; } },
      transport: { async request() {
        monotonic = 5_001;
        return response("{}");
      } },
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "timeout");
  });

  it("uses one actual pinned socket lookup with canonical Host/SNI, TLS 1.2+, and no proxy bypass", async () => {
    let hostHeader: string | undefined;
    let servername: string | undefined;
    const server = createServer({ key: TLS_KEY, cert: TLS_CERT }, (request, reply) => {
      hostHeader = request.headers.host;
      const negotiatedServername = (request.socket as TLSSocket).servername;
      servername = typeof negotiatedServername === "string" ? negotiatedServername : undefined;
      reply.writeHead(200, { "content-type": "application/json" });
      reply.end("{}");
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("TLS server did not bind an IP port");
    let lookupCalls = 0;
    let connectionOptions: Record<string, unknown> | undefined;
    let socketError: Error | undefined;
    const previousProxy = process.env.HTTPS_PROXY;
    process.env.HTTPS_PROXY = "http://127.0.0.1:1";
    try {
      const transport = createNodeHttpsDiscoveryTransport({
        createConnection(options) {
          connectionOptions = options as unknown as Record<string, unknown>;
          const originalLookup = options.lookup;
          if (originalLookup === undefined) throw new Error("Pinned lookup was not configured");
          const socket = tlsConnect({
            host: "agent.example",
            port: address.port,
            ca: TLS_CERT,
            servername: "agent.example",
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            lookup: ((hostname: string, lookupOptions: unknown, lookupCallback: unknown) => {
              lookupCalls += 1;
              const callback = typeof lookupOptions === "function" ? lookupOptions : lookupCallback;
              const options = typeof lookupOptions === "function" ? { all: false } : lookupOptions;
              Reflect.apply(originalLookup, undefined, [hostname, options, callback]);
            }) as NonNullable<typeof options.lookup>,
          });
          socket.once("error", (error) => { socketError = error; });
          return socket;
        },
      });
      try {
        await expect(transport.request({
          url: new URL("https://agent.example/.well-known/agent-card.json"),
          pinnedAddress: { address: "127.0.0.1", family: 4 },
          headers: { Accept: "application/json", "Accept-Encoding": "identity", Connection: "close" },
          timeoutMs: 2_000,
        })).resolves.toMatchObject({ statusCode: 200 });
      } catch (error) {
        throw new Error(`Pinned TLS request failed: ${socketError?.message ?? "no socket error"}`, { cause: error });
      }
      expect(lookupCalls).toBe(1);
      expect(hostHeader).toBe("agent.example");
      expect(servername).toBe("agent.example");
      expect(connectionOptions).toMatchObject({ servername: "agent.example", minVersion: "TLSv1.2", rejectUnauthorized: true });
    } finally {
      if (previousProxy === undefined) delete process.env.HTTPS_PROXY;
      else process.env.HTTPS_PROXY = previousProxy;
      server.close();
      await once(server, "close");
    }
  });

  it.each(["application/json", "application/problem+json", "application/vnd.a2a+json; charset=UTF-8"])(
    "accepts bounded JSON MIME %s",
    async (contentType) => {
      await expect(fetchBoundedJson({
        url: new URL("https://agent.example/card"),
        resolver: { async resolve() { return [publicV4]; } },
        transport: { async request() { return response("{}", { headers: { "content-type": contentType } }); } },
      })).resolves.toMatchObject({ status: 200 });
    },
  );

  it("bounds validators, rejects duplicate validators, and applies cache freshness directives", async () => {
    const run = (headers: DiscoveryTransportResponse["headers"]) => fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [publicV4]; } },
      transport: { async request() { return response("{}", { headers: { "content-type": "application/json", ...headers } }); } },
      clock: { wallNow: () => 1_000, monotonicNow: () => 0 },
    });
    await expect(run({ etag: "x".repeat(1025) })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "headers-too-large");
    await expect(run({ etag: ['"one"', '"two"'] })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "http-rejected");
    await expect(run({ "last-modified": "not-a-date" })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "http-rejected");
    await expect(run({ "cache-control": "max-age=99999" })).resolves.toMatchObject({ freshnessMs: 15 * 60_000 });
    await expect(run({ "cache-control": "max-age=invalid" })).resolves.toMatchObject({ freshnessMs: 0 });
    await expect(run({ "cache-control": "no-cache, max-age=600" })).resolves.toMatchObject({ freshnessMs: 0, noStore: false });
    await expect(run({ "cache-control": "public, max-age=600, no-cache=etag" })).resolves.toMatchObject({ freshnessMs: 0, noStore: false });
    await expect(run({ "cache-control": "public, max-age=600, no-cache=\"etag, last-modified\"" })).resolves.toMatchObject({ freshnessMs: 0, noStore: false });
    await expect(run({ "cache-control": ["max-age=60", "public"] })).resolves.toMatchObject({ freshnessMs: 60_000 });
    await expect(run({ "cache-control": ["max-age=60", "max-age=120"] })).resolves.toMatchObject({ freshnessMs: 0 });
    await expect(run({ "cache-control": "no-store", etag: '"secret"' })).resolves.toMatchObject({ freshnessMs: 0, noStore: true, etag: null });
    await expect(run({ "cache-control": "no-store", etag: ['"one"', '"two"'] })).rejects.toSatisfy(
      (error: unknown) => boundaryCode(error) === "http-rejected",
    );
  });

  it("accepts 304 only with a validator and an empty body", async () => {
    const transport: DiscoveryTransport = { async request() { return response("", { statusCode: 304, headers: {} }); } };
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"), resolver: { async resolve() { return [publicV4]; } }, transport,
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "cache-miss");
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"), resolver: { async resolve() { return [publicV4]; } }, transport,
      etag: '"v1"', allowNotModified: true,
    })).resolves.toMatchObject({ status: 304, bodyBytes: null });
  });

  it("enforces JSON depth, node, object-member, array-item, duplicate-key, and byte caps", () => {
    expect(() => parseStrictJson(`${"[".repeat(32)}0${"]".repeat(32)}`)).not.toThrow();
    expect(() => parseStrictJson(`${"[".repeat(33)}0${"]".repeat(33)}`)).toThrow(StrictJsonError);
    expect(() => parseStrictJson(`{${Array.from({ length: 257 }, (_, index) => `"k${index}":0`).join(",")}}`)).toThrow(StrictJsonError);
    expect(() => parseStrictJson(`[${Array.from({ length: 1025 }, () => "0").join(",")}]`)).toThrow(StrictJsonError);
    expect(() => parseStrictJson(`[${Array.from({ length: 4096 }, () => "0").join(",")}]`)).toThrow(StrictJsonError);
    expect(() => parseStrictJson('{"a":1,"\\u0061":2}')).toThrowError(expect.objectContaining({ code: "json-duplicate-key" }));
    expect(() => parseStrictJson(JSON.stringify("x".repeat(64 * 1024)))).toThrow(StrictJsonError);
    expect(() => parseStrictJson(`${"[".repeat(32)}${"]".repeat(32)}`)).not.toThrow();
    expect(() => parseStrictJson(`${"[".repeat(33)}${"]".repeat(33)}`)).toThrow(StrictJsonError);
    expect(() => parseStrictJson(`${'{"x":'.repeat(31)}{}${"}".repeat(31)}`)).not.toThrow();
    expect(() => parseStrictJson(`${'{"x":'.repeat(32)}{}${"}".repeat(32)}`)).toThrow(StrictJsonError);
  });

  it.each(["null", "true", "0", '"text"', "[]"])("rejects top-level non-object JSON %s before P4-1", async (body) => {
    await expect(fetchBoundedJson({
      url: new URL("https://agent.example/card"),
      resolver: { async resolve() { return [publicV4]; } },
      transport: { async request() { return response(body); } },
    })).rejects.toSatisfy((error: unknown) => boundaryCode(error) === "json-rejected");
  });

  it("rejects duplicate/private/confused JWKS keys and accepts exact P-256/Ed25519 public keys", () => {
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
    const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
    const keys = parseObservedJwks({ keys: [
      { ...ec, kid: "ec-1", alg: "ES256", use: "sig", key_ops: ["verify"] },
      { ...ed, kid: "ed-1", alg: "EdDSA", use: "sig", key_ops: ["verify"] },
    ] });
    expect(keys.map((key) => [key.keyId, key.algorithm])).toEqual([["ec-1", "ES256"], ["ed-1", "EdDSA"]]);
    expect(() => parseObservedJwks({ keys: [{ ...ec, kid: "dup" }, { ...ec, kid: "dup" }] })).toThrow(DiscoveryBoundaryError);
    expect(() => parseObservedJwks({ keys: [{ ...ec, kid: "private", d: "AA" }] })).toThrow(DiscoveryBoundaryError);
    expect(() => parseObservedJwks({ keys: [{ ...ec, kid: "confused", alg: "EdDSA" }] })).toThrow(DiscoveryBoundaryError);
    expect(() => parseObservedJwks({ keys: [{ kty: "oct", kid: "secret", k: "AA" }] })).toThrow(DiscoveryBoundaryError);
  });
});
