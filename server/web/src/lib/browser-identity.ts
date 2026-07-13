/**
 * Browser-local P-256 enrollment identity.
 *
 * The private key is re-imported as non-extractable before it is persisted in
 * IndexedDB. It never enters sessionStorage, localStorage, or an API request.
 */
export type BrowserIdentity = {
  privateKey: CryptoKey;
  publicKeyPem: string;
  publicAddress: string;
};

type StoredBrowserIdentity = BrowserIdentity & { id: "current" };

const DB_NAME = "agent-hub-browser-identity";
const STORE_NAME = "identities";
const CURRENT_ID = "current";
const textEncoder = new TextEncoder();

function requireWebCrypto(): Crypto {
  if ("isSecureContext" in globalThis && globalThis.isSecureContext === false) {
    throw new Error("ECDSA signup requires an HTTPS secure context.");
  }
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    throw new Error("This browser does not provide the Web Crypto API required for ECDSA signup.");
  }
  return globalThis.crypto;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function pemFromSpki(spki: ArrayBuffer): string {
  const body = bytesToBase64(new Uint8Array(spki)).match(/.{1,64}/g)?.join("\n");
  if (!body) throw new Error("Unable to encode browser public key.");
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

async function addressFromSpki(spki: ArrayBuffer, cryptoApi: Crypto): Promise<string> {
  const digest = new Uint8Array(await cryptoApi.subtle.digest("SHA-256", spki));
  return `ah1_${Array.from(digest).map((byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 40)}`;
}

function derInteger(source: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < source.length - 1 && source[offset] === 0) offset += 1;
  const unsigned = source.subarray(offset);
  if ((unsigned[0] & 0x80) === 0) return unsigned;
  const padded = new Uint8Array(unsigned.length + 1);
  padded.set(unsigned, 1);
  return padded;
}

/** Convert Web Crypto's fixed-width P-256 r||s signature into ASN.1 DER. */
function p256RawSignatureToDer(raw: ArrayBuffer): Uint8Array {
  const signature = new Uint8Array(raw);
  if (signature.length !== 64) throw new Error("Browser returned an invalid P-256 ECDSA signature.");
  const r = derInteger(signature.subarray(0, 32));
  const s = derInteger(signature.subarray(32));
  const payloadLength = 2 + r.length + 2 + s.length;
  const der = new Uint8Array(2 + payloadLength);
  let offset = 0;
  der[offset++] = 0x30;
  der[offset++] = payloadLength;
  der[offset++] = 0x02;
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 0x02;
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
}

export async function createBrowserIdentity(cryptoApi = requireWebCrypto()): Promise<BrowserIdentity> {
  const generated = await cryptoApi.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  if (!("privateKey" in generated) || !("publicKey" in generated)) {
    throw new Error("Browser did not create an ECDSA key pair.");
  }

  const spki = await cryptoApi.subtle.exportKey("spki", generated.publicKey);
  return {
    privateKey: generated.privateKey,
    publicKeyPem: pemFromSpki(spki),
    publicAddress: await addressFromSpki(spki, cryptoApi),
  };
}

function openIdentityDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    return Promise.reject(new Error("This browser does not provide IndexedDB required to retain its signing identity."));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME, { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Unable to open browser identity storage."));
    request.onblocked = () => reject(new Error("Browser identity storage is blocked by another tab."));
  });
}

function validStoredIdentity(value: unknown): value is StoredBrowserIdentity {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<StoredBrowserIdentity>;
  const algorithm = candidate.privateKey?.algorithm as EcKeyAlgorithm | undefined;
  return candidate.id === CURRENT_ID
    && candidate.privateKey?.type === "private"
    && candidate.privateKey.extractable === false
    && candidate.privateKey.usages.includes("sign")
    && algorithm?.name === "ECDSA"
    && algorithm.namedCurve === "P-256"
    && typeof candidate.publicKeyPem === "string"
    && /^ah1_[0-9a-f]{40}$/.test(candidate.publicAddress ?? "");
}

async function loadStoredIdentity(): Promise<BrowserIdentity | null> {
  const database = await openIdentityDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(CURRENT_ID);
      request.onsuccess = () => {
        if (request.result === undefined) return resolve(null);
        if (!validStoredIdentity(request.result)) return reject(new Error("Stored browser identity is invalid. Clear this site's data before registering again."));
        const { privateKey, publicKeyPem, publicAddress } = request.result;
        return resolve({ privateKey, publicKeyPem, publicAddress });
      };
      request.onerror = () => reject(request.error ?? new Error("Unable to read browser identity storage."));
    });
  } finally {
    database.close();
  }
}

async function saveBrowserIdentity(identity: BrowserIdentity): Promise<void> {
  const database = await openIdentityDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put({ id: CURRENT_ID, ...identity } satisfies StoredBrowserIdentity);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("Unable to save browser identity."));
      transaction.onabort = () => reject(transaction.error ?? new Error("Browser identity storage was aborted."));
    });
  } finally {
    database.close();
  }
}

/** Load this origin's existing non-exportable key, or create it once. */
export async function loadOrCreateBrowserIdentity(): Promise<BrowserIdentity> {
  const existing = await loadStoredIdentity();
  if (existing) return existing;
  const identity = await createBrowserIdentity();
  await saveBrowserIdentity(identity);
  return identity;
}

/** Sign the server-provided signup message using DER, as required by the API. */
export async function signSignupMessage(identity: BrowserIdentity, message: string, cryptoApi = requireWebCrypto()): Promise<string> {
  const rawSignature = await cryptoApi.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.privateKey,
    textEncoder.encode(message),
  );
  return base64Url(p256RawSignatureToDer(rawSignature));
}
