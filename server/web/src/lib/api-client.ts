/// <reference types="vite/client" />
import { getStoredKey } from "./auth";

const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export interface ApiRequestInit extends RequestInit {
  auth?: boolean;
  /** One-shot bearer token, used by desktop login before sessionStorage write. */
  authToken?: string;
  json?: unknown;
  idempotencyKey?: string;
}

export async function apiRequest<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  const { auth, authToken, json, idempotencyKey, headers: rawHeaders, ...rest } = init;
  const headers = new Headers(rawHeaders);

  if (auth || authToken !== undefined) {
    const key = authToken ?? getStoredKey();
    if (!key) throw new ApiError(401, "Not logged in");
    headers.set("authorization", `Bearer ${key}`);
  }

  let body = rest.body;
  if (json !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(json);
  }

  if (idempotencyKey) {
    headers.set("idempotency-key", idempotencyKey);
  }

  const res = await fetch(`${API_BASE}${path}`, { ...rest, headers, body });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }
  return (await res.json()) as T;
}

export function generateIdempotencyKey(): string {
  return `web-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
