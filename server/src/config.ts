import { z } from "zod";

const defaultOrigins = ["http://127.0.0.1:5174", "http://localhost:5174"];

const settingsSchema = z.object({
  AGENT_HUB_DB_URL: z.string().min(1).default("sqlite://./agent-hub.db"),
  AGENT_HUB_POSTGRES_TLS_MODE: z.enum(["disabled", "verify-full"]).optional(),
  AGENT_HUB_POSTGRES_LOCAL_COMPOSE: z.literal("1").optional(),
  AGENT_HUB_POSTGRES_TLS_CA_FILE: z.string().optional(),
  AGENT_HUB_HOST: z.string().min(1).default("127.0.0.1"),
  AGENT_HUB_PORT: z.coerce.number().int().min(1).max(65535).default(8000),
  AGENT_HUB_LOG_LEVEL: z.string().default("info"),
  AGENT_HUB_RATE_LIMIT_PER_IP_PER_MIN: z.coerce.number().int().min(1).default(300),
  AGENT_HUB_SIGNUP_RATE_LIMIT_PER_IP_PER_MIN: z.coerce.number().int().min(1).default(10),
  AGENT_HUB_TRUST_PROXY: z.string().default(""),
  AGENT_HUB_CORS_ORIGINS: z.string().optional(),
  AGENT_HUB_TLS_HSTS_MAX_AGE: z.coerce.number().int().min(0).default(63_072_000),
  AGENT_HUB_CREDENTIAL_REFERENCE_HMAC_KEY: z.string().min(32).optional(),
});

export type PostgresTlsConfig =
  | { mode: "disabled"; caFile: null }
  | { mode: "verify-full"; caFile: string };

export type Settings = {
  databaseUrl: string;
  postgresTls: PostgresTlsConfig;
  host: string;
  port: number;
  logLevel: string;
  rateLimitPerIpPerMinute: number;
  signupRateLimitPerIpPerMinute: number;
  trustedProxyIps: string[];
  corsOrigins: string[];
  tlsHstsMaxAge: number;
  credentialReferenceHmacKey: string | null;
};

function isBundledLocalComposePostgresUrl(databaseUrl: string): boolean {
  try {
    const parsed = new URL(databaseUrl);
    return (
      (parsed.protocol === "postgres:" || parsed.protocol === "postgresql:") &&
      parsed.hostname === "postgres" &&
      (parsed.port === "" || parsed.port === "5432") &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

export function loadSettings(env: NodeJS.ProcessEnv = process.env): Settings {
  const parsed = settingsSchema.parse(env);
  const corsOrigins = parsed.AGENT_HUB_CORS_ORIGINS === undefined
    ? defaultOrigins
    : parsed.AGENT_HUB_CORS_ORIGINS.split(",").map((value) => value.trim()).filter(Boolean);
  const trustedProxyIps = parsed.AGENT_HUB_TRUST_PROXY.split(",").map((value) => value.trim()).filter(Boolean);
  if (corsOrigins.length === 0 || corsOrigins.includes("*")) {
    throw new Error("AGENT_HUB_CORS_ORIGINS must list one or more explicit origins");
  }
  if (!parsed.AGENT_HUB_DB_URL.startsWith("sqlite://") && !parsed.AGENT_HUB_DB_URL.startsWith("postgres://") && !parsed.AGENT_HUB_DB_URL.startsWith("postgresql://")) {
    throw new Error("AGENT_HUB_DB_URL must use sqlite://, postgres://, or postgresql://");
  }
  const isPostgres = parsed.AGENT_HUB_DB_URL.startsWith("postgres://") || parsed.AGENT_HUB_DB_URL.startsWith("postgresql://");
  if (isPostgres && parsed.AGENT_HUB_POSTGRES_TLS_MODE === undefined) {
    throw new Error("AGENT_HUB_POSTGRES_TLS_MODE must be explicitly set to disabled or verify-full when AGENT_HUB_DB_URL uses PostgreSQL");
  }
  if (
    isPostgres &&
    parsed.AGENT_HUB_POSTGRES_LOCAL_COMPOSE === "1" &&
    parsed.AGENT_HUB_POSTGRES_TLS_MODE === "verify-full"
  ) {
    throw new Error("AGENT_HUB_POSTGRES_LOCAL_COMPOSE must not be combined with AGENT_HUB_POSTGRES_TLS_MODE=verify-full; select exactly one PostgreSQL deployment overlay");
  }
  if (
    isPostgres &&
    parsed.AGENT_HUB_POSTGRES_TLS_MODE === "disabled" &&
    (!isBundledLocalComposePostgresUrl(parsed.AGENT_HUB_DB_URL) || parsed.AGENT_HUB_POSTGRES_LOCAL_COMPOSE !== "1")
  ) {
    throw new Error("AGENT_HUB_POSTGRES_TLS_MODE=disabled is permitted only by deploy/docker-compose.local-postgres.yml with its bundled private PostgreSQL DSN; supported remote deployments require verify-full");
  }
  const postgresTls: PostgresTlsConfig = parsed.AGENT_HUB_POSTGRES_TLS_MODE === "verify-full"
    ? (() => {
      if (!isPostgres) throw new Error("AGENT_HUB_POSTGRES_TLS_MODE=verify-full requires a PostgreSQL AGENT_HUB_DB_URL");
      const configuredCaFile = parsed.AGENT_HUB_POSTGRES_TLS_CA_FILE;
      const caFile = configuredCaFile?.trim();
      if (!caFile) {
        if (configuredCaFile !== undefined) {
          throw new Error("AGENT_HUB_POSTGRES_TLS_CA_FILE must not be blank");
        }
        throw new Error("AGENT_HUB_POSTGRES_TLS_CA_FILE is required when AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
      }
      return { mode: "verify-full", caFile };
    })()
    : (() => {
      if (isPostgres && parsed.AGENT_HUB_POSTGRES_TLS_CA_FILE !== undefined) {
        if (!parsed.AGENT_HUB_POSTGRES_TLS_CA_FILE.trim()) {
          throw new Error("AGENT_HUB_POSTGRES_TLS_CA_FILE must not be blank");
        }
        throw new Error("AGENT_HUB_POSTGRES_TLS_CA_FILE requires AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
      }
      return { mode: "disabled", caFile: null };
    })();
  return {
    databaseUrl: parsed.AGENT_HUB_DB_URL,
    postgresTls,
    host: parsed.AGENT_HUB_HOST,
    port: parsed.AGENT_HUB_PORT,
    logLevel: parsed.AGENT_HUB_LOG_LEVEL,
    rateLimitPerIpPerMinute: parsed.AGENT_HUB_RATE_LIMIT_PER_IP_PER_MIN,
    signupRateLimitPerIpPerMinute: parsed.AGENT_HUB_SIGNUP_RATE_LIMIT_PER_IP_PER_MIN,
    trustedProxyIps,
    corsOrigins,
    tlsHstsMaxAge: parsed.AGENT_HUB_TLS_HSTS_MAX_AGE,
    credentialReferenceHmacKey: parsed.AGENT_HUB_CREDENTIAL_REFERENCE_HMAC_KEY ?? null,
  };
}
