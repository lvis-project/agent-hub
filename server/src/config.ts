import { z } from "zod";

const defaultOrigins = ["http://127.0.0.1:5174", "http://localhost:5174"];

const settingsSchema = z.object({
  AGENT_HUB_DB_URL: z.string().min(1).default("sqlite://./agent-hub.db"),
  AGENT_HUB_HOST: z.string().min(1).default("127.0.0.1"),
  AGENT_HUB_PORT: z.coerce.number().int().min(1).max(65535).default(8000),
  AGENT_HUB_LOG_LEVEL: z.string().default("info"),
  AGENT_HUB_RATE_LIMIT_PER_IP_PER_MIN: z.coerce.number().int().min(1).default(300),
  AGENT_HUB_SIGNUP_RATE_LIMIT_PER_IP_PER_MIN: z.coerce.number().int().min(1).default(10),
  AGENT_HUB_TRUST_PROXY: z.string().default(""),
  AGENT_HUB_CORS_ORIGINS: z.string().optional(),
  AGENT_HUB_TLS_HSTS_MAX_AGE: z.coerce.number().int().min(0).default(63_072_000),
});

export type Settings = {
  databaseUrl: string;
  host: string;
  port: number;
  logLevel: string;
  rateLimitPerIpPerMinute: number;
  signupRateLimitPerIpPerMinute: number;
  trustedProxyIps: string[];
  corsOrigins: string[];
  tlsHstsMaxAge: number;
};

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
  return {
    databaseUrl: parsed.AGENT_HUB_DB_URL,
    host: parsed.AGENT_HUB_HOST,
    port: parsed.AGENT_HUB_PORT,
    logLevel: parsed.AGENT_HUB_LOG_LEVEL,
    rateLimitPerIpPerMinute: parsed.AGENT_HUB_RATE_LIMIT_PER_IP_PER_MIN,
    signupRateLimitPerIpPerMinute: parsed.AGENT_HUB_SIGNUP_RATE_LIMIT_PER_IP_PER_MIN,
    trustedProxyIps,
    corsOrigins,
    tlsHstsMaxAge: parsed.AGENT_HUB_TLS_HSTS_MAX_AGE,
  };
}
