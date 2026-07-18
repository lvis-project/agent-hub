import type { PostgresTlsConfig } from "../config.js";

const modeName = "AGENT_HUB_P4_5_POSTGRES_TLS_MODE";
const caFileName = "AGENT_HUB_P4_5_POSTGRES_TLS_CA_FILE";

/**
 * Serializes the launcher-selected PostgreSQL TLS contract for the isolated
 * P4-5 Vitest child process. The child must parse this value before it opens a
 * PostgreSQL database; there is intentionally no implicit plaintext fallback.
 */
export function p4ParityPostgresTlsEnvironment(config: PostgresTlsConfig): NodeJS.ProcessEnv {
  return config.mode === "verify-full"
    ? { [modeName]: config.mode, [caFileName]: config.caFile }
    : { [modeName]: config.mode };
}

export function p4ParityPostgresTlsFromEnvironment(env: NodeJS.ProcessEnv = process.env): PostgresTlsConfig {
  const mode = env[modeName];
  const caFile = env[caFileName];
  if (mode === "disabled") {
    if (caFile !== undefined) throw new Error(`${caFileName} requires ${modeName}=verify-full`);
    return { mode, caFile: null };
  }
  if (mode === "verify-full") {
    if (!caFile?.trim()) throw new Error(`${caFileName} is required when ${modeName}=verify-full`);
    return { mode, caFile };
  }
  throw new Error(`${modeName} must be disabled or verify-full for a PostgreSQL parity database`);
}
