import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { loadSettings } from "../src/config.js";
import { createDatabase, createPostgresPoolConfig } from "../src/db.js";

const localComposeUrl = "postgresql://agent_hub:local-password@postgres:5432/agent_hub";
const verifiedDnsUrl = "postgresql://operator:password@db.example.test:5432/agent_hub";

function verifyFullEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    AGENT_HUB_DB_URL: verifiedDnsUrl,
    AGENT_HUB_POSTGRES_TLS_MODE: "verify-full",
    AGENT_HUB_POSTGRES_TLS_CA_FILE: "/not-configured/postgres-root-ca.pem",
    ...overrides,
  };
}

async function withCaFile(work: (caFile: string) => void | Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "agent-hub-postgres-tls-"));
  const caFile = join(directory, "root-ca.pem");
  await writeFile(caFile, "test-ca-pem\n", "utf8");
  try {
    await work(caFile);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("PostgreSQL verify-full TLS contract", () => {
  it("keeps the ordinary local Compose DSN explicitly TLS-disabled and does not read a CA", () => {
    const settings = loadSettings({ AGENT_HUB_DB_URL: localComposeUrl });

    expect(settings.postgresTls).toEqual({ mode: "disabled", caFile: null });
    expect(createPostgresPoolConfig(settings.databaseUrl, settings.postgresTls)).toEqual({ connectionString: localComposeUrl });
  });

  it("requires verify-full mode to name PostgreSQL and an explicit CA file", () => {
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: "sqlite://:memory:",
      AGENT_HUB_POSTGRES_TLS_MODE: "verify-full",
      AGENT_HUB_POSTGRES_TLS_CA_FILE: "/not-used.pem",
    })).toThrow(/requires a PostgreSQL/);
    expect(() => loadSettings(verifyFullEnv({ AGENT_HUB_POSTGRES_TLS_CA_FILE: undefined })))
      .toThrow(/CA_FILE is required/);
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: localComposeUrl,
      AGENT_HUB_POSTGRES_TLS_CA_FILE: "/not-used.pem",
    })).toThrow(/CA_FILE requires .*verify-full/);
  });

  it("uses only the validated user-supplied URL hostname with a pinned CA and certificate verification", async () => {
    await withCaFile((caFile) => {
      const settings = loadSettings(verifyFullEnv({ AGENT_HUB_POSTGRES_TLS_CA_FILE: caFile }));
      const config = createPostgresPoolConfig(settings.databaseUrl, settings.postgresTls);
      if (typeof config.ssl !== "object" || config.ssl === null) throw new Error("expected TLS socket options");

      expect(config.ssl.ca).toEqual(Buffer.from("test-ca-pem\n"));
      expect(config.ssl.rejectUnauthorized).toBe(true);
      expect(config.ssl.servername).toBe("db.example.test");
    });
  });

  it.each(["localhost", "LOCALHOST.", "127.0.0.1", "[::1]"])("rejects %s as a verify-full database host", (host) => {
    const databaseUrl = `postgresql://operator:password@${host}:5432/agent_hub`;
    expect(() => createPostgresPoolConfig(databaseUrl, { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(/non-localhost DNS hostname/);
  });

  it.each([
    "ssl", "sslmode", "sslrootcert", "sslcert", "sslkey", "sslnegotiation", "uselibpqcompat",
    "SSLMode", "SSLNEGOTIATION", "UseLibpqCompat",
  ]) ("rejects the %s query key before node-postgres can replace direct TLS settings", (key) => {
    expect(() => createPostgresPoolConfig(`${verifiedDnsUrl}?${key}=value`, { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(new RegExp(key, "i"));
  });

  it("fails closed when the configured CA cannot be read or is empty", async () => {
    expect(() => createPostgresPoolConfig(verifiedDnsUrl, { mode: "verify-full", caFile: "/not-present/postgres-root-ca.pem" }))
      .toThrow(/Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE/);
    await withCaFile(async (caFile) => {
      await writeFile(caFile, "", "utf8");
      expect(() => createPostgresPoolConfig(verifiedDnsUrl, { mode: "verify-full", caFile }))
        .toThrow(/must not be empty/);
    });
  });

  it("does not reveal a URL password, CA path, or CA bytes in a TLS configuration error", () => {
    const password = "never-disclose-database-password";
    const caPath = "/private/operator-ca.pem";
    let message = "";
    try {
      createPostgresPoolConfig(
        `postgresql://operator:${password}@db.example.test:5432/agent_hub?sslmode=require`,
        { mode: "verify-full", caFile: caPath },
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("sslmode");
    expect(message).not.toContain(password);
    expect(message).not.toContain(caPath);
    expect(message).not.toContain("test-ca-pem");

    try {
      createPostgresPoolConfig(
        `postgresql://operator:${password}@db.example.test:5432/agent_hub`,
        { mode: "verify-full", caFile: caPath },
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE");
    expect(message).not.toContain(password);
    expect(message).not.toContain(caPath);
    expect(message).not.toContain("test-ca-pem");
  });

  it("rejects verify-full before a SQLite database can be opened", () => {
    expect(() => createDatabase("sqlite://:memory:", { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(/requires a PostgreSQL/);
  });

  it("routes app, migration, and parity cleanup through the same configured TLS contract", async () => {
    const [app, migrate, parityScript, packageJson, dockerignore] = await Promise.all([
      readFile(new URL("../src/app.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/cli/migrate.ts", import.meta.url), "utf8"),
      readFile(new URL("../scripts/a2a-p4-5-db-parity.mjs", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../.dockerignore", import.meta.url), "utf8"),
    ]);
    expect(app).toContain("createDatabase(settings.databaseUrl, settings.postgresTls)");
    expect(migrate).toContain("createDatabase(settings.databaseUrl, settings.postgresTls)");
    expect(parityScript).toContain("createPostgresPoolConfig(postgresUrl, postgresTls)");
    expect(parityScript).toContain("AGENT_HUB_TEST_POSTGRES_TLS_MODE");
    expect(packageJson).toContain("node --import tsx scripts/a2a-p4-5-db-parity.mjs postgres");
    expect(dockerignore).toContain("**/*.pem");
    expect(dockerignore).toContain("**/secrets/");
  });
});
