import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { p4ParityPostgresTlsEnvironment, p4ParityPostgresTlsFromEnvironment } from "../src/a2a/p4-parity-postgres-tls.js";
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
    const settings = loadSettings({
      AGENT_HUB_DB_URL: localComposeUrl,
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
      AGENT_HUB_POSTGRES_LOCAL_COMPOSE: "1",
    });

    expect(settings.postgresTls).toEqual({ mode: "disabled", caFile: null });
    expect(createPostgresPoolConfig(settings.databaseUrl, settings.postgresTls)).toEqual({ connectionString: localComposeUrl });
  });

  it("rejects disabled-mode local Compose URL query overrides", () => {
    const compatibleUrl = `${localComposeUrl}?application_name=local-development`;
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: compatibleUrl,
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
      AGENT_HUB_POSTGRES_LOCAL_COMPOSE: "1",
    })).toThrow(/permitted only by deploy\/docker-compose\.local-postgres\.yml/);
  });

  it("rejects a Compose-shaped PostgreSQL URL unless the local source-owned deployment marker is present", () => {
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: localComposeUrl,
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
    })).toThrow(/permitted only by deploy\/docker-compose\.local-postgres\.yml/);
  });

  it("rejects the local Compose marker when a PostgreSQL URL points anywhere else", () => {
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: verifiedDnsUrl,
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
      AGENT_HUB_POSTGRES_LOCAL_COMPOSE: "1",
    })).toThrow(/supported remote deployments require verify-full/);
  });

  it("requires PostgreSQL to declare its TLS mode instead of silently disabling verification", () => {
    expect(() => loadSettings({ AGENT_HUB_DB_URL: localComposeUrl }))
      .toThrow(/POSTGRES_TLS_MODE must be explicitly set/);
  });

  it("requires remote PostgreSQL to use verify-full instead of disabled mode", () => {
    expect(() => loadSettings({
      AGENT_HUB_DB_URL: verifiedDnsUrl,
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
    })).toThrow(/supported remote deployments require verify-full/);
  });

  it("keeps SQLite independent of the PostgreSQL TLS mode requirement", () => {
    expect(loadSettings({ AGENT_HUB_DB_URL: "sqlite://:memory:" }).postgresTls)
      .toEqual({ mode: "disabled", caFile: null });
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
      AGENT_HUB_POSTGRES_TLS_MODE: "disabled",
      AGENT_HUB_POSTGRES_LOCAL_COMPOSE: "1",
      AGENT_HUB_POSTGRES_TLS_CA_FILE: "/not-used.pem",
    })).toThrow(/CA_FILE requires .*verify-full/);
  });

  it.each(["", " \t "])("rejects a blank application verify-full CA path", (caFile) => {
    expect(() => loadSettings(verifyFullEnv({ AGENT_HUB_POSTGRES_TLS_CA_FILE: caFile })))
      .toThrow(/AGENT_HUB_POSTGRES_TLS_CA_FILE must not be blank/);
  });

  it("normalizes a padded application verify-full CA path", () => {
    const caFile = " /operator/postgres-root-ca.pem ";

    expect(loadSettings(verifyFullEnv({ AGENT_HUB_POSTGRES_TLS_CA_FILE: caFile })).postgresTls)
      .toEqual({ mode: "verify-full", caFile: "/operator/postgres-root-ca.pem" });
  });

  it("requires the P4-5 PostgreSQL parity launcher to declare its TLS mode", () => {
    const result = spawnSync(
      process.execPath,
      ["--import", "tsx", "scripts/a2a-p4-5-db-parity.mjs", "postgres"],
      {
        cwd: fileURLToPath(new URL("../", import.meta.url)),
        encoding: "utf8",
        env: {
          ...process.env,
          AGENT_HUB_TEST_POSTGRES_URL: verifiedDnsUrl,
          AGENT_HUB_TEST_POSTGRES_TLS_MODE: "",
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain("AGENT_HUB_TEST_POSTGRES_TLS_MODE must be explicitly set");
  });

  it.each(["", " \t "])("rejects a blank P4-5 PostgreSQL parity CA path before opening a database", (caFile) => {
    const result = spawnSync(
      process.execPath,
      ["--import", "tsx", "scripts/a2a-p4-5-db-parity.mjs", "postgres"],
      {
        cwd: fileURLToPath(new URL("../", import.meta.url)),
        encoding: "utf8",
        env: {
          ...process.env,
          AGENT_HUB_TEST_POSTGRES_URL: verifiedDnsUrl,
          AGENT_HUB_TEST_POSTGRES_TLS_MODE: "verify-full",
          AGENT_HUB_TEST_POSTGRES_TLS_CA_FILE: caFile,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}\n${result.stderr}`).toContain("AGENT_HUB_TEST_POSTGRES_TLS_CA_FILE is required");
  });

  it("uses only the validated user-supplied URL hostname with a pinned CA and certificate verification", async () => {
    await withCaFile((caFile) => {
      const settings = loadSettings(verifyFullEnv({ AGENT_HUB_POSTGRES_TLS_CA_FILE: caFile }));
      const config = createPostgresPoolConfig(settings.databaseUrl, settings.postgresTls);
      if (typeof config.ssl !== "object" || config.ssl === null) throw new Error("expected TLS socket options");

      expect(config.ssl.ca).toEqual(Buffer.from("test-ca-pem\n"));
      expect(config.ssl.rejectUnauthorized).toBe(true);
      expect(config.ssl.servername).toBe("db.example.test");
      expect(config).toMatchObject({ host: "db.example.test", port: 5432, user: "operator", password: "password", database: "agent_hub" });
      expect(config).not.toHaveProperty("connectionString");
    });
  });

  it("decodes percent-escaped PostgreSQL credentials exactly once for direct PoolConfig fields", async () => {
    await withCaFile((caFile) => {
      const config = createPostgresPoolConfig(
        "postgresql://user%25name:pass%25word@db.example.test:5432/agent_hub",
        { mode: "verify-full", caFile },
      );

      expect(config).toMatchObject({ user: "user%name", password: "pass%word" });
    });
  });

  it.each([
    ["username", "postgresql://operator%:password@db.example.test:5432/agent_hub", "operator%"],
    ["password", "postgresql://operator:password%@db.example.test:5432/agent_hub", "password%"],
  ] as const)("rejects malformed percent encoding in PostgreSQL %s before CA I/O", (name, databaseUrl, secret) => {
    let message = "";
    try {
      createPostgresPoolConfig(databaseUrl, { mode: "verify-full", caFile: "/not-read.pem" });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain(`invalid percent-encoded PostgreSQL ${name}`);
    expect(message).not.toContain(secret);
    expect(message).not.toContain("Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE");
  });

  it("normalizes a single trailing DNS root dot and IDNA hostname for both endpoint and SNI", async () => {
    await withCaFile((caFile) => {
      const trailingDot = createPostgresPoolConfig(
        "postgresql://operator:password@Db.Example.Test.:5432/agent_hub",
        { mode: "verify-full", caFile },
      );
      const idna = createPostgresPoolConfig(
        "postgresql://operator:password@bücher.example:5432/agent_hub",
        { mode: "verify-full", caFile },
      );
      if (typeof trailingDot.ssl !== "object" || trailingDot.ssl === null) throw new Error("expected TLS socket options");
      if (typeof idna.ssl !== "object" || idna.ssl === null) throw new Error("expected TLS socket options");

      expect(trailingDot.host).toBe("db.example.test");
      expect(trailingDot.ssl.servername).toBe("db.example.test");
      expect(idna.host).toBe("xn--bcher-kva.example");
      expect(idna.ssl.servername).toBe("xn--bcher-kva.example");
    });
  });

  it("pins omitted and empty authority ports to 5432 instead of ambient PGPORT", async () => {
    const previousPgPort = process.env.PGPORT;
    process.env.PGPORT = "65432";
    try {
      await withCaFile((caFile) => {
        for (const databaseUrl of [
          "postgresql://operator:password@db.example.test/agent_hub",
          "postgresql://operator:password@db.example.test:/agent_hub",
        ]) {
          expect(createPostgresPoolConfig(databaseUrl, { mode: "verify-full", caFile })).toMatchObject({
            host: "db.example.test",
            port: 5432,
          });
        }
      });
    } finally {
      if (previousPgPort === undefined) delete process.env.PGPORT;
      else process.env.PGPORT = previousPgPort;
    }
  });

  it.each([
    ["1", 1],
    ["65535", 65535],
  ])("preserves an explicit valid TCP port %s", async (port, expectedPort) => {
    await withCaFile((caFile) => {
      expect(createPostgresPoolConfig(
        `postgresql://operator:password@db.example.test:${port}/agent_hub`,
        { mode: "verify-full", caFile },
      )).toMatchObject({ port: expectedPort });
    });
  });

  it.each([
    ["0", /TCP port from 1 through 65535/],
    ["65536", /must be a valid PostgreSQL URL/],
  ])("rejects invalid TCP port %s before it can construct a verify-full pool", (port, expectedError) => {
    let message = "";
    try {
      createPostgresPoolConfig(
        `postgresql://operator:password@db.example.test:${port}/agent_hub`,
        { mode: "verify-full", caFile: "/not-read.pem" },
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(expectedError);
    expect(message).not.toContain("Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE");
  });

  it.each([
    "localhost", "LOCALHOST.", "foo.localhost", "127.0.0.1", "127.0.0.1.", "127.1", "2130706433", "0x7f000001", "[::1]", "db.example.123",
  ])("rejects %s as a verify-full database host", (host) => {
    const databaseUrl = `postgresql://operator:password@${host}:5432/agent_hub`;
    expect(() => createPostgresPoolConfig(databaseUrl, { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(/canonical non-localhost DNS FQDN/);
  });

  it.each([
    "ssl", "sslmode", "sslrootcert", "sslcert", "sslkey", "sslnegotiation", "uselibpqcompat",
    "SSLMode", "SSLNEGOTIATION", "UseLibpqCompat", "application_name",
  ]) ("rejects the %s query key before node-postgres can parse connection options", (key) => {
    expect(() => createPostgresPoolConfig(`${verifiedDnsUrl}?${key}=value`, { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(/must not include query parameters/);
  });

  it.each(["host", "port", "user", "password", "database", "dbname", "HOST"])("rejects the %s query key before it can override the verified endpoint or identity", (key) => {
    expect(() => createPostgresPoolConfig(`${verifiedDnsUrl}?${key}=override`, { mode: "verify-full", caFile: "/not-read.pem" }))
      .toThrow(/must not include query parameters/);
  });

  it("rejects a host override before CA I/O so the verified authority and connection endpoint cannot diverge", () => {
    let message = "";
    try {
      createPostgresPoolConfig(
        `${verifiedDnsUrl}?host=evil.example.test`,
        { mode: "verify-full", caFile: "/not-read.pem" },
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toMatch(/must not include query parameters/);
    expect(message).not.toContain("Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE");
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
    expect(message).toContain("must not include query parameters");
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

  it("requires an explicit PostgreSQL TLS configuration instead of silently defaulting to plaintext", () => {
    expect(() => createDatabase(verifiedDnsUrl))
      .toThrow(/requires an explicit postgresTls configuration/);
  });

  it("round-trips the requested verify-full contract from the P4 parity launcher into its child process", () => {
    const requested = { mode: "verify-full" as const, caFile: "/operator/root-ca.pem" };
    const childEnvironment = p4ParityPostgresTlsEnvironment(requested);

    expect(p4ParityPostgresTlsFromEnvironment(childEnvironment)).toEqual(requested);
    expect(p4ParityPostgresTlsFromEnvironment({
      AGENT_HUB_P4_5_POSTGRES_TLS_MODE: "verify-full",
      AGENT_HUB_P4_5_POSTGRES_TLS_CA_FILE: " /operator/root-ca.pem ",
    })).toEqual({ mode: "verify-full", caFile: "/operator/root-ca.pem" });
    expect(() => p4ParityPostgresTlsFromEnvironment({ AGENT_HUB_P4_5_POSTGRES_TLS_MODE: "verify-full" }))
      .toThrow(/CA_FILE is required/);
    expect(() => p4ParityPostgresTlsFromEnvironment({
      AGENT_HUB_P4_5_POSTGRES_TLS_MODE: "verify-full",
      AGENT_HUB_P4_5_POSTGRES_TLS_CA_FILE: " \t ",
    })).toThrow(/CA_FILE is required/);
  });

  it("routes app, migration, provisioning, and the P4 parity child path through the same configured TLS contract", async () => {
    const [app, migrate, provision, parityScript, routeControl, packageJson, dockerignore] = await Promise.all([
      readFile(new URL("../src/app.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/cli/migrate.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/cli/provision.ts", import.meta.url), "utf8"),
      readFile(new URL("../scripts/a2a-p4-5-db-parity.mjs", import.meta.url), "utf8"),
      readFile(new URL("route-control.e2e.test.ts", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../.dockerignore", import.meta.url), "utf8"),
    ]);
    expect(app).toContain("createDatabase(settings.databaseUrl, settings.postgresTls)");
    expect(migrate).toContain("createDatabase(settings.databaseUrl, settings.postgresTls)");
    expect(provision).toContain("createDatabase(settings.databaseUrl, settings.postgresTls)");
    expect(parityScript).toContain("createPostgresPoolConfig(postgresUrl, postgresTls)");
    expect(parityScript).toContain("p4ParityPostgresTlsEnvironment(postgresTls)");
    expect(parityScript).toContain("const normalizedCaFile = caFile?.trim();");
    expect(parityScript).toContain('return { mode: "verify-full", caFile: normalizedCaFile };');
    expect(routeControl).toContain("p4ParityPostgresTlsFromEnvironment()");
    expect(routeControl).toContain("createDatabase(parityDatabaseUrl, parityPostgresTls)");
    expect(routeControl).toContain("createDatabase(secondaryParityDatabaseUrl, parityPostgresTls)");
    expect(routeControl).not.toContain("createDatabase(secondaryParityDatabaseUrl);");
    expect(parityScript).toContain("AGENT_HUB_TEST_POSTGRES_TLS_MODE");
    expect(packageJson).toContain("node --import tsx scripts/a2a-p4-5-db-parity.mjs postgres");
    expect(dockerignore).toContain("**/*.pem");
    expect(dockerignore).toContain("**/secrets/");
  });
});
