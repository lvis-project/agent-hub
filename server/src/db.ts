import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { domainToASCII } from "node:url";
import { Pool, type PoolClient, type PoolConfig } from "pg";
import type { PostgresTlsConfig } from "./config.js";

export type SqlValue = string | number | Buffer | null;
export type SqlRow = Record<string, unknown>;

export interface SqlDatabase {
  readonly dialect: "sqlite" | "postgres";
  query<T extends SqlRow = SqlRow>(sql: string, params?: SqlValue[]): Promise<T[]>;
  execute(sql: string, params?: SqlValue[]): Promise<void>;
  transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

function sqliteStatement(sql: string, params: SqlValue[]): { statement: string; parameters: SqlValue[] } {
  const parameters: SqlValue[] = [];
  const statement = sql.replace(/\$(\d+)/g, (_match, index: string) => {
    const value = params[Number(index) - 1];
    if (value === undefined) throw new Error(`Missing SQL parameter $${index}`);
    parameters.push(value);
    return "?";
  });
  return { statement, parameters };
}

class SqliteSession implements SqlDatabase {
  readonly dialect = "sqlite" as const;
  constructor(private readonly connection: DatabaseSync) {
  }

  async query<T extends SqlRow = SqlRow>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    const compiled = sqliteStatement(sql, params);
    return this.connection.prepare(compiled.statement).all(...compiled.parameters) as T[];
  }

  async execute(sql: string, params: SqlValue[] = []): Promise<void> {
    const compiled = sqliteStatement(sql, params);
    this.connection.prepare(compiled.statement).run(...compiled.parameters);
  }

  async transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    return work(this);
  }

  async close(): Promise<void> {}
}

class SqliteDatabase implements SqlDatabase {
  readonly dialect = "sqlite" as const;
  private readonly session: SqliteSession;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly connection: DatabaseSync) {
    this.connection.exec("PRAGMA foreign_keys = ON");
    this.session = new SqliteSession(connection);
  }

  private enqueue<T>(work: () => Promise<T>): Promise<T> {
    const pending = this.queue.then(work, work);
    this.queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  query<T extends SqlRow = SqlRow>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    return this.enqueue(() => this.session.query<T>(sql, params));
  }

  execute(sql: string, params: SqlValue[] = []): Promise<void> {
    return this.enqueue(() => this.session.execute(sql, params));
  }

  transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    return this.enqueue(async () => {
      this.connection.exec("BEGIN IMMEDIATE");
      try {
        const result = await work(this.session);
        this.connection.exec("COMMIT");
        return result;
      } catch (error) {
        this.connection.exec("ROLLBACK");
        throw error;
      }
    });
  }

  close(): Promise<void> {
    return this.enqueue(async () => this.connection.close());
  }
}

class PostgresSession implements SqlDatabase {
  readonly dialect = "postgres" as const;
  constructor(private readonly client: PoolClient) {}

  async query<T extends SqlRow = SqlRow>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    return (await this.client.query<T>(sql, params)).rows;
  }

  async execute(sql: string, params: SqlValue[] = []): Promise<void> {
    await this.client.query(sql, params);
  }

  async transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    return work(this);
  }

  async close(): Promise<void> {}
}

class PostgresDatabase implements SqlDatabase {
  readonly dialect = "postgres" as const;
  constructor(private readonly pool: Pool) {}

  async query<T extends SqlRow = SqlRow>(sql: string, params: SqlValue[] = []): Promise<T[]> {
    return (await this.pool.query<T>(sql, params)).rows;
  }

  async execute(sql: string, params: SqlValue[] = []): Promise<void> {
    await this.pool.query(sql, params);
  }

  async transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await work(new PostgresSession(client));
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

function decodedUrlComponent(value: string, name: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error(`AGENT_HUB_DB_URL has an invalid percent-encoded ${name} when AGENT_HUB_POSTGRES_TLS_MODE=verify-full`);
  }
}

type VerifiedPostgresConnection = {
  host: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
};

function verifiedPostgresConnection(databaseUrl: string): VerifiedPostgresConnection {
  let parsed: URL;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error("AGENT_HUB_DB_URL must be a valid PostgreSQL URL when AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error("AGENT_HUB_POSTGRES_TLS_MODE=verify-full requires a PostgreSQL AGENT_HUB_DB_URL");
  }
  if (parsed.searchParams.size > 0) {
    throw new Error("AGENT_HUB_DB_URL must not include query parameters when AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
  }
  const asciiHostname = domainToASCII(decodedUrlComponent(parsed.hostname.replace(/^\[|\]$/g, ""), "hostname"));
  const hostname = asciiHostname.toLowerCase().endsWith(".") ? asciiHostname.slice(0, -1).toLowerCase() : asciiHostname.toLowerCase();
  const labels = hostname.split(".");
  const topLevelDomain = labels.at(-1) ?? "";
  const validDnsLabel = (label: string) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label);
  const validTopLevelDomain = /^[a-z]+$/u.test(topLevelDomain) || /^xn--[a-z0-9-]+$/u.test(topLevelDomain);
  if (
    !hostname || hostname.length > 253 || hostname === "localhost" || hostname.endsWith(".localhost") ||
    isIP(hostname) !== 0 || labels.length < 2 || labels.some((label) => !validDnsLabel(label)) || !validTopLevelDomain
  ) {
    throw new Error("AGENT_HUB_DB_URL must use a canonical non-localhost DNS FQDN when AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
  }
  const port = parsed.port === "" ? undefined : Number(parsed.port);
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65_535)) {
    throw new Error("AGENT_HUB_DB_URL must use a TCP port from 1 through 65535 when AGENT_HUB_POSTGRES_TLS_MODE=verify-full");
  }
  return {
    host: hostname,
    ...(port === undefined ? {} : { port }),
    ...(parsed.username === "" ? {} : { user: decodedUrlComponent(parsed.username, "username") }),
    ...(parsed.password === "" ? {} : { password: decodedUrlComponent(parsed.password, "password") }),
    ...(parsed.pathname === "/" || parsed.pathname === "" ? {} : { database: decodedUrlComponent(parsed.pathname.slice(1), "database") }),
  };
}

export function createPostgresPoolConfig(databaseUrl: string, postgresTls: PostgresTlsConfig): PoolConfig {
  if (postgresTls.mode === "disabled") return { connectionString: databaseUrl };

  const connection = verifiedPostgresConnection(databaseUrl);
  let ca: Buffer;
  try {
    ca = readFileSync(postgresTls.caFile);
  } catch {
    throw new Error("Unable to read AGENT_HUB_POSTGRES_TLS_CA_FILE");
  }
  if (ca.length === 0) throw new Error("AGENT_HUB_POSTGRES_TLS_CA_FILE must not be empty");
  return {
    ...connection,
    ssl: {
      ca,
      rejectUnauthorized: true,
      servername: connection.host,
    },
  };
}

export function createDatabase(databaseUrl: string, postgresTls?: PostgresTlsConfig): SqlDatabase {
  if (databaseUrl.startsWith("sqlite://")) {
    if (postgresTls?.mode === "verify-full") {
      throw new Error("AGENT_HUB_POSTGRES_TLS_MODE=verify-full requires a PostgreSQL AGENT_HUB_DB_URL");
    }
    const filename = databaseUrl.slice("sqlite://".length) || ":memory:";
    return new SqliteDatabase(new DatabaseSync(filename, { readBigInts: true, timeout: 5_000 }));
  }
  if (postgresTls === undefined) {
    throw new Error("PostgreSQL database creation requires an explicit postgresTls configuration");
  }
  return new PostgresDatabase(new Pool(createPostgresPoolConfig(databaseUrl, postgresTls)));
}

export function asNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") return Number(value);
  if (typeof value === "bigint") {
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) throw new Error("Database integer exceeds JavaScript safe-number range");
    return parsed;
  }
  throw new Error(`Expected a numeric database value, received ${typeof value}`);
}

export function asString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  throw new Error(`Expected a string database value, received ${typeof value}`);
}

export function asBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw new Error(`Expected a binary database value, received ${typeof value}`);
}
