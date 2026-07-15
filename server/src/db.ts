import { DatabaseSync } from "node:sqlite";
import { Pool, type PoolClient } from "pg";

export type SqlValue = string | number | null;
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

export function createDatabase(databaseUrl: string): SqlDatabase {
  if (databaseUrl.startsWith("sqlite://")) {
    const filename = databaseUrl.slice("sqlite://".length) || ":memory:";
    return new SqliteDatabase(new DatabaseSync(filename, { readBigInts: true, timeout: 5_000 }));
  }
  return new PostgresDatabase(new Pool({ connectionString: databaseUrl }));
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
