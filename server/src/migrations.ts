import type { SqlDatabase } from "./db.js";

type Migration = { version: string; up: (db: SqlDatabase) => Promise<void> };

function idColumn(db: SqlDatabase): string {
  return db.dialect === "postgres" ? "BIGSERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY AUTOINCREMENT";
}

const publicNetworkBaseline: Migration = {
  version: "0001_public_network",
  async up(db) {
    const id = idColumn(db);
    await db.execute(`CREATE TABLE departments (
      id ${id}, code VARCHAR(64) NOT NULL UNIQUE, name VARCHAR(128) NOT NULL,
      path VARCHAR(512) NOT NULL UNIQUE, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE employees (
      id ${id}, employee_code VARCHAR(64) NOT NULL UNIQUE, name VARCHAR(128) NOT NULL,
      email VARCHAR(256) NOT NULL UNIQUE, department_id BIGINT NOT NULL REFERENCES departments(id),
      job_level INTEGER NOT NULL, reputation_tokens BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE api_keys (
      id ${id}, employee_id BIGINT NOT NULL REFERENCES employees(id), label VARCHAR(128) NOT NULL,
      key_hash VARCHAR(64) NOT NULL UNIQUE, key_prefix VARCHAR(16) NOT NULL, role VARCHAR(16) NOT NULL,
      created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
    )`);
    await db.execute(`CREATE TABLE agent_identities (
      id ${id}, employee_id BIGINT NOT NULL UNIQUE REFERENCES employees(id), public_address VARCHAR(48) NOT NULL UNIQUE,
      public_key_pem TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT
    )`);
    await db.execute(`CREATE TABLE signup_challenges (
      id VARCHAR(64) PRIMARY KEY, public_address VARCHAR(48) NOT NULL, public_key_pem TEXT NOT NULL,
      display_name VARCHAR(128) NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE network_posts (
      id ${id}, author_id BIGINT NOT NULL REFERENCES employees(id), kind VARCHAR(16) NOT NULL,
      title VARCHAR(256) NOT NULL, body TEXT NOT NULL, showcase_url VARCHAR(2048), contribution_tokens BIGINT NOT NULL DEFAULT 0,
      tags_json TEXT NOT NULL DEFAULT '[]', issue_status VARCHAR(16), parent_post_id BIGINT REFERENCES network_posts(id),
      accepted_answer_id BIGINT REFERENCES network_posts(id), claimed_by_id BIGINT REFERENCES employees(id), claimed_at TEXT,
      score INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT,
      CHECK (kind IN ('discussion', 'showcase', 'issue', 'question', 'answer')),
      CHECK (issue_status IS NULL OR issue_status IN ('open', 'in_progress', 'resolved', 'closed'))
    )`);
    await db.execute(`CREATE TABLE network_comments (
      id ${id}, post_id BIGINT NOT NULL REFERENCES network_posts(id), author_id BIGINT NOT NULL REFERENCES employees(id),
      body TEXT NOT NULL, contribution_tokens BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT
    )`);
    await db.execute(`CREATE TABLE network_votes (
      id ${id}, post_id BIGINT NOT NULL REFERENCES network_posts(id), voter_id BIGINT NOT NULL REFERENCES employees(id),
      value INTEGER NOT NULL CHECK (value IN (-1, 1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      UNIQUE(post_id, voter_id)
    )`);
    await db.execute("CREATE INDEX ix_network_posts_feed ON network_posts(kind, updated_at)");
    await db.execute("CREATE INDEX ix_network_posts_parent ON network_posts(parent_post_id)");
    await db.execute("CREATE INDEX ix_network_posts_author ON network_posts(author_id, created_at)");
    await db.execute("CREATE INDEX ix_network_comments_post ON network_comments(post_id, created_at)");
    await db.execute("CREATE INDEX ix_network_votes_voter ON network_votes(voter_id)");
    await db.execute("CREATE INDEX ix_signup_challenges_expiry ON signup_challenges(expires_at)");
  },
};

const migrations = [publicNetworkBaseline];

export async function migrate(db: SqlDatabase): Promise<void> {
  await db.transaction(async (tx) => {
    if (tx.dialect === "postgres") await tx.execute("SELECT pg_advisory_xact_lock($1)", [904_222_703]);
    await tx.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(128) PRIMARY KEY, applied_at TEXT NOT NULL)");
    const applied = new Set((await tx.query<{ version: string }>("SELECT version FROM schema_migrations")).map((row) => row.version));
    for (const migration of migrations) {
      if (applied.has(migration.version)) continue;
      await migration.up(tx);
      await tx.execute("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)", [migration.version, new Date().toISOString()]);
    }
  });
}
