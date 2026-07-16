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

const agentCardRegistry: Migration = {
  version: "0002_agent_card_registry",
  async up(db) {
    const id = idColumn(db);
    await db.execute(`CREATE TABLE a2a_trust_anchors (
      id ${id}, key_id VARCHAR(128) NOT NULL UNIQUE, algorithm VARCHAR(8) NOT NULL,
      public_key_pem TEXT NOT NULL, key_fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
      state VARCHAR(16) NOT NULL DEFAULT 'active', row_version BIGINT NOT NULL DEFAULT 1,
      created_by BIGINT NOT NULL REFERENCES employees(id), created_at TEXT NOT NULL,
      revoked_by BIGINT REFERENCES employees(id), revoked_at TEXT, revoke_reason VARCHAR(1024),
      CHECK (algorithm IN ('ES256', 'EdDSA')),
      CHECK (state IN ('active', 'revoked')),
      CHECK (row_version >= 1),
      CHECK ((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
        OR (state = 'revoked' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_card_documents (
      id ${id}, document_sha256 VARCHAR(64) NOT NULL UNIQUE, payload_sha256 VARCHAR(64) NOT NULL,
      document_json TEXT NOT NULL, payload_json TEXT NOT NULL,
      name VARCHAR(128) NOT NULL, card_version VARCHAR(64) NOT NULL,
      preferred_interface_uri VARCHAR(2048) NOT NULL, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE a2a_card_registry (
      id ${id}, document_id BIGINT NOT NULL UNIQUE REFERENCES a2a_card_documents(id),
      preferred_interface_uri VARCHAR(2048) NOT NULL,
      state VARCHAR(16) NOT NULL DEFAULT 'discovered', trusted_anchor_id BIGINT REFERENCES a2a_trust_anchors(id),
      verified_key_id VARCHAR(128), row_version BIGINT NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      reviewed_by BIGINT REFERENCES employees(id), decision_reason VARCHAR(1024),
      CHECK (state IN ('discovered', 'trusted', 'rejected', 'revoked')),
      CHECK (row_version >= 1),
      CHECK ((state = 'discovered' AND trusted_anchor_id IS NULL AND verified_key_id IS NULL
          AND reviewed_by IS NULL AND decision_reason IS NULL)
        OR (state = 'trusted' AND trusted_anchor_id IS NOT NULL AND verified_key_id IS NOT NULL
          AND reviewed_by IS NOT NULL AND decision_reason IS NOT NULL)
        OR (state = 'rejected' AND trusted_anchor_id IS NULL AND verified_key_id IS NULL
          AND reviewed_by IS NOT NULL AND decision_reason IS NOT NULL)
        OR (state = 'revoked' AND trusted_anchor_id IS NOT NULL AND verified_key_id IS NOT NULL
          AND reviewed_by IS NOT NULL AND decision_reason IS NOT NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_card_observations (
      id ${id}, registry_id BIGINT NOT NULL REFERENCES a2a_card_registry(id),
      actor_id BIGINT NOT NULL REFERENCES employees(id), submission_id VARCHAR(128) NOT NULL,
      provenance_kind VARCHAR(32) NOT NULL, provenance_source VARCHAR(256) NOT NULL,
      provenance_detail VARCHAR(1024), observed_at TEXT NOT NULL,
      UNIQUE(actor_id, submission_id),
      CHECK (provenance_kind IN ('manual', 'api', 'migration', 'admin-review'))
    )`);
    await db.execute(`CREATE TABLE a2a_card_verifications (
      id ${id}, observation_id BIGINT NOT NULL UNIQUE REFERENCES a2a_card_observations(id),
      document_id BIGINT NOT NULL REFERENCES a2a_card_documents(id),
      trust_anchor_id BIGINT REFERENCES a2a_trust_anchors(id),
      admission_trust_state VARCHAR(16) NOT NULL, verified_key_id VARCHAR(128),
      document_sha256 VARCHAR(64) NOT NULL, payload_sha256 VARCHAR(64) NOT NULL,
      trust_anchor_snapshot_json TEXT NOT NULL, verified_at TEXT NOT NULL,
      CHECK (admission_trust_state IN ('discovered', 'trusted')),
      CHECK ((admission_trust_state = 'discovered' AND trust_anchor_id IS NULL AND verified_key_id IS NULL)
        OR (admission_trust_state = 'trusted' AND trust_anchor_id IS NOT NULL AND verified_key_id IS NOT NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_registry_audit (
      id ${id}, actor_id BIGINT NOT NULL REFERENCES employees(id), action VARCHAR(64) NOT NULL,
      target_kind VARCHAR(32) NOT NULL, target_id VARCHAR(128) NOT NULL,
      before_state VARCHAR(32), after_state VARCHAR(32), reason VARCHAR(1024),
      metadata_json TEXT NOT NULL, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE a2a_mutation_submissions (
      actor_id BIGINT NOT NULL REFERENCES employees(id), submission_id VARCHAR(128) NOT NULL,
      operation VARCHAR(64) NOT NULL, request_sha256 VARCHAR(64) NOT NULL,
      response_json TEXT, response_status INTEGER, created_at TEXT NOT NULL,
      PRIMARY KEY(actor_id, submission_id),
      CHECK ((response_json IS NULL AND response_status IS NULL)
        OR (response_json IS NOT NULL AND response_status IS NOT NULL))
    )`);
    await db.execute("CREATE INDEX ix_a2a_documents_payload ON a2a_card_documents(payload_sha256)");
    await db.execute("CREATE INDEX ix_a2a_registry_state ON a2a_card_registry(state, updated_at)");
    await db.execute("CREATE UNIQUE INDEX ux_a2a_trusted_interface ON a2a_card_registry(preferred_interface_uri) WHERE state = 'trusted'");
    await db.execute("CREATE INDEX ix_a2a_observations_registry ON a2a_card_observations(registry_id, observed_at)");
    await db.execute("CREATE INDEX ix_a2a_verifications_document ON a2a_card_verifications(document_id, verified_at)");
    await db.execute("CREATE INDEX ix_a2a_audit_created ON a2a_registry_audit(created_at, id)");

    const appendOnlyTables = ["a2a_card_documents", "a2a_card_observations", "a2a_card_verifications", "a2a_registry_audit"];
    if (db.dialect === "postgres") {
      await db.execute(`CREATE FUNCTION reject_a2a_append_only_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'a2a append-only record'; END $$`);
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_append_only BEFORE UPDATE OR DELETE ON ${table}
          FOR EACH ROW EXECUTE FUNCTION reject_a2a_append_only_mutation()`);
      }
    } else {
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a append-only record'); END`);
        await db.execute(`CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a append-only record'); END`);
      }
    }
  },
};

const migrations = [publicNetworkBaseline, agentCardRegistry];

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
