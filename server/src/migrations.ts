import type { SqlDatabase } from "./db.js";
import { EXACT_SEND_REPLAY_EXTENSION_URI } from "./a2a/agent-card-registry.js";

type Migration = { version: string; up: (db: SqlDatabase) => Promise<void> };

function idColumn(db: SqlDatabase): string {
  return db.dialect === "postgres" ? "BIGSERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY AUTOINCREMENT";
}

function binaryColumn(db: SqlDatabase): string {
  return db.dialect === "postgres" ? "BYTEA" : "BLOB";
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

const agentDiscoveryConnectivity: Migration = {
  version: "0003_a2a_discovery_connectivity",
  async up(db) {
    const id = idColumn(db);
    const binary = binaryColumn(db);
    await db.execute(`CREATE TABLE a2a_principals (
      id ${id}, kind VARCHAR(16) NOT NULL, employee_id BIGINT UNIQUE REFERENCES employees(id),
      system_name VARCHAR(64) UNIQUE, created_at TEXT NOT NULL,
      CHECK (kind IN ('employee', 'system')),
      CHECK ((kind = 'employee' AND employee_id IS NOT NULL AND system_name IS NULL)
        OR (kind = 'system' AND employee_id IS NULL AND system_name IS NOT NULL))
    )`);
    await db.execute(`INSERT INTO a2a_principals (kind, employee_id, system_name, created_at)
      VALUES ('system', NULL, 'g003-discovery', $1)`, [new Date().toISOString()]);
    await db.execute(`CREATE TABLE a2a_discovery_targets (
      id ${id}, canonical_origin VARCHAR(2048) NOT NULL UNIQUE,
      canonical_domain VARCHAR(253) NOT NULL UNIQUE, card_url VARCHAR(2048) NOT NULL UNIQUE,
      state VARCHAR(16) NOT NULL DEFAULT 'active', row_version BIGINT NOT NULL DEFAULT 1,
      next_fence_sequence BIGINT NOT NULL DEFAULT 0,
      created_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      created_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id), created_at TEXT NOT NULL,
      disabled_by_employee_id BIGINT REFERENCES employees(id),
      disabled_by_principal_id BIGINT REFERENCES a2a_principals(id), disabled_at TEXT, disable_reason VARCHAR(1024),
      CHECK (state IN ('active', 'disabled')), CHECK (row_version >= 1),
      CHECK (next_fence_sequence >= 0),
      CHECK ((state = 'active' AND disabled_by_employee_id IS NULL AND disabled_by_principal_id IS NULL
          AND disabled_at IS NULL AND disable_reason IS NULL)
        OR (state = 'disabled' AND disabled_by_employee_id IS NOT NULL AND disabled_by_principal_id IS NOT NULL
          AND disabled_at IS NOT NULL AND disable_reason IS NOT NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_admin_operations (
      id ${id}, requested_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      executed_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id),
      target_id BIGINT REFERENCES a2a_discovery_targets(id), submission_id VARCHAR(128) NOT NULL,
      operation_kind VARCHAR(64) NOT NULL, semantic_request_hash VARCHAR(64) NOT NULL,
      state VARCHAR(16) NOT NULL, response_status INTEGER, response_json TEXT,
      lease_token VARCHAR(128), fence_sequence BIGINT, lease_expires_at TEXT,
      started_at TEXT NOT NULL, completed_at TEXT,
      UNIQUE(requested_by_employee_id, submission_id),
      CHECK (state IN ('claiming', 'running', 'succeeded', 'failed')),
      CHECK ((state IN ('claiming', 'running') AND response_status IS NULL AND response_json IS NULL AND completed_at IS NULL)
        OR (state IN ('succeeded', 'failed') AND response_status IS NOT NULL AND response_json IS NOT NULL AND completed_at IS NOT NULL)),
      CHECK ((operation_kind = 'discovery.revalidate' AND state = 'claiming' AND target_id IS NULL
          AND lease_token IS NULL AND fence_sequence IS NULL AND lease_expires_at IS NULL)
        OR (operation_kind = 'discovery.revalidate' AND state IN ('running', 'succeeded') AND target_id IS NOT NULL
          AND lease_token IS NOT NULL AND fence_sequence IS NOT NULL AND fence_sequence > 0 AND lease_expires_at IS NOT NULL)
        OR (operation_kind = 'discovery.revalidate' AND state = 'failed' AND (
          (target_id IS NULL AND lease_token IS NULL AND fence_sequence IS NULL AND lease_expires_at IS NULL)
          OR (target_id IS NOT NULL AND lease_token IS NOT NULL AND fence_sequence IS NOT NULL
            AND fence_sequence > 0 AND lease_expires_at IS NOT NULL)))
        OR (operation_kind <> 'discovery.revalidate' AND lease_token IS NULL AND fence_sequence IS NULL AND lease_expires_at IS NULL)),
      FOREIGN KEY (requested_by_employee_id, submission_id)
        REFERENCES a2a_mutation_submissions(actor_id, submission_id)
    )`);
    await db.execute(`CREATE TABLE a2a_discovery_documents (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      operation_id BIGINT NOT NULL REFERENCES a2a_admin_operations(id), kind VARCHAR(16) NOT NULL,
      source_url VARCHAR(2048) NOT NULL, body_sha256 VARCHAR(64) NOT NULL, body_blob ${binary} NOT NULL,
      created_at TEXT NOT NULL, CHECK (kind IN ('agent-card', 'jwks')),
      UNIQUE(operation_id, kind)
    )`);
    await db.execute(`CREATE TABLE a2a_discovery_cache_entries (
      target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id), kind VARCHAR(16) NOT NULL,
      document_id BIGINT NOT NULL REFERENCES a2a_discovery_documents(id),
      etag VARCHAR(1024), last_modified VARCHAR(256), cache_expires_at TEXT NOT NULL,
      row_version BIGINT NOT NULL DEFAULT 1, updated_at TEXT NOT NULL,
      PRIMARY KEY(target_id, kind), CHECK (kind IN ('agent-card', 'jwks')), CHECK (row_version >= 1)
    )`);
    await db.execute(`CREATE TABLE a2a_discovery_attempts (
      id ${id}, operation_id BIGINT NOT NULL UNIQUE REFERENCES a2a_admin_operations(id),
      target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id), fence_sequence BIGINT NOT NULL,
      requested_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      executed_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id),
      outcome VARCHAR(24) NOT NULL, error_code VARCHAR(64),
      card_document_id BIGINT REFERENCES a2a_discovery_documents(id),
      jwks_document_id BIGINT REFERENCES a2a_discovery_documents(id),
      card_sha256 VARCHAR(64), jwks_sha256 VARCHAR(64),
      started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
      CHECK (outcome IN ('succeeded', 'not_modified', 'failed')),
      CHECK (error_code IS NULL OR error_code IN (
        'dns-rejected', 'connect-rejected', 'tls-rejected', 'redirect-rejected', 'http-rejected',
        'timeout', 'headers-too-large', 'body-too-large', 'content-rejected', 'json-rejected',
        'card-rejected', 'jwks-rejected')),
      CHECK ((outcome = 'failed' AND error_code IS NOT NULL) OR (outcome <> 'failed' AND error_code IS NULL)),
      UNIQUE(target_id, fence_sequence)
    )`);
    await db.execute(`CREATE TABLE a2a_managed_key_sources (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      jku_uri VARCHAR(2048) NOT NULL UNIQUE, state VARCHAR(16) NOT NULL DEFAULT 'active',
      row_version BIGINT NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      CHECK (state IN ('active', 'disabled')), CHECK (row_version >= 1)
    )`);
    await db.execute(`CREATE TABLE a2a_managed_key_revisions (
      id ${id}, source_id BIGINT NOT NULL REFERENCES a2a_managed_key_sources(id),
      key_id VARCHAR(128) NOT NULL, algorithm VARCHAR(8) NOT NULL, public_key_pem TEXT NOT NULL,
      key_fingerprint_sha256 VARCHAR(64) NOT NULL, state VARCHAR(16) NOT NULL DEFAULT 'observed',
      row_version BIGINT NOT NULL DEFAULT 1, linked_trust_anchor_id BIGINT UNIQUE REFERENCES a2a_trust_anchors(id),
      first_seen_attempt_id BIGINT NOT NULL REFERENCES a2a_discovery_attempts(id),
      last_seen_attempt_id BIGINT NOT NULL REFERENCES a2a_discovery_attempts(id),
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      activated_by_employee_id BIGINT REFERENCES employees(id),
      activated_by_principal_id BIGINT REFERENCES a2a_principals(id), activated_at TEXT,
      revoked_by_employee_id BIGINT REFERENCES employees(id),
      revoked_by_principal_id BIGINT REFERENCES a2a_principals(id), revoked_at TEXT, decision_reason VARCHAR(1024),
      CHECK (algorithm IN ('ES256', 'EdDSA')),
      CHECK (state IN ('observed', 'active', 'revoked')), CHECK (row_version >= 1),
      UNIQUE(source_id, key_id, key_fingerprint_sha256),
      CHECK ((state = 'observed' AND linked_trust_anchor_id IS NULL AND activated_by_principal_id IS NULL
          AND activated_by_employee_id IS NULL AND activated_at IS NULL
          AND revoked_by_principal_id IS NULL AND revoked_by_employee_id IS NULL AND revoked_at IS NULL
          AND decision_reason IS NULL)
        OR (state = 'active' AND linked_trust_anchor_id IS NOT NULL AND activated_by_principal_id IS NOT NULL
          AND activated_by_employee_id IS NOT NULL AND activated_at IS NOT NULL
          AND revoked_by_principal_id IS NULL AND revoked_by_employee_id IS NULL AND revoked_at IS NULL
          AND decision_reason IS NOT NULL)
        OR (state = 'revoked' AND linked_trust_anchor_id IS NOT NULL AND activated_by_principal_id IS NOT NULL
          AND activated_by_employee_id IS NOT NULL AND activated_at IS NOT NULL
          AND revoked_by_principal_id IS NOT NULL AND revoked_by_employee_id IS NOT NULL AND revoked_at IS NOT NULL
          AND decision_reason IS NOT NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_credential_bindings (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      canonical_origin VARCHAR(2048) NOT NULL, scheme_name VARCHAR(64) NOT NULL, scope VARCHAR(256) NOT NULL,
      state VARCHAR(16) NOT NULL DEFAULT 'active', row_version BIGINT NOT NULL DEFAULT 1,
      created_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      created_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id),
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      revoked_by_employee_id BIGINT REFERENCES employees(id), revoked_by_principal_id BIGINT REFERENCES a2a_principals(id),
      revoked_at TEXT, revoke_reason VARCHAR(1024),
      CHECK (state IN ('active', 'revoked')), CHECK (row_version >= 1),
      CHECK ((state = 'active' AND revoked_by_employee_id IS NULL AND revoked_by_principal_id IS NULL
          AND revoked_at IS NULL AND revoke_reason IS NULL)
        OR (state = 'revoked' AND revoked_by_employee_id IS NOT NULL AND revoked_by_principal_id IS NOT NULL
          AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
      UNIQUE(target_id, scheme_name, scope)
    )`);
    await db.execute(`CREATE TABLE a2a_credential_revisions (
      id ${id}, binding_id BIGINT NOT NULL REFERENCES a2a_credential_bindings(id),
      provider VARCHAR(64) NOT NULL, external_version VARCHAR(256) NOT NULL,
      secret_reference VARCHAR(1024) NOT NULL, secret_reference_hmac_sha256 VARCHAR(64) NOT NULL,
      state VARCHAR(16) NOT NULL DEFAULT 'active', row_version BIGINT NOT NULL DEFAULT 1,
      created_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      created_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id), created_at TEXT NOT NULL,
      revoked_by_employee_id BIGINT REFERENCES employees(id),
      revoked_by_principal_id BIGINT REFERENCES a2a_principals(id), revoked_at TEXT,
      CHECK (state IN ('active', 'revoked')), CHECK (row_version >= 1),
      CHECK ((state = 'active' AND revoked_by_employee_id IS NULL AND revoked_by_principal_id IS NULL AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_by_employee_id IS NOT NULL AND revoked_by_principal_id IS NOT NULL AND revoked_at IS NOT NULL)),
      UNIQUE(binding_id, id, state),
      UNIQUE(binding_id, secret_reference_hmac_sha256)
    )`);
    await db.execute("CREATE UNIQUE INDEX ux_a2a_credential_one_active_revision ON a2a_credential_revisions(binding_id) WHERE state = 'active'");
    await db.execute(`CREATE TABLE a2a_credential_active_revisions (
      binding_id BIGINT PRIMARY KEY REFERENCES a2a_credential_bindings(id) DEFERRABLE INITIALLY DEFERRED,
      revision_id BIGINT NOT NULL UNIQUE, revision_state VARCHAR(16) NOT NULL DEFAULT 'active',
      CHECK (revision_state = 'active'),
      FOREIGN KEY (binding_id, revision_id, revision_state)
        REFERENCES a2a_credential_revisions(binding_id, id, state) DEFERRABLE INITIALLY DEFERRED
    )`);
    await db.execute(`ALTER TABLE a2a_credential_bindings
      ADD COLUMN active_revision_id BIGINT REFERENCES a2a_credential_active_revisions(revision_id)
        DEFERRABLE INITIALLY DEFERRED`);
    await db.execute(`CREATE TABLE a2a_discovery_health (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      attempt_id BIGINT NOT NULL UNIQUE REFERENCES a2a_discovery_attempts(id),
      fence_sequence BIGINT NOT NULL, metadata_health VARCHAR(16) NOT NULL, reason_code VARCHAR(64) NOT NULL,
      evidence_expires_at TEXT, observed_at TEXT NOT NULL,
      CHECK (metadata_health IN ('healthy', 'invalid', 'unreachable')),
      CHECK ((metadata_health = 'healthy' AND evidence_expires_at IS NOT NULL)
        OR (metadata_health <> 'healthy' AND evidence_expires_at IS NULL)),
      CHECK (reason_code IN ('discovery-succeeded', 'discovery-not-modified', 'dns-rejected',
        'connect-rejected', 'tls-rejected', 'redirect-rejected', 'http-rejected', 'timeout',
        'headers-too-large', 'body-too-large', 'content-rejected', 'json-rejected',
        'card-rejected', 'jwks-rejected')),
      UNIQUE(target_id, fence_sequence)
    )`);
    await db.execute(`CREATE TABLE a2a_g003_audit (
      id ${id}, operation_id BIGINT NOT NULL REFERENCES a2a_admin_operations(id),
      requested_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      executed_by_principal_id BIGINT NOT NULL REFERENCES a2a_principals(id),
      action VARCHAR(64) NOT NULL, target_kind VARCHAR(32) NOT NULL, target_id VARCHAR(128) NOT NULL,
      before_state VARCHAR(32), after_state VARCHAR(32), reason VARCHAR(1024),
      metadata_json TEXT NOT NULL, created_at TEXT NOT NULL
    )`);
    await db.execute("CREATE INDEX ix_a2a_discovery_attempts_target ON a2a_discovery_attempts(target_id, id)");
    await db.execute("CREATE INDEX ix_a2a_discovery_documents_target_kind ON a2a_discovery_documents(target_id, kind, id)");
    await db.execute("CREATE INDEX ix_a2a_operations_target_state ON a2a_admin_operations(target_id, state, id)");
    await db.execute("CREATE INDEX ix_a2a_managed_keys_source_state ON a2a_managed_key_revisions(source_id, state, id)");
    await db.execute("CREATE INDEX ix_a2a_credentials_target_state ON a2a_credential_bindings(target_id, state, id)");
    await db.execute("CREATE INDEX ix_a2a_discovery_health_target ON a2a_discovery_health(target_id, fence_sequence)");
    await db.execute("CREATE INDEX ix_a2a_g003_audit_created ON a2a_g003_audit(created_at, id)");

    const appendOnlyTables = [
      "a2a_discovery_documents", "a2a_discovery_attempts", "a2a_discovery_health", "a2a_g003_audit",
    ];
    if (db.dialect === "postgres") {
      await db.execute(`CREATE FUNCTION reject_a2a_g003_append_only_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          RAISE EXCEPTION 'a2a g003 append-only record';
          RETURN NULL;
        END $$`);
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_append_only BEFORE UPDATE OR DELETE ON ${table}
          FOR EACH ROW EXECUTE FUNCTION reject_a2a_g003_append_only_mutation()`);
      }
    } else {
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g003 append-only record'); END`);
        await db.execute(`CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g003 append-only record'); END`);
      }
    }
    if (db.dialect === "postgres") {
      await db.execute(`CREATE FUNCTION reject_a2a_principal_identity_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.kind <> OLD.kind OR NEW.employee_id IS DISTINCT FROM OLD.employee_id
            OR NEW.system_name IS DISTINCT FROM OLD.system_name THEN
            RAISE EXCEPTION 'a2a principal identity is immutable';
          END IF;
          RETURN NEW;
        END $$`);
      await db.execute(`CREATE TRIGGER a2a_principals_identity_immutable BEFORE UPDATE ON a2a_principals
        FOR EACH ROW EXECUTE FUNCTION reject_a2a_principal_identity_mutation()`);
      await db.execute(`CREATE FUNCTION reject_a2a_target_identity_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.canonical_origin <> OLD.canonical_origin OR NEW.canonical_domain <> OLD.canonical_domain
            OR NEW.card_url <> OLD.card_url THEN RAISE EXCEPTION 'a2a discovery target identity is immutable'; END IF;
          RETURN NEW;
        END $$`);
      await db.execute(`CREATE TRIGGER a2a_discovery_targets_identity_immutable BEFORE UPDATE ON a2a_discovery_targets
        FOR EACH ROW EXECUTE FUNCTION reject_a2a_target_identity_mutation()`);
      await db.execute(`CREATE FUNCTION enforce_a2a_credential_active_pointer() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.state = 'active' AND (NEW.active_revision_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM a2a_credential_active_revisions r
            WHERE r.revision_id = NEW.active_revision_id AND r.binding_id = NEW.id AND r.revision_state = 'active'
          )) THEN RAISE EXCEPTION 'a2a credential active revision mismatch'; END IF;
          IF NEW.state = 'revoked' AND NEW.active_revision_id IS NOT NULL THEN
            RAISE EXCEPTION 'a2a revoked credential retains active revision';
          END IF;
          RETURN NEW;
        END $$`);
      await db.execute(`CREATE TRIGGER a2a_credential_active_pointer_insert_guard
        BEFORE INSERT ON a2a_credential_bindings
        FOR EACH ROW EXECUTE FUNCTION enforce_a2a_credential_active_pointer()`);
      await db.execute(`CREATE TRIGGER a2a_credential_active_pointer_update_guard
        BEFORE UPDATE OF active_revision_id, state ON a2a_credential_bindings
        FOR EACH ROW EXECUTE FUNCTION enforce_a2a_credential_active_pointer()`);
      await db.execute(`CREATE FUNCTION enforce_a2a_credential_revision_link() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.state = 'active' AND NOT EXISTS (
            SELECT 1 FROM a2a_credential_active_revisions a
            WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id AND a.revision_state = 'active'
          ) THEN RAISE EXCEPTION 'a2a active credential revision is not linked'; END IF;
          IF NEW.state = 'revoked' AND EXISTS (
            SELECT 1 FROM a2a_credential_active_revisions a
            WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id
          ) THEN RAISE EXCEPTION 'a2a revoked credential revision remains linked'; END IF;
          RETURN NEW;
        END $$`);
      await db.execute(`CREATE TRIGGER a2a_credential_revision_insert_guard
        BEFORE INSERT ON a2a_credential_revisions
        FOR EACH ROW EXECUTE FUNCTION enforce_a2a_credential_revision_link()`);
      await db.execute(`CREATE TRIGGER a2a_credential_revision_update_guard
        BEFORE UPDATE OF state ON a2a_credential_revisions
        FOR EACH ROW EXECUTE FUNCTION enforce_a2a_credential_revision_link()`);
    } else {
      await db.execute(`CREATE TRIGGER a2a_principals_identity_immutable BEFORE UPDATE ON a2a_principals
        WHEN NEW.kind <> OLD.kind OR NEW.employee_id IS NOT OLD.employee_id OR NEW.system_name IS NOT OLD.system_name
        BEGIN SELECT RAISE(ABORT, 'a2a principal identity is immutable'); END`);
      await db.execute(`CREATE TRIGGER a2a_discovery_targets_identity_immutable BEFORE UPDATE ON a2a_discovery_targets
        WHEN NEW.canonical_origin <> OLD.canonical_origin OR NEW.canonical_domain <> OLD.canonical_domain
          OR NEW.card_url <> OLD.card_url
        BEGIN SELECT RAISE(ABORT, 'a2a discovery target identity is immutable'); END`);
      await db.execute(`CREATE TRIGGER a2a_credential_active_pointer_insert_guard BEFORE INSERT
        ON a2a_credential_bindings
        WHEN (NEW.state = 'active' AND (NEW.active_revision_id IS NULL OR NOT EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions r
          WHERE r.revision_id = NEW.active_revision_id AND r.binding_id = NEW.id AND r.revision_state = 'active'
        ))) OR (NEW.state = 'revoked' AND NEW.active_revision_id IS NOT NULL)
        BEGIN SELECT RAISE(ABORT, 'a2a credential active revision mismatch'); END`);
      await db.execute(`CREATE TRIGGER a2a_credential_active_pointer_update_guard BEFORE UPDATE OF active_revision_id, state
        ON a2a_credential_bindings
        WHEN (NEW.state = 'active' AND (NEW.active_revision_id IS NULL OR NOT EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions r
          WHERE r.revision_id = NEW.active_revision_id AND r.binding_id = NEW.id AND r.revision_state = 'active'
        ))) OR (NEW.state = 'revoked' AND NEW.active_revision_id IS NOT NULL)
        BEGIN SELECT RAISE(ABORT, 'a2a credential active revision mismatch'); END`);
      await db.execute(`CREATE TRIGGER a2a_credential_revision_insert_guard BEFORE INSERT ON a2a_credential_revisions
        WHEN (NEW.state = 'active' AND NOT EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions a
          WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id AND a.revision_state = 'active'
        )) OR (NEW.state = 'revoked' AND EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions a
          WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id
        ))
        BEGIN SELECT RAISE(ABORT, 'a2a credential revision link mismatch'); END`);
      await db.execute(`CREATE TRIGGER a2a_credential_revision_update_guard BEFORE UPDATE OF state ON a2a_credential_revisions
        WHEN (NEW.state = 'active' AND NOT EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions a
          WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id AND a.revision_state = 'active'
        )) OR (NEW.state = 'revoked' AND EXISTS (
          SELECT 1 FROM a2a_credential_active_revisions a
          WHERE a.binding_id = NEW.binding_id AND a.revision_id = NEW.id
        ))
        BEGIN SELECT RAISE(ABORT, 'a2a credential revision link mismatch'); END`);
    }
  },
};

const a2aDirectRouteControlPlane: Migration = {
  version: "0004_a2a_direct_route_control_plane",
  async up(db) {
    const id = idColumn(db);
    await db.execute("CREATE UNIQUE INDEX ux_api_keys_id_employee ON api_keys(id, employee_id)");
    await db.execute(`CREATE TABLE a2a_caller_generations (
      id VARCHAR(128) PRIMARY KEY, employee_id BIGINT NOT NULL REFERENCES employees(id),
      api_key_id BIGINT NOT NULL,
      host_id VARCHAR(128) NOT NULL, state VARCHAR(16) NOT NULL DEFAULT 'active',
      row_version BIGINT NOT NULL DEFAULT 1, created_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      created_at TEXT NOT NULL, revoked_by_employee_id BIGINT REFERENCES employees(id),
      revoked_at TEXT, revoke_reason VARCHAR(1024),
      CHECK (state IN ('active', 'revoked')), CHECK (row_version >= 1),
      CHECK ((state = 'active' AND revoked_by_employee_id IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
        OR (state = 'revoked' AND revoked_by_employee_id IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
      FOREIGN KEY (api_key_id, employee_id) REFERENCES api_keys(id, employee_id)
    )`);
    await db.execute(`CREATE TABLE a2a_advertised_interfaces (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      card_registry_id BIGINT NOT NULL REFERENCES a2a_card_registry(id),
      interface_url VARCHAR(2048) NOT NULL, protocol_binding VARCHAR(16) NOT NULL,
      protocol_version VARCHAR(16) NOT NULL, auth_scheme VARCHAR(16) NOT NULL,
      created_at TEXT NOT NULL,
      CHECK (protocol_binding = 'JSONRPC'), CHECK (protocol_version = '1.0'), CHECK (auth_scheme = 'Bearer'),
      UNIQUE(target_id, card_registry_id, interface_url)
    )`);
    await db.execute(`CREATE TABLE a2a_interface_health_observations (
      id ${id}, advertised_interface_id BIGINT NOT NULL REFERENCES a2a_advertised_interfaces(id),
      target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      card_registry_id BIGINT NOT NULL REFERENCES a2a_card_registry(id),
      interface_url VARCHAR(2048) NOT NULL, reachability VARCHAR(16) NOT NULL,
      reason_code VARCHAR(64) NOT NULL, evidence_sha256 VARCHAR(64) NOT NULL,
      observed_at TEXT NOT NULL, expires_at TEXT,
      observed_by_employee_id BIGINT NOT NULL REFERENCES employees(id),
      CHECK (reachability IN ('healthy', 'unreachable')),
      CHECK ((reachability = 'healthy' AND expires_at IS NOT NULL)
        OR (reachability = 'unreachable' AND expires_at IS NULL))
    )`);
    await db.execute(`CREATE TABLE a2a_route_policies (
      id ${id}, target_id BIGINT NOT NULL REFERENCES a2a_discovery_targets(id),
      card_registry_id BIGINT NOT NULL REFERENCES a2a_card_registry(id),
      managed_key_revision_id BIGINT NOT NULL REFERENCES a2a_managed_key_revisions(id),
      credential_binding_id BIGINT NOT NULL REFERENCES a2a_credential_bindings(id),
      caller_generation_id VARCHAR(128) NOT NULL REFERENCES a2a_caller_generations(id),
      host_id VARCHAR(128) NOT NULL, operation_class VARCHAR(32) NOT NULL,
      interface_url VARCHAR(2048) NOT NULL,
      extension_uri VARCHAR(2048) NOT NULL, extension_spec_digest_sha256 VARCHAR(64) NOT NULL,
      wire_conformance_artifact_id VARCHAR(128) NOT NULL,
      wire_conformance_digest_sha256 VARCHAR(64) NOT NULL,
      policy_version BIGINT NOT NULL, policy_digest_sha256 VARCHAR(64) NOT NULL,
      state VARCHAR(16) NOT NULL DEFAULT 'active', row_version BIGINT NOT NULL DEFAULT 1,
      created_by_employee_id BIGINT NOT NULL REFERENCES employees(id), created_at TEXT NOT NULL,
      revoked_by_employee_id BIGINT REFERENCES employees(id), revoked_at TEXT, revoke_reason VARCHAR(1024),
      CHECK (operation_class IN ('initial_send', 'exact_initial_send_replay', 'get_task', 'continue_send', 'cancel_task')),
      CHECK (state IN ('active', 'revoked')), CHECK (policy_version >= 1), CHECK (row_version >= 1),
      CHECK ((state = 'active' AND revoked_by_employee_id IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL)
        OR (state = 'revoked' AND revoked_by_employee_id IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
      UNIQUE(target_id, caller_generation_id, host_id, operation_class, policy_version)
    )`);
    await db.execute(`CREATE TABLE a2a_route_admin_audit (
      id ${id}, actor_id BIGINT NOT NULL REFERENCES employees(id), action VARCHAR(64) NOT NULL,
      target_kind VARCHAR(32) NOT NULL, target_id VARCHAR(128) NOT NULL,
      metadata_json TEXT NOT NULL, created_at TEXT NOT NULL
    )`);
    await db.execute(`CREATE TABLE a2a_route_snapshot_issuance_audit (
      issuance_sequence ${id}, snapshot_id VARCHAR(64) NOT NULL UNIQUE,
      actor_id BIGINT NOT NULL REFERENCES employees(id),
      actor_api_key_id BIGINT NOT NULL,
      request_sha256 VARCHAR(64) NOT NULL, operation_id VARCHAR(128) NOT NULL,
      attempt_id VARCHAR(128) NOT NULL, operation_kind VARCHAR(32) NOT NULL,
      a2a_method VARCHAR(32) NOT NULL, target_agent_id BIGINT NOT NULL,
      interface_url VARCHAR(2048) NOT NULL, agent_card_digest_sha256 VARCHAR(64) NOT NULL,
      trust_key_id BIGINT NOT NULL, credential_binding_id BIGINT NOT NULL,
      credential_revision_id BIGINT NOT NULL, intended_credential_revision_id BIGINT NOT NULL,
      caller_generation_id VARCHAR(128) NOT NULL, route_policy_version BIGINT NOT NULL,
      route_policy_digest_sha256 VARCHAR(64) NOT NULL, extension_spec_digest_sha256 VARCHAR(64) NOT NULL,
      extension_uri VARCHAR(2048) NOT NULL,
      wire_conformance_artifact_id VARCHAR(128) NOT NULL,
      wire_conformance_digest_sha256 VARCHAR(64) NOT NULL,
      predecessor_credential_revision_id BIGINT,
      health_observation_id BIGINT NOT NULL REFERENCES a2a_interface_health_observations(id),
      response_json TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
      CHECK (operation_kind IN ('initial_send', 'exact_initial_send_replay', 'get_task', 'continue_send', 'cancel_task')),
      CHECK (a2a_method IN ('SendMessage', 'GetTask', 'CancelTask')),
      FOREIGN KEY (actor_api_key_id, actor_id) REFERENCES api_keys(id, employee_id),
      UNIQUE(operation_id, attempt_id)
    )`);
    await db.execute("CREATE INDEX ix_a2a_caller_generations_actor ON a2a_caller_generations(employee_id, api_key_id, host_id, state)");
    await db.execute("CREATE INDEX ix_a2a_interface_health_current ON a2a_interface_health_observations(target_id, card_registry_id, interface_url, id)");
    await db.execute("CREATE INDEX ix_a2a_route_policies_resolve ON a2a_route_policies(caller_generation_id, host_id, operation_class, state)");
    await db.execute("CREATE INDEX ix_a2a_route_snapshot_actor_created ON a2a_route_snapshot_issuance_audit(actor_id, issued_at)");
    await db.execute(`CREATE INDEX ix_a2a_route_snapshot_predecessor
      ON a2a_route_snapshot_issuance_audit
      (actor_id, actor_api_key_id, caller_generation_id, operation_id, issuance_sequence)`);

    const appendOnlyTables = [
      "a2a_advertised_interfaces", "a2a_interface_health_observations",
      "a2a_route_admin_audit", "a2a_route_snapshot_issuance_audit",
    ];
    if (db.dialect === "postgres") {
      await db.execute(`CREATE FUNCTION reject_a2a_g005_append_only_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'a2a g005 append-only record'; END $$`);
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_append_only BEFORE UPDATE OR DELETE ON ${table}
          FOR EACH ROW EXECUTE FUNCTION reject_a2a_g005_append_only_mutation()`);
      }
    } else {
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
        await db.execute(`CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
      }
    }
  },
};

const a2aVerifiedRouteEvidence: Migration = {
  version: "0005_a2a_verified_route_evidence",
  async up(db) {
    const id = idColumn(db);
    const binary = binaryColumn(db);
    await db.execute(`CREATE TABLE a2a_evidence_signers (
      id ${id}, key_id VARCHAR(128) NOT NULL UNIQUE, algorithm VARCHAR(16) NOT NULL,
      public_key_pem TEXT NOT NULL, key_fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,
      created_by_employee_id BIGINT NOT NULL REFERENCES employees(id), created_at TEXT NOT NULL,
      CHECK (algorithm = 'Ed25519'), CHECK (length(key_fingerprint_sha256) = 64)
    )`);
    await db.execute(`CREATE TABLE a2a_evidence_signer_revocations (
      id ${id}, signer_id BIGINT NOT NULL UNIQUE REFERENCES a2a_evidence_signers(id),
      revoked_by_employee_id BIGINT NOT NULL REFERENCES employees(id), revoked_at TEXT NOT NULL,
      revoke_reason VARCHAR(1024) NOT NULL
    )`);
    await db.execute(`CREATE TABLE a2a_served_spec_observations (
      id ${id}, spec_uri VARCHAR(2048) NOT NULL, body_sha256 VARCHAR(64) NOT NULL,
      body_size BIGINT NOT NULL, body_blob ${binary} NOT NULL, evidence_sha256 VARCHAR(64) NOT NULL,
      observed_by_employee_id BIGINT NOT NULL REFERENCES employees(id), observed_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      CHECK (spec_uri = '${EXACT_SEND_REPLAY_EXTENSION_URI}'),
      CHECK (body_size > 0 AND body_size <= 65536),
      CHECK (length(body_sha256) = 64 AND length(evidence_sha256) = 64)
    )`);
    await db.execute(`CREATE TABLE a2a_served_spec_revocations (
      id ${id}, served_spec_observation_id BIGINT NOT NULL UNIQUE REFERENCES a2a_served_spec_observations(id),
      revoked_by_employee_id BIGINT NOT NULL REFERENCES employees(id), revoked_at TEXT NOT NULL,
      revoke_reason VARCHAR(1024) NOT NULL
    )`);
    await db.execute(`CREATE TABLE a2a_wire_conformance_evidence (
      id ${id}, signer_id BIGINT NOT NULL REFERENCES a2a_evidence_signers(id),
      served_spec_observation_id BIGINT NOT NULL REFERENCES a2a_served_spec_observations(id),
      artifact_id VARCHAR(128) NOT NULL, artifact_digest_sha256 VARCHAR(64) NOT NULL,
      signed_payload_blob ${binary} NOT NULL, signature_blob ${binary} NOT NULL,
      schema_version VARCHAR(64) NOT NULL,
      agent_hub_head_sha VARCHAR(40) NOT NULL, lvis_app_head_sha VARCHAR(40) NOT NULL,
      remote_server_head_sha VARCHAR(40) NOT NULL,
      a2a_tck_tag VARCHAR(64) NOT NULL, a2a_tck_commit_sha VARCHAR(40) NOT NULL,
      agent_hub_lock_digest_sha256 VARCHAR(64) NOT NULL,
      lvis_app_lock_digest_sha256 VARCHAR(64) NOT NULL,
      remote_server_lock_digest_sha256 VARCHAR(64) NOT NULL,
      a2a_tck_lock_digest_sha256 VARCHAR(64) NOT NULL,
      a2a_specification_uri VARCHAR(2048) NOT NULL,
      extension_spec_uri VARCHAR(2048) NOT NULL, extension_spec_digest_sha256 VARCHAR(64) NOT NULL,
      agent_card_digest_sha256 VARCHAR(64) NOT NULL,
      test_vectors_total BIGINT NOT NULL, test_vectors_passed BIGINT NOT NULL,
      test_vectors_failed BIGINT NOT NULL, test_vectors_skipped BIGINT NOT NULL,
      verification_state VARCHAR(16) NOT NULL,
      verified_by_employee_id BIGINT NOT NULL REFERENCES employees(id), verified_at TEXT NOT NULL,
      CHECK (schema_version = 'lvis-wire-conformance-bundle/v1'),
      CHECK (a2a_specification_uri = 'https://a2a-protocol.org/v1.0.0/specification/'),
      CHECK (extension_spec_uri = '${EXACT_SEND_REPLAY_EXTENSION_URI}'),
      CHECK (length(agent_hub_head_sha) = 40 AND length(lvis_app_head_sha) = 40
        AND length(remote_server_head_sha) = 40 AND length(a2a_tck_commit_sha) = 40),
      CHECK (length(artifact_digest_sha256) = 64 AND length(agent_hub_lock_digest_sha256) = 64
        AND length(lvis_app_lock_digest_sha256) = 64
        AND length(remote_server_lock_digest_sha256) = 64
        AND length(a2a_tck_lock_digest_sha256) = 64
        AND length(extension_spec_digest_sha256) = 64 AND length(agent_card_digest_sha256) = 64),
      CHECK (test_vectors_total > 0 AND test_vectors_passed = test_vectors_total),
      CHECK (test_vectors_failed = 0 AND test_vectors_skipped = 0),
      CHECK (verification_state = 'passed'),
      UNIQUE(artifact_id, artifact_digest_sha256)
    )`);
    await db.execute(`CREATE TABLE a2a_wire_conformance_revocations (
      id ${id}, wire_conformance_evidence_id BIGINT NOT NULL UNIQUE REFERENCES a2a_wire_conformance_evidence(id),
      revoked_by_employee_id BIGINT NOT NULL REFERENCES employees(id), revoked_at TEXT NOT NULL,
      revoke_reason VARCHAR(1024) NOT NULL
    )`);
    await db.execute(`ALTER TABLE a2a_route_policies
      ADD COLUMN served_spec_observation_id BIGINT REFERENCES a2a_served_spec_observations(id)`);
    await db.execute(`ALTER TABLE a2a_route_policies
      ADD COLUMN wire_conformance_evidence_id BIGINT REFERENCES a2a_wire_conformance_evidence(id)`);
    await db.execute(`ALTER TABLE a2a_route_policies ADD COLUMN remote_server_head_sha VARCHAR(40)
      CHECK (remote_server_head_sha IS NULL OR length(remote_server_head_sha) = 40)`);
    await db.execute(`ALTER TABLE a2a_route_policies ADD COLUMN remote_server_lock_digest_sha256 VARCHAR(64)
      CHECK (remote_server_lock_digest_sha256 IS NULL OR length(remote_server_lock_digest_sha256) = 64)`);
    await db.execute(`ALTER TABLE a2a_route_policies ADD COLUMN a2a_specification_uri VARCHAR(2048)
      CHECK (a2a_specification_uri IS NULL OR a2a_specification_uri = 'https://a2a-protocol.org/v1.0.0/specification/')`);
    await db.execute(`ALTER TABLE a2a_route_snapshot_issuance_audit
      ADD COLUMN served_spec_observation_id BIGINT REFERENCES a2a_served_spec_observations(id)`);
    await db.execute(`ALTER TABLE a2a_route_snapshot_issuance_audit
      ADD COLUMN wire_conformance_evidence_id BIGINT REFERENCES a2a_wire_conformance_evidence(id)`);
    await db.execute(`ALTER TABLE a2a_route_snapshot_issuance_audit ADD COLUMN remote_server_head_sha VARCHAR(40)
      CHECK (remote_server_head_sha IS NULL OR length(remote_server_head_sha) = 40)`);
    await db.execute(`ALTER TABLE a2a_route_snapshot_issuance_audit ADD COLUMN remote_server_lock_digest_sha256 VARCHAR(64)
      CHECK (remote_server_lock_digest_sha256 IS NULL OR length(remote_server_lock_digest_sha256) = 64)`);
    await db.execute(`ALTER TABLE a2a_route_snapshot_issuance_audit ADD COLUMN a2a_specification_uri VARCHAR(2048)
      CHECK (a2a_specification_uri IS NULL OR a2a_specification_uri = 'https://a2a-protocol.org/v1.0.0/specification/')`);
    await db.execute(`CREATE INDEX ix_a2a_interface_health_latest
      ON a2a_interface_health_observations(advertised_interface_id, id DESC)`);
    await db.execute(`CREATE INDEX ix_a2a_served_spec_active
      ON a2a_served_spec_observations(spec_uri, body_sha256, expires_at, id)`);
    await db.execute(`CREATE INDEX ix_a2a_wire_evidence_lineage
      ON a2a_wire_conformance_evidence(served_spec_observation_id, extension_spec_digest_sha256,
        agent_card_digest_sha256, artifact_digest_sha256, id)`);

    const appendOnlyTables = [
      "a2a_evidence_signers", "a2a_evidence_signer_revocations",
      "a2a_served_spec_observations", "a2a_served_spec_revocations",
      "a2a_wire_conformance_evidence", "a2a_wire_conformance_revocations",
    ];
    if (db.dialect === "postgres") {
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_append_only BEFORE UPDATE OR DELETE ON ${table}
          FOR EACH ROW EXECUTE FUNCTION reject_a2a_g005_append_only_mutation()`);
      }
    } else {
      for (const table of appendOnlyTables) {
        await db.execute(`CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
        await db.execute(`CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}
          BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
      }
    }
  },
};

/**
 * Preserve immutable legacy evidence bytes while enforcing the reviewed URN
 * for every future insert. Old signed payloads cannot be rewritten without
 * invalidating their signatures, and runtime eligibility already requires the
 * exact current identifier.
 */
const a2aDomainFreeIdentifierContract: Migration = {
  version: "0006_a2a_domain_free_identifier_contract",
  async up(db) {
    if (db.dialect === "postgres") {
      const targets = [
        { table: "a2a_served_spec_observations", column: "spec_uri", constraint: "a2a_served_spec_identifier_contract_check" },
        { table: "a2a_wire_conformance_evidence", column: "extension_spec_uri", constraint: "a2a_wire_identifier_contract_check" },
      ] as const;
      for (const target of targets) {
        const existing = await db.query<{ conname: string }>(`SELECT c.conname
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
          WHERE n.nspname = current_schema() AND t.relname = $1 AND a.attname = $2
            AND c.contype = 'c' AND array_length(c.conkey, 1) = 1`, [target.table, target.column]);
        for (const row of existing) {
          const quoted = `"${row.conname.replaceAll('"', '""')}"`;
          await db.execute(`ALTER TABLE ${target.table} DROP CONSTRAINT ${quoted}`);
        }
        await db.execute(`ALTER TABLE ${target.table} ADD CONSTRAINT ${target.constraint}
          CHECK (${target.column} = '${EXACT_SEND_REPLAY_EXTENSION_URI}') NOT VALID`);
      }
      return;
    }

    // SQLite cannot drop an inline CHECK constraint. The migration runner
    // disables FK enforcement outside this transaction and verifies the full
    // graph before it records the migration.
    await db.execute("PRAGMA legacy_alter_table = ON");
    await db.execute("DROP TRIGGER IF EXISTS a2a_served_spec_observations_no_update");
    await db.execute("DROP TRIGGER IF EXISTS a2a_served_spec_observations_no_delete");
    await db.execute("ALTER TABLE a2a_served_spec_observations RENAME TO a2a_served_spec_observations_legacy_0006");
    await db.execute(`CREATE TABLE a2a_served_spec_observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, spec_uri VARCHAR(2048) NOT NULL,
      body_sha256 VARCHAR(64) NOT NULL, body_size BIGINT NOT NULL, body_blob BLOB NOT NULL,
      evidence_sha256 VARCHAR(64) NOT NULL,
      observed_by_employee_id BIGINT NOT NULL REFERENCES employees(id), observed_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      CHECK (body_size > 0 AND body_size <= 65536),
      CHECK (length(body_sha256) = 64 AND length(evidence_sha256) = 64)
    )`);
    await db.execute(`INSERT INTO a2a_served_spec_observations
      (id, spec_uri, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at)
      SELECT id, spec_uri, body_sha256, body_size, body_blob, evidence_sha256,
        observed_by_employee_id, observed_at, expires_at
      FROM a2a_served_spec_observations_legacy_0006`);
    await db.execute("DROP TABLE a2a_served_spec_observations_legacy_0006");
    await db.execute(`CREATE INDEX ix_a2a_served_spec_active
      ON a2a_served_spec_observations(spec_uri, body_sha256, expires_at, id)`);

    await db.execute("DROP TRIGGER IF EXISTS a2a_wire_conformance_evidence_no_update");
    await db.execute("DROP TRIGGER IF EXISTS a2a_wire_conformance_evidence_no_delete");
    await db.execute("ALTER TABLE a2a_wire_conformance_evidence RENAME TO a2a_wire_conformance_evidence_legacy_0006");
    await db.execute(`CREATE TABLE a2a_wire_conformance_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT, signer_id BIGINT NOT NULL REFERENCES a2a_evidence_signers(id),
      served_spec_observation_id BIGINT NOT NULL REFERENCES a2a_served_spec_observations(id),
      artifact_id VARCHAR(128) NOT NULL, artifact_digest_sha256 VARCHAR(64) NOT NULL,
      signed_payload_blob BLOB NOT NULL, signature_blob BLOB NOT NULL,
      schema_version VARCHAR(64) NOT NULL,
      agent_hub_head_sha VARCHAR(40) NOT NULL, lvis_app_head_sha VARCHAR(40) NOT NULL,
      remote_server_head_sha VARCHAR(40) NOT NULL,
      a2a_tck_tag VARCHAR(64) NOT NULL, a2a_tck_commit_sha VARCHAR(40) NOT NULL,
      agent_hub_lock_digest_sha256 VARCHAR(64) NOT NULL,
      lvis_app_lock_digest_sha256 VARCHAR(64) NOT NULL,
      remote_server_lock_digest_sha256 VARCHAR(64) NOT NULL,
      a2a_tck_lock_digest_sha256 VARCHAR(64) NOT NULL,
      a2a_specification_uri VARCHAR(2048) NOT NULL,
      extension_spec_uri VARCHAR(2048) NOT NULL, extension_spec_digest_sha256 VARCHAR(64) NOT NULL,
      agent_card_digest_sha256 VARCHAR(64) NOT NULL,
      test_vectors_total BIGINT NOT NULL, test_vectors_passed BIGINT NOT NULL,
      test_vectors_failed BIGINT NOT NULL, test_vectors_skipped BIGINT NOT NULL,
      verification_state VARCHAR(16) NOT NULL,
      verified_by_employee_id BIGINT NOT NULL REFERENCES employees(id), verified_at TEXT NOT NULL,
      CHECK (schema_version = 'lvis-wire-conformance-bundle/v1'),
      CHECK (a2a_specification_uri = 'https://a2a-protocol.org/v1.0.0/specification/'),
      CHECK (length(agent_hub_head_sha) = 40 AND length(lvis_app_head_sha) = 40
        AND length(remote_server_head_sha) = 40 AND length(a2a_tck_commit_sha) = 40),
      CHECK (length(artifact_digest_sha256) = 64 AND length(agent_hub_lock_digest_sha256) = 64
        AND length(lvis_app_lock_digest_sha256) = 64
        AND length(remote_server_lock_digest_sha256) = 64
        AND length(a2a_tck_lock_digest_sha256) = 64
        AND length(extension_spec_digest_sha256) = 64 AND length(agent_card_digest_sha256) = 64),
      CHECK (test_vectors_total > 0 AND test_vectors_passed = test_vectors_total),
      CHECK (test_vectors_failed = 0 AND test_vectors_skipped = 0),
      CHECK (verification_state = 'passed'),
      UNIQUE(artifact_id, artifact_digest_sha256)
    )`);
    await db.execute(`INSERT INTO a2a_wire_conformance_evidence
      (id, signer_id, served_spec_observation_id, artifact_id, artifact_digest_sha256,
        signed_payload_blob, signature_blob, schema_version,
        agent_hub_head_sha, lvis_app_head_sha, remote_server_head_sha,
        a2a_tck_tag, a2a_tck_commit_sha,
        agent_hub_lock_digest_sha256, lvis_app_lock_digest_sha256,
        remote_server_lock_digest_sha256, a2a_tck_lock_digest_sha256,
        a2a_specification_uri, extension_spec_uri, extension_spec_digest_sha256,
        agent_card_digest_sha256, test_vectors_total, test_vectors_passed,
        test_vectors_failed, test_vectors_skipped, verification_state,
        verified_by_employee_id, verified_at)
      SELECT id, signer_id, served_spec_observation_id, artifact_id, artifact_digest_sha256,
        signed_payload_blob, signature_blob, schema_version,
        agent_hub_head_sha, lvis_app_head_sha, remote_server_head_sha,
        a2a_tck_tag, a2a_tck_commit_sha,
        agent_hub_lock_digest_sha256, lvis_app_lock_digest_sha256,
        remote_server_lock_digest_sha256, a2a_tck_lock_digest_sha256,
        a2a_specification_uri, extension_spec_uri, extension_spec_digest_sha256,
        agent_card_digest_sha256, test_vectors_total, test_vectors_passed,
        test_vectors_failed, test_vectors_skipped, verification_state,
        verified_by_employee_id, verified_at
      FROM a2a_wire_conformance_evidence_legacy_0006`);
    await db.execute("DROP TABLE a2a_wire_conformance_evidence_legacy_0006");
    await db.execute(`CREATE INDEX ix_a2a_wire_evidence_lineage
      ON a2a_wire_conformance_evidence(served_spec_observation_id, extension_spec_digest_sha256,
        agent_card_digest_sha256, artifact_digest_sha256, id)`);

    for (const table of ["a2a_served_spec_observations", "a2a_wire_conformance_evidence"]) {
      await db.execute(`CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}
        BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
      await db.execute(`CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}
        BEGIN SELECT RAISE(ABORT, 'a2a g005 append-only record'); END`);
    }
    await db.execute(`CREATE TRIGGER a2a_served_spec_observations_identifier_contract_insert
      BEFORE INSERT ON a2a_served_spec_observations
      WHEN NEW.spec_uri <> '${EXACT_SEND_REPLAY_EXTENSION_URI}'
      BEGIN SELECT RAISE(ABORT, 'a2a served spec identifier is not current'); END`);
    await db.execute(`CREATE TRIGGER a2a_wire_conformance_evidence_identifier_contract_insert
      BEFORE INSERT ON a2a_wire_conformance_evidence
      WHEN NEW.extension_spec_uri <> '${EXACT_SEND_REPLAY_EXTENSION_URI}'
      BEGIN SELECT RAISE(ABORT, 'a2a wire identifier is not current'); END`);
    await db.execute("PRAGMA legacy_alter_table = OFF");
  },
};

/**
 * Add served-spec retrieval provenance without rewriting 0006. The column is
 * nullable for immutable legacy observations, while a forward-only constraint
 * or trigger requires it on every new write. Schema inspection also makes this
 * safe for databases that briefly applied the pre-release 0006 variant which
 * already contained the column.
 */
const a2aServedSpecSourceProvenance: Migration = {
  version: "0007_a2a_served_spec_source_provenance",
  async up(db) {
    if (db.dialect === "postgres") {
      await db.execute(`ALTER TABLE a2a_served_spec_observations
        ADD COLUMN IF NOT EXISTS source_url VARCHAR(2048)`);
      const existing = await db.query<{ conname: string }>(`SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'a2a_served_spec_observations'::regclass
          AND conname = 'a2a_served_spec_source_url_present_check'`);
      if (existing.length === 0) {
        await db.execute(`ALTER TABLE a2a_served_spec_observations
          ADD CONSTRAINT a2a_served_spec_source_url_present_check
          CHECK (source_url IS NOT NULL) NOT VALID`);
      }
      return;
    }

    const columns = await db.query<{ name: unknown }>("PRAGMA table_info(a2a_served_spec_observations)");
    if (!columns.some((column) => String(column.name) === "source_url")) {
      await db.execute("ALTER TABLE a2a_served_spec_observations ADD COLUMN source_url VARCHAR(2048)");
    }
    await db.execute("DROP TRIGGER IF EXISTS a2a_served_spec_observations_identifier_contract_insert");
    await db.execute(`CREATE TRIGGER a2a_served_spec_observations_identifier_contract_insert
      BEFORE INSERT ON a2a_served_spec_observations
      WHEN NEW.spec_uri <> '${EXACT_SEND_REPLAY_EXTENSION_URI}' OR NEW.source_url IS NULL
      BEGIN SELECT RAISE(ABORT, 'a2a served spec identifier is not current'); END`);
  },
};

const migrations = [
  publicNetworkBaseline,
  agentCardRegistry,
  agentDiscoveryConnectivity,
  a2aDirectRouteControlPlane,
  a2aVerifiedRouteEvidence,
  a2aDomainFreeIdentifierContract,
  a2aServedSpecSourceProvenance,
];

export async function migrate(db: SqlDatabase): Promise<void> {
  if (db.dialect === "sqlite") {
    await db.transaction(async (tx) => {
      await tx.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(128) PRIMARY KEY, applied_at TEXT NOT NULL)");
    });
    for (const migration of migrations) {
      const applied = await db.query<{ version: string }>(
        "SELECT version FROM schema_migrations WHERE version = $1", [migration.version],
      );
      if (applied.length > 0) continue;
      const rebuildsEvidenceTables = migration.version === a2aDomainFreeIdentifierContract.version;
      if (rebuildsEvidenceTables) await db.execute("PRAGMA foreign_keys = OFF");
      try {
        await db.transaction(async (tx) => {
          const alreadyApplied = await tx.query<{ version: string }>(
            "SELECT version FROM schema_migrations WHERE version = $1", [migration.version],
          );
          if (alreadyApplied.length > 0) return;
          await migration.up(tx);
          if (rebuildsEvidenceTables) {
            const violations = await tx.query<Record<string, unknown>>("PRAGMA foreign_key_check");
            if (violations.length > 0) throw new Error("a2a identifier migration foreign-key check failed");
          }
          await tx.execute("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)", [
            migration.version, new Date().toISOString(),
          ]);
        });
      } finally {
        if (rebuildsEvidenceTables) {
          await db.execute("PRAGMA legacy_alter_table = OFF");
          await db.execute("PRAGMA foreign_keys = ON");
        }
      }
    }
    return;
  }

  await db.transaction(async (tx) => {
    await tx.execute("SELECT pg_advisory_xact_lock($1)", [904_222_703]);
    await tx.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(128) PRIMARY KEY, applied_at TEXT NOT NULL)");
    const applied = new Set((await tx.query<{ version: string }>("SELECT version FROM schema_migrations")).map((row) => row.version));
    for (const migration of migrations) {
      if (applied.has(migration.version)) continue;
      await migration.up(tx);
      await tx.execute("INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)", [migration.version, new Date().toISOString()]);
    }
  });
}
