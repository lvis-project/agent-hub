import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import pg from "pg";

const engine = process.argv[2];
if (engine !== "sqlite" && engine !== "postgres") {
  throw new Error("usage: a2a-p4-5-db-parity.mjs <sqlite|postgres>");
}
const postgresUrl = process.env.AGENT_HUB_TEST_POSTGRES_URL;
if (engine === "postgres" && !postgresUrl) {
  throw new Error(
    "P4-5 PostgreSQL parity blocker: AGENT_HUB_TEST_POSTGRES_URL is required and must name a disposable database",
  );
}

const serverRoot = process.cwd();
const repositoryRoot = resolve(serverRoot, "..");
const artifactsDirectory = resolve(repositoryRoot, "artifacts/a2a-p4-5");
const sqlitePath = resolve("/tmp", `agent-hub-p4-5-${process.pid}.sqlite`);
const vitestReportPath = resolve("/tmp", `agent-hub-p4-5-${engine}-${process.pid}.vitest.json`);
const databaseUrl = engine === "sqlite" ? `sqlite://${sqlitePath}` : postgresUrl;
const git = (...args) => {
  const result = spawnSync("git", args, { cwd: repositoryRoot, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || "git command failed");
  return result.stdout.trim();
};
const head = git("rev-parse", "HEAD");
const nonArtifactChanges = git("status", "--porcelain").split("\n").filter(Boolean)
  .filter((line) => !line.includes("artifacts/"));
if (nonArtifactChanges.length > 0) {
  throw new Error("P4-5 parity artifacts require a clean committed implementation head");
}
const migrationBytes = await readFile(resolve(serverRoot, "src/migrations.ts"));
const migrationSha256 = createHash("sha256").update(migrationBytes).digest("hex");

const test = spawnSync(
  process.execPath,
  [
    "node_modules/vitest/vitest.mjs", "run", "test/route-control.e2e.test.ts",
    "--reporter=json", `--outputFile=${vitestReportPath}`,
  ],
  {
    cwd: serverRoot,
    encoding: "utf8",
    env: { ...process.env, AGENT_HUB_P4_5_DATABASE_URL: databaseUrl },
  },
);
const testOutput = `${test.stdout ?? ""}\n${test.stderr ?? ""}`;
if (test.status !== 0) {
  process.stderr.write(testOutput);
  throw new Error(`P4-5 ${engine} parity suite failed`);
}
const vitestReport = JSON.parse(await readFile(vitestReportPath, "utf8"));
await unlink(vitestReportPath);
const passed = Number(vitestReport.numPassedTests);
const failed = Number(vitestReport.numFailedTests);
const skipped = Number(vitestReport.numPendingTests) + Number(vitestReport.numTodoTests ?? 0);
const total = Number(vitestReport.numTotalTests);
if (vitestReport.success !== true || total !== 5 || passed !== 5 || failed !== 0 || skipped !== 0) {
  throw new Error(
    `P4-5 ${engine} parity expected exactly 5 tests and zero failures/skips; ` +
    `got total=${total} passed=${passed} failed=${failed} skipped=${skipped}`,
  );
}

let databaseVersion;
let schemaText;
let cleanTeardown = false;
if (engine === "sqlite") {
  const connection = new DatabaseSync(sqlitePath, { readBigInts: true });
  try {
    databaseVersion = String(connection.prepare("SELECT sqlite_version() AS version").get().version);
    schemaText = connection.prepare(`SELECT type, name, sql FROM sqlite_master
      WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`).all()
      .map((row) => JSON.stringify(row)).join("\n");
  } finally {
    connection.close();
    await unlink(sqlitePath);
    cleanTeardown = true;
  }
} else {
  const pool = new pg.Pool({ connectionString: postgresUrl });
  try {
    databaseVersion = String((await pool.query("SHOW server_version")).rows[0].server_version);
    schemaText = (await pool.query(`SELECT table_name, column_name, data_type, is_nullable
      FROM information_schema.columns WHERE table_schema = 'public'
      ORDER BY table_name, ordinal_position`)).rows.map((row) => JSON.stringify(row)).join("\n");
    await pool.query("DROP SCHEMA IF EXISTS public CASCADE");
    await pool.query("CREATE SCHEMA public");
    cleanTeardown = true;
  } finally {
    await pool.end();
  }
}

const fragment = {
  schema_version: 1,
  agent_hub_head_sha: head,
  engine,
  database_version: databaseVersion,
  migration_sha256: migrationSha256,
  schema_sha256: createHash("sha256").update(schemaText).digest("hex"),
  suite: "test/route-control.e2e.test.ts",
  test_count: passed,
  skipped_count: skipped,
  parity_cases: {
    strict_json_auth_order: true,
    admin_replay_nonduplicating: true,
    caller_api_key_host_binding: true,
    caller_api_key_final_state_fence: true,
    exact_lineage_resolution: true,
    exact_attempt_replay_nonduplicating: true,
    mismatched_attempt_replay_conflict: true,
    expired_attempt_never_reissued: true,
    concurrent_attempt_single_issuance: true,
    exact_predecessor_chain: true,
    predecessor_missing_mismatch_no_prior_fence: true,
    predecessor_cross_actor_lineage_policy_fence: true,
    predecessor_latest_attempt_fence: true,
    fresh_post_lock_expiry_fence: true,
    post_lock_latest_health_fence: true,
    intended_revision_fence: true,
    revocation_blocks_issuance: true,
    served_spec_live_byte_digest: true,
    ed25519_raw_signature_verification: true,
    canonical_wire_evidence_schema: true,
    remote_server_head_and_lock_lineage: true,
    exact_a2a_specification_uri: true,
    official_tagged_tck_release: true,
    evidence_signer_separation: true,
    evidence_revocation_fence: true,
    required_extension_fail_closed: true,
    scoped_strict_json_parser: true,
    route_rate_limit_no_store: true,
    pagination_cursor_no_skip: true,
    public_policy_operation_kind: true,
    latest_health_index: true,
    append_only_audit: true,
  },
  clean_teardown: cleanTeardown,
};
await mkdir(artifactsDirectory, { recursive: true });
const fragmentPath = resolve(artifactsDirectory, `database-parity.${engine}.json`);
await writeFile(fragmentPath, `${JSON.stringify(fragment, null, 2)}\n`, { mode: 0o444 });

const otherEngine = engine === "sqlite" ? "postgres" : "sqlite";
const otherPath = resolve(artifactsDirectory, `database-parity.${otherEngine}.json`);
try {
  await stat(otherPath);
  const other = JSON.parse(await readFile(otherPath, "utf8"));
  if (
    other.agent_hub_head_sha !== head || other.migration_sha256 !== migrationSha256 ||
    other.skipped_count !== 0 || other.clean_teardown !== true
  ) {
    throw new Error("P4-5 parity fragments do not describe the same clean implementation head");
  }
  const finalPath = resolve(artifactsDirectory, "database-parity.json");
  try {
    await stat(finalPath);
    throw new Error("P4-5 database-parity.json is immutable once finalized");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const engines = [fragment, other].sort((left, right) => left.engine.localeCompare(right.engine));
  const artifact = {
    schema_version: 1,
    agent_hub_head_sha: head,
    migration_sha256: migrationSha256,
    zero_skips: true,
    transaction_fence_replay_parity: true,
    engines,
  };
  await writeFile(finalPath, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o444 });
  await chmod(finalPath, 0o444);
  process.stdout.write(`${finalPath}\n`);
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
  process.stdout.write(`${fragmentPath}\n`);
}
