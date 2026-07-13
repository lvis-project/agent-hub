import { createHash } from "node:crypto";
import { loadSettings } from "../config.js";
import { asNumber, createDatabase, type SqlDatabase } from "../db.js";
import { newBearerToken } from "../identity.js";
import { migrate } from "../migrations.js";

type BootstrapInput = { employeeCode: string; name: string; email: string };
type EmployeeCodeInput = { employeeCode: string };
type Command = "bootstrap-admin" | "rotate-admin" | "revoke-agent-tokens" | "revoke-agent-identity";

function readOption(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function usage(): never {
  throw new Error("Usage: bun run provision -- <bootstrap-admin|rotate-admin|revoke-agent-tokens|revoke-agent-identity> --employee-code CODE [--name NAME --email EMAIL]");
}

function command(): Command {
  const value = process.argv[2];
  if (value === "bootstrap-admin" || value === "rotate-admin" || value === "revoke-agent-tokens" || value === "revoke-agent-identity") return value;
  return usage();
}

function employeeCodeInput(): EmployeeCodeInput {
  const employeeCode = readOption("--employee-code")?.trim();
  if (!employeeCode) usage();
  return { employeeCode };
}

function bootstrapInput(): BootstrapInput {
  const { employeeCode } = employeeCodeInput();
  const name = readOption("--name")?.trim();
  const email = readOption("--email")?.trim();
  if (!name || !email) usage();
  return { employeeCode, name, email };
}

async function issueAdminToken(tx: SqlDatabase, employeeId: number, employeeCode: string, label: string) {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.parse(issuedAt) + 90 * 24 * 60 * 60_000).toISOString();
  const token = newBearerToken();
  const hash = createHash("sha256").update(token, "utf8").digest("hex");
  await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE employee_id = $2 AND role = 'admin' AND revoked_at IS NULL", [issuedAt, employeeId]);
  await tx.execute("INSERT INTO api_keys (employee_id, label, key_hash, key_prefix, role, created_at, expires_at) VALUES ($1, $2, $3, $4, 'admin', $5, $6)", [employeeId, label, hash, token.slice(0, 16), issuedAt, expiresAt]);
  return { employee_code: employeeCode, access_token: token, expires_at: expiresAt };
}

async function bootstrapAdmin(tx: SqlDatabase, value: BootstrapInput) {
  const existing = await tx.query("SELECT id FROM employees WHERE employee_code = $1 OR email = $2", [value.employeeCode, value.email]);
  if (existing.length > 0) throw new Error("An employee with that code or email already exists; use rotate-admin for an existing administrator.");
  let department = await tx.query<{ id: unknown }>("SELECT id FROM departments WHERE code = 'ADMINS'");
  if (department[0] === undefined) department = await tx.query<{ id: unknown }>("INSERT INTO departments (code, name, path, created_at) VALUES ('ADMINS', 'Agent Hub administrators', '/ADMINS', $1) RETURNING id", [new Date().toISOString()]);
  const employee = await tx.query<{ id: unknown }>("INSERT INTO employees (employee_code, name, email, department_id, job_level, reputation_tokens, created_at) VALUES ($1, $2, $3, $4, 1, 0, $5) RETURNING id", [value.employeeCode, value.name, value.email, asNumber(department[0]!.id), new Date().toISOString()]);
  return issueAdminToken(tx, asNumber(employee[0]!.id), value.employeeCode, "operator-bootstrap");
}

async function rotateAdmin(tx: SqlDatabase, value: EmployeeCodeInput) {
  const employee = (await tx.query<{ id: unknown }>("SELECT e.id FROM employees e WHERE e.employee_code = $1 AND EXISTS (SELECT 1 FROM api_keys k WHERE k.employee_id = e.id AND k.role = 'admin')", [value.employeeCode]))[0];
  if (employee === undefined) throw new Error("No administrator exists with that employee code.");
  return issueAdminToken(tx, asNumber(employee.id), value.employeeCode, "operator-rotation");
}

async function revokeAgentTokens(tx: SqlDatabase, value: EmployeeCodeInput) {
  const employee = (await tx.query<{ id: unknown }>("SELECT id FROM employees WHERE employee_code = $1", [value.employeeCode]))[0];
  if (employee === undefined) throw new Error("No employee exists with that employee code.");
  const revokedAt = new Date().toISOString();
  await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE employee_id = $2 AND role = 'employee' AND revoked_at IS NULL", [revokedAt, asNumber(employee.id)]);
  return { employee_code: value.employeeCode, revoked_at: revokedAt };
}

/** Disable a lost/compromised ECDSA identity as well as every employee Bearer it issued. */
async function revokeAgentIdentity(tx: SqlDatabase, value: EmployeeCodeInput) {
  const identity = (await tx.query<{ employee_id: unknown; revoked_at: unknown }>(`SELECT i.employee_id, i.revoked_at
    FROM agent_identities i JOIN employees e ON e.id = i.employee_id WHERE e.employee_code = $1`, [value.employeeCode]))[0];
  if (identity === undefined) throw new Error("No agent identity exists with that employee code.");
  const employeeId = asNumber(identity.employee_id);
  const revokedAt = identity.revoked_at === null ? new Date().toISOString() : String(identity.revoked_at);
  if (identity.revoked_at === null) {
    await tx.execute("UPDATE agent_identities SET revoked_at = $1 WHERE employee_id = $2 AND revoked_at IS NULL", [revokedAt, employeeId]);
  }
  await tx.execute("UPDATE api_keys SET revoked_at = $1 WHERE employee_id = $2 AND role = 'employee' AND revoked_at IS NULL", [revokedAt, employeeId]);
  return { employee_code: value.employeeCode, identity_revoked_at: revokedAt, bearer_tokens_revoked_at: revokedAt };
}

const settings = loadSettings();
const db = createDatabase(settings.databaseUrl);
try {
  await migrate(db);
  const selected = command();
  const result = await db.transaction(async (tx) => {
    if (selected === "bootstrap-admin") return bootstrapAdmin(tx, bootstrapInput());
    if (selected === "rotate-admin") return rotateAdmin(tx, employeeCodeInput());
    if (selected === "revoke-agent-tokens") return revokeAgentTokens(tx, employeeCodeInput());
    return revokeAgentIdentity(tx, employeeCodeInput());
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} finally {
  await db.close();
}
