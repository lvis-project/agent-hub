import { describe, expect, it } from "vitest";
import {
  revokeEvidenceSigner,
  RouteControlError,
  type RouteActor,
} from "../src/a2a/route-control-store.js";
import type { SqlDatabase, SqlRow, SqlValue } from "../src/db.js";

class LostRevocationRaceDatabase implements SqlDatabase {
  readonly dialect = "postgres" as const;
  readonly executeCalls: string[] = [];

  async query<T extends SqlRow = SqlRow>(sql: string, _params: SqlValue[] = []): Promise<T[]> {
    if (sql.includes("INSERT INTO a2a_mutation_submissions")) {
      return [{ actor_id: 17 }] as unknown as T[];
    }
    if (sql.includes("SELECT p.* FROM a2a_evidence_signers")) {
      return [{ id: 42 }] as unknown as T[];
    }
    if (sql.includes("INSERT INTO a2a_evidence_signer_revocations")) {
      // Another transaction committed the revocation after this transaction's
      // active-row read but before its INSERT reached the unique constraint.
      return [];
    }
    throw new Error(`unexpected query: ${sql}`);
  }

  async execute(sql: string): Promise<void> {
    this.executeCalls.push(sql);
    const error = Object.assign(new Error("duplicate key value violates unique constraint"), { code: "23505" });
    throw error;
  }

  async transaction<T>(work: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    return work(this);
  }

  async close(): Promise<void> {}
}

describe("route-control evidence revocation concurrency", () => {
  it("maps a lost revocation race to the stable not-active contract", async () => {
    const db = new LostRevocationRaceDatabase();
    const actor: RouteActor = { id: 17, apiKeyId: 23, employeeCode: "admin-17" };

    await expect(revokeEvidenceSigner(db, actor, 42, {
      submissionId: "concurrent-revoke-loser",
      reason: "retired",
    })).rejects.toEqual(expect.objectContaining<Partial<RouteControlError>>({
      statusCode: 404,
      code: "evidence-signer-not-active",
    }));

    expect(db.executeCalls).toEqual([]);
  });
});
