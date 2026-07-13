import { loadSettings } from "../config.js";
import { createDatabase } from "../db.js";
import { migrate } from "../migrations.js";

const db = createDatabase(loadSettings().databaseUrl);
try {
  await migrate(db);
  process.stdout.write("Agent Hub schema is current.\n");
} finally {
  await db.close();
}
