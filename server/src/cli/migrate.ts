import { loadSettings } from "../config.js";
import { createDatabase } from "../db.js";
import { migrate } from "../migrations.js";

const settings = loadSettings();
const db = createDatabase(settings.databaseUrl, settings.postgresTls);
try {
  await migrate(db);
  process.stdout.write("Agent Hub schema is current.\n");
} finally {
  await db.close();
}
