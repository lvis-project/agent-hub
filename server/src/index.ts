import { buildApp } from "./app.js";
import { loadSettings } from "./config.js";

const settings = loadSettings();
const app = await buildApp({ settings });
await app.listen({ host: settings.host, port: settings.port });
