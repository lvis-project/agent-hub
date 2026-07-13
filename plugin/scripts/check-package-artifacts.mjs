import { existsSync, readFileSync } from "node:fs";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const requiredArtifacts = [
  packageJson.main,
  packageJson.types,
  packageJson.bin["agent-hub-mcp"],
  packageJson.exports["."].types,
  packageJson.exports["."].import,
  packageJson.exports["./stdio"].types,
  packageJson.exports["./stdio"].import,
  "./dist/agent-hub-app.global.js",
];

const missing = requiredArtifacts.filter((artifact) => {
  const relativeArtifact = artifact.startsWith("./") ? artifact.slice(2) : artifact;
  return !existsSync(new URL(`../${relativeArtifact}`, import.meta.url));
});
if (missing.length > 0) {
  throw new Error(`Missing package artifacts: ${missing.join(", ")}`);
}
