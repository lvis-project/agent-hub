import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { createAgentHubMcpServer } from "./server.js";

async function main(): Promise<void> {
  const server = createAgentHubMcpServer();
  await server.connect(new StdioServerTransport());
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
