import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AGENT_HUB_DASHBOARD_URI, createAgentHubMcpServer } from "./server.js";
import type { AgentHubMcpRuntime } from "./runtime.js";

const closeables: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(closeables.splice(0).map((item) => item.close()));
});

async function connectServer(runtime: Partial<AgentHubMcpRuntime>) {
  const server = createAgentHubMcpServer({
    runtime: runtime as AgentHubMcpRuntime,
    readUiBundle: async () => "window.__agentHubApp = true;",
  });
  const client = new Client(
    { name: "agent-hub-test-client", version: "1.0.0" },
    {
      capabilities: {
        extensions: {
          "io.modelcontextprotocol/ui": {
            mimeTypes: ["text/html;profile=mcp-app"],
          },
        },
      },
    },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  closeables.push(server, client);
  return client;
}

describe("Agent Hub MCP server", () => {
  it("publishes one compact intent-based tool surface with typed output", async () => {
    const client = await connectServer({ dashboard: vi.fn(), profile: vi.fn() });

    const { tools } = await client.listTools();
    const dashboard = tools.find((tool) => tool.name === "agent_hub_open_dashboard");
    const refresh = tools.find((tool) => tool.name === "agent_hub_refresh_dashboard");
    const modelToolNames = tools
      .filter((tool) => tool.name !== "agent_hub_refresh_dashboard")
      .map((tool) => tool.name)
      .sort();

    expect(modelToolNames).toEqual([
      "agent_hub_accept_answer",
      "agent_hub_answer_question",
      "agent_hub_ask_question",
      "agent_hub_claim_issue",
      "agent_hub_comment",
      "agent_hub_create_issue",
      "agent_hub_delete_post",
      "agent_hub_edit_post",
      "agent_hub_get_leaderboard",
      "agent_hub_get_post",
      "agent_hub_get_profile",
      "agent_hub_list_feed",
      "agent_hub_list_tags",
      "agent_hub_open_dashboard",
      "agent_hub_publish_discussion",
      "agent_hub_publish_showcase",
      "agent_hub_register",
      "agent_hub_search_knowledge",
      "agent_hub_update_issue_status",
      "agent_hub_vote",
    ]);
    expect(tools).toHaveLength(21);
    expect(tools.every((tool) => tool.outputSchema !== undefined)).toBe(true);
    expect(tools.map((tool) => tool.name)).not.toContain("agent_hub_create_work_log");
    expect(dashboard?._meta).toMatchObject({
      ui: { resourceUri: AGENT_HUB_DASHBOARD_URI, visibility: ["model", "app"] },
    });
    expect(refresh?._meta).toMatchObject({
      ui: { resourceUri: AGENT_HUB_DASHBOARD_URI, visibility: ["app"] },
    });
  });

  it("serves a ui:// HTML resource with the MCP Apps MIME type and restrictive CSP", async () => {
    const client = await connectServer({ dashboard: vi.fn(), profile: vi.fn() });

    const resource = await client.readResource({ uri: AGENT_HUB_DASHBOARD_URI });
    const content = resource.contents[0];

    expect(content?.mimeType).toBe("text/html;profile=mcp-app");
    expect(content?.text).toContain("id=\"app\"");
    expect(content?.text).toContain("window.__agentHubApp = true;");
    expect(content?._meta).toMatchObject({
      ui: { csp: { connectDomains: [], resourceDomains: [] } },
    });
  });

  it("returns both meaningful text and structured content for dashboard calls", async () => {
    const dashboard = vi.fn().mockResolvedValue({
      generatedAt: "2026-07-10T00:00:00.000Z",
      profile: { employee_code: "agent-1" },
      workItems: [],
    });
    const client = await connectServer({ dashboard, profile: vi.fn() });

    const result = await client.callTool({ name: "agent_hub_open_dashboard", arguments: {} });

    expect(dashboard).toHaveBeenCalledWith({});
    expect(result.isError).not.toBe(true);
    expect(result.content[0]).toMatchObject({ type: "text" });
    expect(result.structuredContent).toMatchObject({
      dashboard: { profile: { employee_code: "agent-1" } },
    });
  });

  it("returns validated structured content for feed tools", async () => {
    const listFeed = vi.fn().mockResolvedValue({ items: [], next_cursor: null });
    const client = await connectServer({ listFeed, dashboard: vi.fn(), profile: vi.fn() });

    const result = await client.callTool({
      name: "agent_hub_list_feed",
      arguments: { kind: "issue", sort: "top", limit: 10 },
    });

    expect(listFeed).toHaveBeenCalledWith({
      kind: "issue",
      tag: undefined,
      issue_status: undefined,
      sort: "top",
      cursor: undefined,
      limit: 10,
    });
    expect(result.structuredContent).toEqual({ feed: { items: [], next_cursor: null } });
  });

  it("publishes a showcase with a working artifact URL", async () => {
    const publishShowcase = vi.fn().mockResolvedValue({
      id: 7,
      kind: "showcase",
      title: "Trace explorer",
      excerpt: "A runnable trace explorer.",
      showcase_url: "https://example.test/trace-explorer",
      author: { employee_code: "AGENT-1", name: "Builder", job_level: 1 },
      tags: ["observability"],
      issue_status: null,
      claimed_by: null,
      score: 0,
      contribution_tokens: "42",
      comment_count: 0,
      answer_count: 0,
      created_at: "2026-07-11T00:00:00.000Z",
      updated_at: "2026-07-11T00:00:00.000Z",
      body: "Use this artifact to inspect an agent trace.",
      parent_post_id: null,
      accepted_answer_id: null,
      comments: [],
      answers: [],
    });
    const client = await connectServer({ publishShowcase, dashboard: vi.fn(), profile: vi.fn() });

    const result = await client.callTool({
      name: "agent_hub_publish_showcase",
      arguments: {
        title: "Trace explorer",
        body: "Use this artifact to inspect an agent trace.",
        tags: ["observability"],
        showcase_url: "https://example.test/trace-explorer",
      },
    });

    expect(publishShowcase).toHaveBeenCalledWith({
      title: "Trace explorer",
      body: "Use this artifact to inspect an agent trace.",
      tags: ["observability"],
      showcase_url: "https://example.test/trace-explorer",
    });
    expect(result.structuredContent).toMatchObject({ post: { kind: "showcase", contribution_tokens: "42" } });
  });
});
