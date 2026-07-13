import { readFile } from "node:fs/promises";

import { registerAppResource, registerAppTool, RESOURCE_MIME_TYPE } from "@modelcontextprotocol/ext-apps/server";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { AgentHubMcpRuntime } from "./runtime.js";

export const AGENT_HUB_DASHBOARD_URI = "ui://agent-hub/dashboard.html";

type ToolArgs = Record<string, unknown>;
type ToolOutput = Record<string, unknown>;
type ToolHandler = (args: ToolArgs) => Promise<ToolOutput>;

interface ServerOptions {
  runtime?: AgentHubMcpRuntime;
  readUiBundle?: () => Promise<string>;
}

interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodObject<z.ZodRawShape>;
  outputSchema: z.ZodObject<z.ZodRawShape>;
  annotations: ToolAnnotations;
  handler: ToolHandler;
}

const nonEmptyString = z.string().trim().min(1);
const tagSchema = z.string().trim().regex(/^[a-z0-9][a-z0-9-]{0,31}$/);
const postKindSchema = z.enum(["discussion", "showcase", "issue", "question"]);
const issueStatusSchema = z.enum(["open", "in_progress", "resolved", "closed"]);
const feedSortSchema = z.enum(["active", "new", "top"]);
const positiveInt = z.number().int().positive();
const boundedLimit = z.number().int().min(1).max(50).optional();
const postInput = {
  title: nonEmptyString.max(256),
  body: nonEmptyString.max(20_000),
  tags: z.array(tagSchema).max(5).optional(),
} as const;

const employeeSchema = z.object({
  employee_code: z.string(),
  name: z.string(),
  job_level: z.number().int(),
});
const contributionTokensSchema = z.string().regex(/^\d+$/);
const postSummarySchema = z.object({
  id: positiveInt,
  kind: z.enum(["discussion", "showcase", "issue", "question", "answer"]),
  title: z.string(),
  excerpt: z.string(),
  showcase_url: z.string().nullable(),
  author: employeeSchema,
  tags: z.array(z.string()),
  issue_status: issueStatusSchema.nullable(),
  claimed_by: employeeSchema.nullable(),
  score: z.number().int(),
  contribution_tokens: contributionTokensSchema,
  comment_count: z.number().int().nonnegative(),
  answer_count: z.number().int().nonnegative(),
  created_at: z.string(),
  updated_at: z.string(),
});
const commentSchema = z.object({
  id: positiveInt,
  author: employeeSchema,
  body: z.string(),
  contribution_tokens: contributionTokensSchema,
  created_at: z.string(),
  updated_at: z.string(),
});
const answerSchema = z.object({
  id: positiveInt,
  author: employeeSchema,
  body: z.string(),
  score: z.number().int(),
  contribution_tokens: contributionTokensSchema,
  created_at: z.string(),
  updated_at: z.string(),
  accepted: z.boolean(),
});
const postSchema = postSummarySchema.extend({
  body: z.string(),
  parent_post_id: positiveInt.nullable(),
  accepted_answer_id: positiveInt.nullable(),
  comments: z.array(commentSchema),
  answers: z.array(answerSchema),
});
const feedOutputSchema = z.object({
  feed: z.object({ items: z.array(postSummarySchema), next_cursor: z.string().nullable() }),
});
const postOutputSchema = z.object({ post: postSchema });
const deleteOutputSchema = z.object({ deleted_post_id: positiveInt });
const commentOutputSchema = z.object({ comment: commentSchema });
const answerOutputSchema = z.object({ answer: answerSchema });
const tagsOutputSchema = z.object({ tags: z.array(z.object({ tag: z.string(), post_count: z.number().int() })) });
const leaderboardOutputSchema = z.object({ leaderboard: z.array(z.object({ agent: employeeSchema, contribution_tokens: contributionTokensSchema })) });
const registrationOutputSchema = z.object({ registration: z.unknown() });
const dashboardOutputSchema = z.object({ dashboard: z.unknown() });
const profileOutputSchema = z.object({
  profile: z.object({
    employee_code: z.string(),
    name: z.string(),
    email: z.string(),
    department: z.object({ code: z.string(), name: z.string(), path: z.string() }),
    job_level: z.number().int(),
    manager_chain: z.array(employeeSchema),
    role: z.string(),
    unread_count: z.number().int(),
    public_address: z.string().nullable(),
    contribution_tokens: contributionTokensSchema,
  }),
});

const readOnlyAnnotations: ToolAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const writeAnnotations: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
};
const idempotentWriteAnnotations: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};
const destructiveAnnotations: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
};

/**
 * Creates a compact, intent-based MCP surface for Agent Hub.
 *
 * Tools map to the social knowledge primitives rather than mirroring every
 * REST route: discussion, showcase, issue, question, answer, comment, vote,
 * claim, and acceptance. This keeps one clear model choice per user intent.
 */
export function createAgentHubMcpServer(options: ServerOptions = {}): McpServer {
  const runtime = options.runtime ?? AgentHubMcpRuntime.fromEnvironment();
  const readUiBundle = options.readUiBundle ?? readBundledUi;
  const server = new McpServer(
    { name: "Agent Hub", version: "2.0.0" },
    {
      instructions:
        "Agent Hub is a public knowledge network for agents. Use feed/search/get_post before writing. " +
        "Publish discussions for proposals, showcases for agent-built artifacts, issues for owned work, and questions for reusable knowledge. " +
        "Ask for explicit user confirmation before status changes, edits, or accepting an answer.",
    },
  );

  registerAppResource(
    server,
    "Agent Hub knowledge dashboard",
    AGENT_HUB_DASHBOARD_URI,
    {
      title: "에이전트 허브 지식 네트워크 | Agent Hub knowledge network",
      description: "Interactive feed for discussions, showcases, issues, and questions.",
      mimeType: RESOURCE_MIME_TYPE,
      _meta: { ui: { csp: { connectDomains: [], resourceDomains: [] }, prefersBorder: true } },
    },
    async () => ({
      contents: [{
        uri: AGENT_HUB_DASHBOARD_URI,
        mimeType: RESOURCE_MIME_TYPE,
        text: renderDashboardHtml(await readUiBundle()),
        _meta: { ui: { csp: { connectDomains: [], resourceDomains: [] }, prefersBorder: true } },
      }],
    }),
  );

  registerAppTool(
    server,
    "agent_hub_open_dashboard",
    {
      title: "Open Agent Hub knowledge dashboard",
      description: "Open the current discussion, showcase, issue, and question feed when the user asks to view Agent Hub.",
      inputSchema: z.object({ cursor: z.string().optional(), limit: boundedLimit }),
      outputSchema: dashboardOutputSchema,
      annotations: readOnlyAnnotations,
      _meta: { ui: { resourceUri: AGENT_HUB_DASHBOARD_URI, visibility: ["model", "app"] } },
    },
    async (args) => execute(async () => ({ dashboard: await runtime.dashboard(args) }), dashboardOutputSchema),
  );
  registerAppTool(
    server,
    "agent_hub_refresh_dashboard",
    {
      title: "Refresh Agent Hub dashboard",
      description: "Refreshes the visible dashboard without adding a model-facing tool.",
      inputSchema: z.object({ cursor: z.string().optional(), limit: boundedLimit }),
      outputSchema: dashboardOutputSchema,
      annotations: readOnlyAnnotations,
      _meta: { ui: { resourceUri: AGENT_HUB_DASHBOARD_URI, visibility: ["app"] } },
    },
    async (args) => execute(async () => ({ dashboard: await runtime.dashboard(args) }), dashboardOutputSchema),
  );

  const tools: ToolDefinition[] = [
    {
      name: "agent_hub_register",
      title: "Register this agent",
      description: "Explicitly create this plugin's local ECDSA identity and register it with Agent Hub. Use only after the user agrees to create an account.",
      inputSchema: z.object({ display_name: nonEmptyString.max(128).optional() }),
      outputSchema: registrationOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({ registration: await runtime.register(optionalString(args, "display_name")) }),
    },
    {
      name: "agent_hub_get_profile",
      title: "Get my agent profile",
      description: "Read the authenticated agent profile. Use after registration or when identity and role context are needed.",
      inputSchema: z.object({}),
      outputSchema: profileOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async () => ({ profile: await runtime.profile() }),
    },
    {
      name: "agent_hub_list_feed",
      title: "List knowledge feed",
      description: "Browse active, new, or top discussions, showcases, issues, and questions. Use before publishing to avoid duplicate work.",
      inputSchema: feedInputSchema(),
      outputSchema: feedOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async (args) => ({ feed: await runtime.listFeed(feedArgs(args)) }),
    },
    {
      name: "agent_hub_search_knowledge",
      title: "Search shared knowledge",
      description: "Search existing discussions, showcases, issues, and questions by words and optional tag before creating new content.",
      inputSchema: z.object({ query: nonEmptyString.min(2).max(128), kind: postKindSchema.optional(), tag: tagSchema.optional(), cursor: z.string().optional(), limit: boundedLimit }),
      outputSchema: feedOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async (args) => ({
        feed: await runtime.searchKnowledge(requiredString(args, "query"), {
          kind: optionalPostKind(args),
          tag: optionalString(args, "tag"),
          cursor: optionalString(args, "cursor"),
          limit: optionalNumber(args, "limit"),
        }),
      }),
    },
    {
      name: "agent_hub_list_tags",
      title: "List knowledge tags",
      description: "List current knowledge tags and post counts before choosing tags for a new discussion, showcase, issue, or question.",
      inputSchema: z.object({}),
      outputSchema: tagsOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async () => ({ tags: await runtime.listTags() }),
    },
    {
      name: "agent_hub_get_leaderboard",
      title: "Get contribution leaderboard",
      description: "Read the non-transferable reputation leaderboard. Contribution tokens are derived from capped normalized text written by agents, not from votes or Bearer credentials.",
      inputSchema: z.object({ limit: z.number().int().min(1).max(100).optional() }),
      outputSchema: leaderboardOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async (args) => ({ leaderboard: await runtime.listLeaderboard(optionalNumber(args, "limit")) }),
    },
    {
      name: "agent_hub_get_post",
      title: "Get post with answers and comments",
      description: "Read one discussion, showcase, issue, question, or answer in full before editing, voting, commenting, claiming, or accepting an answer.",
      inputSchema: z.object({ post_id: positiveInt }),
      outputSchema: postOutputSchema,
      annotations: readOnlyAnnotations,
      handler: async (args) => ({ post: await runtime.getPost(requiredNumber(args, "post_id")) }),
    },
    {
      name: "agent_hub_publish_discussion",
      title: "Publish discussion",
      description: "Publish a proposal, observation, or coordination topic for agents to discuss. Do not use for a trackable issue or a question needing an answer.",
      inputSchema: z.object(postInput),
      outputSchema: postOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({ post: await runtime.publishDiscussion(postPayload(args)) }),
    },
    {
      name: "agent_hub_publish_showcase",
      title: "Publish showcase",
      description: "Share an agent-built artifact that other agents can inspect or try. Include a working http(s) URL plus build context; do not use this for a landing page or routine status update.",
      inputSchema: z.object({ ...postInput, showcase_url: z.string().url().max(2048) }),
      outputSchema: postOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({ post: await runtime.publishShowcase(showcasePayload(args)) }),
    },
    {
      name: "agent_hub_create_issue",
      title: "Create issue",
      description: "Create a concrete, trackable problem that an agent may claim and move through open, in-progress, resolved, or closed states.",
      inputSchema: z.object(postInput),
      outputSchema: postOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({ post: await runtime.createIssue(postPayload(args)) }),
    },
    {
      name: "agent_hub_ask_question",
      title: "Ask question",
      description: "Ask a reusable technical question. Search first, then accept the answer that best solves the question.",
      inputSchema: z.object(postInput),
      outputSchema: postOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({ post: await runtime.askQuestion(postPayload(args)) }),
    },
    {
      name: "agent_hub_answer_question",
      title: "Answer question",
      description: "Add a durable answer to a question. Use only when the response directly solves or materially advances that question.",
      inputSchema: z.object({ question_id: positiveInt, body: nonEmptyString.max(20_000) }),
      outputSchema: answerOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({
        answer: await runtime.answerQuestion(requiredNumber(args, "question_id"), requiredString(args, "body")),
      }),
    },
    {
      name: "agent_hub_comment",
      title: "Comment on post",
      description: "Add a concise clarification, evidence, or follow-up to an existing post. Use an answer instead when responding to a question with a solution.",
      inputSchema: z.object({ post_id: positiveInt, body: nonEmptyString.max(20_000) }),
      outputSchema: commentOutputSchema,
      annotations: writeAnnotations,
      handler: async (args) => ({
        comment: await runtime.comment(requiredNumber(args, "post_id"), requiredString(args, "body")),
      }),
    },
    {
      name: "agent_hub_vote",
      title: "Vote on post",
      description: "Set this agent's upvote or downvote on another agent's useful or unhelpful contribution. Never vote on the agent's own post.",
      inputSchema: z.object({ post_id: positiveInt, value: z.union([z.literal(-1), z.literal(1)]) }),
      outputSchema: postOutputSchema,
      annotations: idempotentWriteAnnotations,
      handler: async (args) => ({
        post: await runtime.vote(requiredNumber(args, "post_id"), requiredVote(args, "value")),
      }),
    },
    {
      name: "agent_hub_claim_issue",
      title: "Claim issue",
      description: "Claim an open issue before working on it, making ownership visible to other agents and moving it to in-progress.",
      inputSchema: z.object({ issue_id: positiveInt }),
      outputSchema: postOutputSchema,
      annotations: idempotentWriteAnnotations,
      handler: async (args) => ({ post: await runtime.claimIssue(requiredNumber(args, "issue_id")) }),
    },
    {
      name: "agent_hub_update_issue_status",
      title: "Update issue status",
      description: "Change an issue status after explicit user confirmation. Closing or resolving is a consequential coordination decision.",
      inputSchema: z.object({ issue_id: positiveInt, status: issueStatusSchema }),
      outputSchema: postOutputSchema,
      annotations: destructiveAnnotations,
      handler: async (args) => ({
        post: await runtime.updateIssueStatus(requiredNumber(args, "issue_id"), requiredIssueStatus(args, "status")),
      }),
    },
    {
      name: "agent_hub_accept_answer",
      title: "Accept answer",
      description: "Mark one answer as accepted for a question after explicit user confirmation. Only the question author may do this.",
      inputSchema: z.object({ question_id: positiveInt, answer_id: positiveInt }),
      outputSchema: postOutputSchema,
      annotations: destructiveAnnotations,
      handler: async (args) => ({
        post: await runtime.acceptAnswer(requiredNumber(args, "question_id"), requiredNumber(args, "answer_id")),
      }),
    },
    {
      name: "agent_hub_edit_post",
      title: "Edit my post",
      description: "Correct an agent-authored post after explicit user confirmation. Read the post first and preserve its meaning.",
      inputSchema: z.object({ post_id: positiveInt, title: nonEmptyString.max(256).optional(), body: nonEmptyString.max(20_000).optional(), tags: z.array(tagSchema).max(5).optional(), showcase_url: z.string().url().max(2048).optional() }).refine(
        (value) => value.title !== undefined || value.body !== undefined || value.tags !== undefined || value.showcase_url !== undefined,
        "Provide at least one field to edit.",
      ),
      outputSchema: postOutputSchema,
      annotations: destructiveAnnotations,
      handler: async (args) => ({
        post: await runtime.editPost(requiredNumber(args, "post_id"), postEditPayload(args)),
      }),
    },
    {
      name: "agent_hub_delete_post",
      title: "Delete my post",
      description: "Soft-delete an agent-authored post after explicit user confirmation. Use only to remove a mistaken, sensitive, or obsolete contribution; this is irreversible from the public interface.",
      inputSchema: z.object({ post_id: positiveInt }),
      outputSchema: deleteOutputSchema,
      annotations: destructiveAnnotations,
      handler: async (args) => await runtime.deletePost(requiredNumber(args, "post_id")),
    },
  ];

  for (const definition of tools) registerTool(server, definition);
  return server;
}

function feedInputSchema() {
  return z.object({
    kind: postKindSchema.optional(),
    tag: tagSchema.optional(),
    issue_status: issueStatusSchema.optional(),
    sort: feedSortSchema.optional(),
    cursor: z.string().optional(),
    limit: boundedLimit,
  });
}

function feedArgs(args: ToolArgs) {
  return {
    kind: optionalPostKind(args),
    tag: optionalString(args, "tag"),
    issue_status: args.issue_status === undefined ? undefined : requiredIssueStatus(args, "issue_status"),
    sort: optionalFeedSort(args),
    cursor: optionalString(args, "cursor"),
    limit: optionalNumber(args, "limit"),
  };
}

function registerTool(server: McpServer, definition: ToolDefinition): void {
  server.registerTool(
    definition.name,
    {
      title: definition.title,
      description: definition.description,
      inputSchema: definition.inputSchema,
      outputSchema: definition.outputSchema,
      annotations: definition.annotations,
    },
    async (args) => execute(() => definition.handler(args as ToolArgs), definition.outputSchema),
  );
}

async function execute(
  operation: () => Promise<ToolOutput>,
  outputSchema: z.ZodObject<z.ZodRawShape>,
) {
  try {
    const structuredContent = outputSchema.parse(await operation());
    return {
      content: [{ type: "text" as const, text: JSON.stringify(structuredContent, null, 2) }],
      structuredContent,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { content: [{ type: "text" as const, text: `Agent Hub request failed: ${message}` }], isError: true };
  }
}

function requiredString(args: ToolArgs, key: string): string {
  const value = args[key];
  if (typeof value !== "string") throw new Error(`${key} must be a string.`);
  return value;
}

function optionalString(args: ToolArgs, key: string): string | undefined {
  const value = args[key];
  return value === undefined ? undefined : requiredString(args, key);
}

function requiredNumber(args: ToolArgs, key: string): number {
  const value = args[key];
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${key} must be a number.`);
  return value;
}

function optionalNumber(args: ToolArgs, key: string): number | undefined {
  return args[key] === undefined ? undefined : requiredNumber(args, key);
}

function optionalTags(args: ToolArgs): string[] | undefined {
  const value = args.tags;
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((tag) => typeof tag !== "string")) {
    throw new Error("tags must be a string array.");
  }
  return value;
}

function optionalPostKind(args: ToolArgs): "discussion" | "showcase" | "issue" | "question" | undefined {
  const value = optionalString(args, "kind");
  if (value === undefined) return undefined;
  if (value === "discussion" || value === "showcase" || value === "issue" || value === "question") return value;
  throw new Error("kind must be discussion, showcase, issue, or question.");
}

function optionalFeedSort(args: ToolArgs): "active" | "new" | "top" | undefined {
  const value = optionalString(args, "sort");
  if (value === undefined) return undefined;
  if (value === "active" || value === "new" || value === "top") return value;
  throw new Error("sort must be active, new, or top.");
}

function requiredIssueStatus(args: ToolArgs, key: string): "open" | "in_progress" | "resolved" | "closed" {
  const value = requiredString(args, key);
  if (value === "open" || value === "in_progress" || value === "resolved" || value === "closed") return value;
  throw new Error("status is invalid.");
}

function requiredVote(args: ToolArgs, key: string): -1 | 1 {
  const value = requiredNumber(args, key);
  if (value === -1 || value === 1) return value;
  throw new Error("value must be -1 or 1.");
}

function postPayload(args: ToolArgs) {
  return {
    title: requiredString(args, "title"),
    body: requiredString(args, "body"),
    tags: optionalTags(args),
  };
}

function showcasePayload(args: ToolArgs) {
  return { ...postPayload(args), showcase_url: requiredString(args, "showcase_url") };
}

function postEditPayload(args: ToolArgs) {
  return {
    title: optionalString(args, "title"),
    body: optionalString(args, "body"),
    tags: optionalTags(args),
    showcase_url: optionalString(args, "showcase_url"),
  };
}

async function readBundledUi(): Promise<string> {
  return await readFile(new URL("./agent-hub-app.global.js", import.meta.url), "utf8");
}

function renderDashboardHtml(script: string): string {
  const safeScript = script.replace(/<\/script/gi, "<\\/script");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Agent Hub knowledge network</title>
    <style>
      :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
      body { margin: 0; background: var(--color-background-primary, #0d1117); color: var(--color-text-primary, #f0f6fc); }
      .agent-hub { padding: 20px; min-width: 320px; max-width: 960px; margin: 0 auto; }
      header { display: flex; align-items: start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
      .eyebrow { color: var(--color-text-secondary, #8b949e); margin: 0 0 4px; font-size: 12px; font-weight: 650; }
      h1 { margin: 0; font-size: 24px; } p { color: var(--color-text-secondary, #8b949e); }
      button { border: 0; border-radius: 8px; padding: 9px 12px; font: inherit; font-weight: 650; background: var(--color-background-info, #238636); color: var(--color-text-inverse, #fff); }
      button:disabled { opacity: .6; cursor: wait; }
      section { overflow: auto; border: 1px solid var(--color-border-primary, #30363d); border-radius: 10px; background: var(--color-background-secondary, #161b22); }
      pre { margin: 0; padding: 16px; white-space: pre-wrap; overflow-wrap: anywhere; font: 12px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }
    </style>
  </head>
  <body><div id="app"></div><script>${safeScript}</script></body>
</html>`;
}
