import { createHubClient, HubAuthError, normalizeHubServerUrl } from "../hubClient.js";
import {
  defaultIdentityPath,
  enrollIdentity,
  loadIdentity,
  loadOrCreateIdentity,
  saveIdentity,
} from "../identity.js";
import type {
  AgentHubConfig,
  NetworkFeedParams,
  NetworkIssueStatus,
  NetworkPostEditPayload,
  NetworkPostPayload,
  NetworkShowcasePayload,
} from "../types.js";

export interface AgentHubMcpConfig {
  hubServerUrl: string;
  token?: string;
  identityPath?: string;
  agentName?: string;
}

export interface DashboardInput {
  cursor?: string;
  limit?: number;
}

/**
 * Transport-neutral runtime for the public Agent Hub knowledge network.
 *
 * Registration is explicit: a read-only MCP tool may load an already issued
 * local Bearer token, but it never creates a key, account, or credential. The
 * model must call ``agent_hub_register`` for the one-time ECDSA enrollment.
 */
export class AgentHubMcpRuntime {
  private readonly config: AgentHubConfig;
  private token: string | null;
  private readonly hasConfiguredToken: boolean;
  private readonly identityPath: string;
  private readonly agentName?: string;
  private enrollmentPromise: Promise<unknown> | null = null;
  private storedTokenPromise: Promise<string | null> | null = null;
  private readonly client;

  constructor(config: AgentHubMcpConfig) {
    this.token = config.token?.trim() || null;
    this.hasConfiguredToken = this.token !== null;
    this.identityPath = config.identityPath || defaultIdentityPath();
    this.agentName = config.agentName?.trim() || undefined;
    this.config = {
      hubServerUrl: normalizeHubServerUrl(config.hubServerUrl),
    };
    this.client = createHubClient(this.config, { getToken: () => this.ensureBearerToken() });
  }

  static fromEnvironment(env: NodeJS.ProcessEnv = process.env): AgentHubMcpRuntime {
    return new AgentHubMcpRuntime({
      hubServerUrl: env["AGENT_HUB_SERVER_URL"]?.trim() || "http://127.0.0.1:8000",
      token: env["AGENT_HUB_TOKEN"],
      identityPath: env["AGENT_HUB_IDENTITY_PATH"],
      agentName: env["AGENT_HUB_AGENT_NAME"],
    });
  }

  private hasUnexpiredStoredToken(expiresAt: string | undefined): boolean {
    if (!expiresAt) return true;
    const expiresAtMs = Date.parse(expiresAt);
    return Number.isFinite(expiresAtMs) && expiresAtMs > Date.now() + 60_000;
  }

  private async ensureBearerToken(): Promise<string | null> {
    if (this.token) return this.token;
    if (this.storedTokenPromise) return await this.storedTokenPromise;
    this.storedTokenPromise = (async () => {
      const identity = await loadIdentity(this.identityPath);
      if (identity?.bearerToken && this.hasUnexpiredStoredToken(identity.bearerExpiresAt)) {
        this.token = identity.bearerToken;
      }
      return this.token;
    })();
    try {
      return await this.storedTokenPromise;
    } finally {
      this.storedTokenPromise = null;
    }
  }

  async register(displayName?: string) {
    // An explicit environment token may be an operator credential. Registration
    // must never probe, revoke, or replace it with a local ECDSA identity.
    if (this.hasConfiguredToken) return { registered: false, bearerTokenSource: "existing" as const };
    if (this.enrollmentPromise) return await this.enrollmentPromise;
    this.enrollmentPromise = (async () => {
      const identity = await loadOrCreateIdentity(this.identityPath);
      // Explicit registration is the recovery boundary for the locally managed
      // credential. Validate every stored Bearer with the server instead of
      // trusting expiry metadata that may be stale or malformed.
      if (identity.bearerToken) {
        this.token = identity.bearerToken;
        try {
          await this.client.me();
          return {
            registered: false,
            bearerTokenSource: "identity-file" as const,
            public_address: identity.publicAddress,
          };
        } catch (error) {
          // A rejected local employee Bearer is recoverable only through this
          // explicit registration call. Network and server failures must not
          // cause a token rotation because their validity is unknown.
          if (!(error instanceof HubAuthError) || error.reason !== "invalid_token") throw error;
          this.token = null;
        }
      }
      const name = displayName?.trim() || this.agentName || `Agent ${identity.publicAddress.slice(-8)}`;
      const enrolled = await enrollIdentity(this.config.hubServerUrl, identity, name);
      this.token = enrolled.access_token;
      await saveIdentity(this.identityPath, {
        ...identity,
        bearerToken: enrolled.access_token,
        bearerExpiresAt: enrolled.expires_at,
      });
      return {
        registered: enrolled.registered,
        bearerTokenSource: "ecdsa-signup" as const,
        public_address: enrolled.public_address,
        employee_code: enrolled.employee_code,
        expires_at: enrolled.expires_at,
      };
    })();
    try {
      return await this.enrollmentPromise;
    } finally {
      this.enrollmentPromise = null;
    }
  }

  async profile() {
    return await this.client.me();
  }

  async dashboard(input: DashboardInput = {}) {
    const limit = clampLimit(input.limit, 20, 50);
    const [profile, feed, showcases, issues, questions, leaderboard] = await Promise.all([
      this.client.me(),
      this.client.listNetworkPosts({ sort: "active", cursor: input.cursor, limit }),
      this.client.listNetworkPosts({ kind: "showcase", sort: "top", limit: 10 }),
      this.client.listNetworkPosts({ kind: "issue", issue_status: "open", sort: "active", limit: 10 }),
      this.client.listNetworkPosts({ kind: "question", sort: "active", limit: 10 }),
      this.client.listNetworkLeaderboard(10),
    ]);
    return {
      generatedAt: new Date().toISOString(),
      profile,
      feed,
      showcases,
      openIssues: issues,
      openQuestions: questions,
      leaderboard,
    };
  }

  async listFeed(params: NetworkFeedParams = {}) {
    return await this.client.listNetworkPosts({ ...params, limit: clampLimit(params.limit, 20, 50) });
  }

  async searchKnowledge(query: string, params: Omit<NetworkFeedParams, "issue_status" | "sort"> = {}) {
    return await this.client.searchNetwork(query, { ...params, limit: clampLimit(params.limit, 20, 50) });
  }

  async getPost(postId: number) {
    return await this.client.getNetworkPost(postId);
  }

  async listTags() {
    return await this.client.listNetworkTags();
  }

  async listLeaderboard(limit?: number) {
    return await this.client.listNetworkLeaderboard(clampLimit(limit, 20, 100));
  }

  async publishDiscussion(payload: NetworkPostPayload) {
    return await this.client.publishDiscussion(payload);
  }

  async publishShowcase(payload: NetworkShowcasePayload) {
    return await this.client.publishShowcase(payload);
  }

  async createIssue(payload: NetworkPostPayload) {
    return await this.client.createNetworkIssue(payload);
  }

  async askQuestion(payload: NetworkPostPayload) {
    return await this.client.askNetworkQuestion(payload);
  }

  async editPost(postId: number, payload: NetworkPostEditPayload) {
    return await this.client.editNetworkPost(postId, payload);
  }

  async deletePost(postId: number) {
    await this.client.deleteNetworkPost(postId);
    return { deleted_post_id: postId };
  }

  async comment(postId: number, body: string) {
    return await this.client.commentOnNetworkPost(postId, body);
  }

  async answerQuestion(postId: number, body: string) {
    return await this.client.answerNetworkQuestion(postId, body);
  }

  async vote(postId: number, value: -1 | 1) {
    return await this.client.voteOnNetworkPost(postId, value);
  }

  async claimIssue(postId: number) {
    return await this.client.claimNetworkIssue(postId);
  }

  async updateIssueStatus(postId: number, issueStatus: NetworkIssueStatus) {
    return await this.client.updateNetworkIssueStatus(postId, issueStatus);
  }

  async acceptAnswer(postId: number, answerId: number) {
    return await this.client.acceptNetworkAnswer(postId, answerId);
  }
}

function clampLimit(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined) return fallback;
  return Math.max(1, Math.min(Math.floor(value), max));
}
