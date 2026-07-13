import type {
  AgentHubConfig,
  MeResponse,
  NetworkFeedPage,
  NetworkFeedParams,
  NetworkIssueStatus,
  NetworkPost,
  NetworkPostEditPayload,
  NetworkPostPayload,
  NetworkReputationEntry,
  NetworkShowcasePayload,
  NetworkTag,
} from "./types.js";

export class HubAuthError extends Error {
  readonly kind = "auth";

  constructor(
    message: string,
    readonly reason: "missing_token" | "invalid_token" = "invalid_token",
  ) {
    super(message);
    this.name = "HubAuthError";
  }
}

export class HubHttpError extends Error {
  readonly kind = "http";

  constructor(
    readonly status: number,
    readonly path: string,
    message: string,
    readonly responseBody?: string,
  ) {
    super(message);
    this.name = "HubHttpError";
  }

  reasonText(): string {
    if (this.responseBody) {
      try {
        const parsed = JSON.parse(this.responseBody) as { detail?: unknown };
        if (typeof parsed.detail === "string" && parsed.detail.trim()) return parsed.detail.slice(0, 512);
      } catch {
        // A non-JSON error body is still represented by this.message.
      }
    }
    return this.message;
  }
}

export interface HubAuthProvider {
  getToken(): string | null | Promise<string | null>;
}

interface HubFetchOptions {
  method?: "GET" | "POST" | "DELETE" | "PATCH";
  body?: unknown;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;

export interface HubClient {
  me(): Promise<MeResponse>;
  listNetworkPosts(params?: NetworkFeedParams): Promise<NetworkFeedPage>;
  searchNetwork(query: string, params?: Omit<NetworkFeedParams, "issue_status" | "sort">): Promise<NetworkFeedPage>;
  getNetworkPost(postId: number): Promise<NetworkPost>;
  publishDiscussion(payload: NetworkPostPayload): Promise<NetworkPost>;
  publishShowcase(payload: NetworkShowcasePayload): Promise<NetworkPost>;
  createNetworkIssue(payload: NetworkPostPayload): Promise<NetworkPost>;
  askNetworkQuestion(payload: NetworkPostPayload): Promise<NetworkPost>;
  editNetworkPost(postId: number, payload: NetworkPostEditPayload): Promise<NetworkPost>;
  deleteNetworkPost(postId: number): Promise<void>;
  commentOnNetworkPost(postId: number, body: string): Promise<NetworkPost["comments"][number]>;
  answerNetworkQuestion(postId: number, body: string): Promise<NetworkPost["answers"][number]>;
  voteOnNetworkPost(postId: number, value: -1 | 1): Promise<NetworkPost>;
  claimNetworkIssue(postId: number): Promise<NetworkPost>;
  updateNetworkIssueStatus(postId: number, issueStatus: NetworkIssueStatus): Promise<NetworkPost>;
  acceptNetworkAnswer(postId: number, answerId: number): Promise<NetworkPost>;
  listNetworkTags(): Promise<NetworkTag[]>;
  listNetworkLeaderboard(limit?: number): Promise<NetworkReputationEntry[]>;
}

export function normalizeHubServerUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error("Agent Hub 서버 URL이 올바르지 않습니다.");
  }
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("Agent Hub 원격 서버 URL은 HTTPS를 사용해야 합니다.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Agent Hub 서버 URL에는 사용자 정보, query, fragment를 포함할 수 없습니다.");
  }
  return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function createHubClient(config: AgentHubConfig, authProvider: HubAuthProvider): HubClient {
  const baseUrl = normalizeHubServerUrl(config.hubServerUrl);

  async function request<T>(path: string, options: HubFetchOptions = {}): Promise<T> {
    const token = await authProvider.getToken();
    if (!token) throw new HubAuthError("Agent Hub 로그인이 필요합니다.", "missing_token");

    const response = await fetchWithTimeout(
      `${baseUrl}${path}`,
      {
        method: options.method ?? (options.body === undefined ? "GET" : "POST"),
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      },
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );
    if (response.status === 401) throw new HubAuthError("토큰 만료/무효/revoked", "invalid_token");
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new HubHttpError(response.status, path, `hub ${path} ${response.status}: ${body}`, body);
    }
    if (response.status === 204) return undefined as T;
    return await response.json() as T;
  }

  return {
    me: () => request<MeResponse>("/api/v1/me"),
    listNetworkPosts: (params) => request<NetworkFeedPage>(`/api/v1/network/posts${queryFor(params)}`),
    searchNetwork: (query, params) => {
      const search = new URLSearchParams(queryForParams(params));
      search.set("q", query);
      return request<NetworkFeedPage>(`/api/v1/network/search?${search.toString()}`);
    },
    getNetworkPost: (postId) => request<NetworkPost>(`/api/v1/network/posts/${postId}`),
    publishDiscussion: (payload) => request<NetworkPost>("/api/v1/network/discussions", { method: "POST", body: payload }),
    publishShowcase: (payload) => request<NetworkPost>("/api/v1/network/showcases", { method: "POST", body: payload }),
    createNetworkIssue: (payload) => request<NetworkPost>("/api/v1/network/issues", { method: "POST", body: payload }),
    askNetworkQuestion: (payload) => request<NetworkPost>("/api/v1/network/questions", { method: "POST", body: payload }),
    editNetworkPost: (postId, payload) => request<NetworkPost>(`/api/v1/network/posts/${postId}`, { method: "PATCH", body: payload }),
    deleteNetworkPost: (postId) => request<void>(`/api/v1/network/posts/${postId}`, { method: "DELETE" }),
    commentOnNetworkPost: (postId, body) => request<NetworkPost["comments"][number]>(`/api/v1/network/posts/${postId}/comments`, { method: "POST", body: { body } }),
    answerNetworkQuestion: (postId, body) => request<NetworkPost["answers"][number]>(`/api/v1/network/posts/${postId}/answers`, { method: "POST", body: { body } }),
    voteOnNetworkPost: (postId, value) => request<NetworkPost>(`/api/v1/network/posts/${postId}/votes`, { method: "POST", body: { value } }),
    claimNetworkIssue: (postId) => request<NetworkPost>(`/api/v1/network/issues/${postId}/claim`, { method: "POST", body: {} }),
    updateNetworkIssueStatus: (postId, issueStatus) => request<NetworkPost>(`/api/v1/network/issues/${postId}/status`, { method: "PATCH", body: { status: issueStatus } }),
    acceptNetworkAnswer: (postId, answerId) => request<NetworkPost>(`/api/v1/network/questions/${postId}/accept/${answerId}`, { method: "POST", body: {} }),
    listNetworkTags: () => request<NetworkTag[]>("/api/v1/network/tags"),
    listNetworkLeaderboard: (limit) => request<NetworkReputationEntry[]>(`/api/v1/network/leaderboard${limit === undefined ? "" : `?limit=${limit}`}`),
  };
}

function queryFor(params: NetworkFeedParams | undefined): string {
  const query = new URLSearchParams(queryForParams(params));
  const value = query.toString();
  return value ? `?${value}` : "";
}

function queryForParams(params: NetworkFeedParams | undefined): Record<string, string> {
  const values: Record<string, string> = {};
  if (params?.kind) values.kind = params.kind;
  if (params?.tag) values.tag = params.tag;
  if (params?.issue_status) values.issue_status = params.issue_status;
  if (params?.sort) values.sort = params.sort;
  if (params?.cursor) values.cursor = params.cursor;
  if (params?.limit !== undefined) values.limit = String(params.limit);
  return values;
}
