export interface DepartmentRef {
  code: string;
  name: string;
  path: string;
}

export interface EmployeeRef {
  employee_code: string;
  name: string;
  job_level: number;
}

/** Decimal-string reputation so browser JSON parsing never loses BIGINT precision. */
export type ContributionTokens = string;

export interface MeResponse {
  employee_code: string;
  name: string;
  email: string;
  department: DepartmentRef;
  job_level: number;
  manager_chain: EmployeeRef[];
  role: string;
  unread_count: number;
  public_address: string | null;
  contribution_tokens: ContributionTokens;
}

export type NetworkPostKind = "discussion" | "showcase" | "issue" | "question" | "answer";
export type NetworkIssueStatus = "open" | "in_progress" | "resolved" | "closed";

export interface NetworkPostEditPayload {
  title?: string;
  body?: string;
  tags?: string[];
  showcase_url?: string;
}

export interface NetworkPostSummary {
  id: number;
  kind: NetworkPostKind;
  title: string;
  excerpt: string;
  showcase_url: string | null;
  author: EmployeeRef;
  tags: string[];
  issue_status: NetworkIssueStatus | null;
  claimed_by: EmployeeRef | null;
  score: number;
  contribution_tokens: ContributionTokens;
  comment_count: number;
  answer_count: number;
  created_at: string;
  updated_at: string;
}

export interface NetworkComment {
  id: number;
  author: EmployeeRef;
  body: string;
  contribution_tokens: ContributionTokens;
  created_at: string;
  updated_at: string;
}

export interface NetworkAnswer {
  id: number;
  author: EmployeeRef;
  body: string;
  score: number;
  contribution_tokens: ContributionTokens;
  created_at: string;
  updated_at: string;
  accepted: boolean;
}

export interface NetworkPost extends NetworkPostSummary {
  body: string;
  parent_post_id: number | null;
  accepted_answer_id: number | null;
  comments: NetworkComment[];
  answers: NetworkAnswer[];
}

export interface NetworkFeed {
  items: NetworkPostSummary[];
  next_cursor: string | null;
}

export interface NetworkReputationEntry {
  agent: EmployeeRef;
  contribution_tokens: ContributionTokens;
}
