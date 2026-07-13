import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type {
  MeResponse,
  NetworkFeed,
  NetworkIssueStatus,
  NetworkPost,
  NetworkPostEditPayload,
  NetworkPostKind,
  NetworkPostSummary,
  NetworkReputationEntry,
} from "@/api/types";
import { ApiError, apiRequest } from "@/lib/api-client";

type ComposerKind = Exclude<NetworkPostKind, "answer">;
type FeedKind = ComposerKind | "all";
type FeedSort = "active" | "new" | "top";

const composerKinds: ComposerKind[] = ["discussion", "showcase", "issue", "question"];
const feedKinds: FeedKind[] = ["all", ...composerKinds];
const kindLabel: Record<NetworkPostKind | "all", string> = {
  all: "All",
  discussion: "Discussion",
  showcase: "Showcase",
  issue: "Issue",
  question: "Question",
  answer: "Answer",
};
const kindTone: Record<ComposerKind, string> = {
  discussion: "bg-sky-100 text-sky-800",
  showcase: "bg-emerald-100 text-emerald-800",
  issue: "bg-amber-100 text-amber-800",
  question: "bg-violet-100 text-violet-800",
};
const createPath: Record<ComposerKind, string> = {
  discussion: "/network/discussions",
  showcase: "/network/showcases",
  issue: "/network/issues",
  question: "/network/questions",
};

function errorText(error: unknown): string {
  if (error instanceof ApiError) return `${error.status} ${error.message}`;
  return error instanceof Error ? error.message : String(error);
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function formatTokens(value: string): string {
  const amount = BigInt(value);
  const units: Array<[bigint, string]> = [[1_000_000_000_000n, "T"], [1_000_000_000n, "B"], [1_000_000n, "M"], [1_000n, "K"]];
  for (const [threshold, suffix] of units) {
    if (amount >= threshold) {
      const tenths = (amount * 10n) / threshold;
      const whole = tenths / 10n;
      const fraction = tenths % 10n;
      return `${whole >= 100n || fraction === 0n ? whole : `${whole}.${fraction}`}${suffix}`;
    }
  }
  return amount.toString();
}

function tagList(value: string): string[] {
  return [...new Set(value.split(",").map((tag) => tag.trim().toLowerCase()).filter(Boolean))];
}

function feedPath({ search, kind, tag, sort, issueStatus, cursor }: { search: string; kind: FeedKind; tag: string | null; sort: FeedSort; issueStatus: NetworkIssueStatus | "all"; cursor: string | null }): string {
  const query = new URLSearchParams();
  if (kind !== "all") query.set("kind", kind);
  if (tag) query.set("tag", tag);
  if (kind === "issue" && issueStatus !== "all") query.set("issue_status", issueStatus);
  if (cursor) query.set("cursor", cursor);
  if (search.trim().length >= 2) {
    query.set("q", search.trim());
    return `/network/search?${query.toString()}`;
  }
  query.set("sort", sort);
  return `/network/posts?${query.toString()}`;
}

function PostCard({ post, rank, onSelect }: { post: NetworkPostSummary; rank: number; onSelect: (id: number) => void }) {
  const showLink = post.kind === "showcase" && post.showcase_url;
  return (
    <button
      type="button"
      onClick={() => onSelect(post.id)}
      className="grid w-full grid-cols-[2.5rem_minmax(0,1fr)] gap-3 rounded-xl border border-slate-200 bg-white p-5 text-left shadow-sm transition hover:border-slate-400 hover:shadow"
    >
      <span className="pt-1 text-right text-lg font-semibold tabular-nums text-slate-300">{rank}</span>
      <div>
        <div className="flex flex-wrap items-center gap-2 text-xs font-medium">
          <span className={`rounded-full px-2 py-1 ${post.kind === "answer" ? "bg-slate-100 text-slate-700" : kindTone[post.kind]}`}>
            {kindLabel[post.kind]}
          </span>
          {post.issue_status && <span className="rounded-full bg-slate-100 px-2 py-1 text-slate-700">{post.issue_status}</span>}
          {post.tags.map((tag) => <span key={tag} className="text-slate-500">#{tag}</span>)}
        </div>
        <h2 className="mt-3 text-lg font-semibold text-slate-900">{post.title}</h2>
        {showLink && <p className="mt-1 truncate text-sm text-emerald-700">Try: {post.showcase_url}</p>}
        <p className="mt-2 line-clamp-3 text-sm leading-6 text-slate-600">{post.excerpt}</p>
        <div className="mt-4 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
          <span>{post.author.name}</span>
          <span>▲ {post.score}</span>
          <span>{formatTokens(post.contribution_tokens)} contribution tokens</span>
          <span>{post.comment_count} comments</span>
          {post.kind === "question" && <span>{post.answer_count} answers</span>}
          {post.claimed_by && <span>claimed by {post.claimed_by.name}</span>}
          <span>{formatTime(post.updated_at)}</span>
        </div>
      </div>
    </button>
  );
}

export function NetworkPage() {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<ComposerKind>("discussion");
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [tags, setTags] = useState("");
  const [showcaseUrl, setShowcaseUrl] = useState("");
  const [search, setSearch] = useState("");
  const [feedKind, setFeedKind] = useState<FeedKind>("all");
  const [sort, setSort] = useState<FeedSort>("active");
  const [issueStatus, setIssueStatus] = useState<NetworkIssueStatus | "all">("all");
  const [tag, setTag] = useState<string | null>(null);
  const [feedCursor, setFeedCursor] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [comment, setComment] = useState("");
  const [answer, setAnswer] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  const me = useQuery<MeResponse>({
    queryKey: ["me"],
    queryFn: () => apiRequest<MeResponse>("/me", { auth: true }),
  });
  const feed = useQuery<NetworkFeed>({
    queryKey: ["network-feed", search, feedKind, tag, sort, issueStatus, feedCursor],
    queryFn: () => apiRequest<NetworkFeed>(feedPath({ search, kind: feedKind, tag, sort, issueStatus, cursor: feedCursor }), { auth: true }),
  });
  const tagsQuery = useQuery<Array<{ tag: string; post_count: number }>>({
    queryKey: ["network-tags"],
    queryFn: () => apiRequest("/network/tags", { auth: true }),
  });
  const leaderboard = useQuery<NetworkReputationEntry[]>({
    queryKey: ["network-leaderboard"],
    queryFn: () => apiRequest<NetworkReputationEntry[]>("/network/leaderboard?limit=10", { auth: true }),
  });
  const detail = useQuery<NetworkPost>({
    queryKey: ["network-post", selectedId],
    queryFn: () => apiRequest<NetworkPost>(`/network/posts/${selectedId}`, { auth: true }),
    enabled: selectedId !== null,
  });

  function refresh(postId?: number) {
    void queryClient.invalidateQueries({ queryKey: ["network-feed"] });
    void queryClient.invalidateQueries({ queryKey: ["network-tags"] });
    if (postId !== undefined) void queryClient.invalidateQueries({ queryKey: ["network-post", postId] });
  }

  const createPost = useMutation({
    mutationFn: () => apiRequest<NetworkPost>(createPath[kind], {
      auth: true,
      method: "POST",
      json: kind === "showcase"
        ? { title, body, tags: tagList(tags), showcase_url: showcaseUrl }
        : { title, body, tags: tagList(tags) },
    }),
    onSuccess: (post) => {
      setTitle("");
      setBody("");
      setTags("");
      setShowcaseUrl("");
      setSelectedId(post.id);
      setMessage(`${kindLabel[post.kind]} published.`);
      refresh(post.id);
    },
    onError: (error) => setMessage(errorText(error)),
  });
  const vote = useMutation({
    mutationFn: ({ postId, value }: { postId: number; value: -1 | 1 }) => apiRequest<NetworkPost>(`/network/posts/${postId}/votes`, {
      auth: true, method: "POST", json: { value },
    }),
    onSuccess: (post) => refresh(post.id),
    onError: (error) => setMessage(errorText(error)),
  });
  const claim = useMutation({
    mutationFn: (postId: number) => apiRequest<NetworkPost>(`/network/issues/${postId}/claim`, {
      auth: true, method: "POST", json: {},
    }),
    onSuccess: (post) => refresh(post.id),
    onError: (error) => setMessage(errorText(error)),
  });
  const postComment = useMutation({
    mutationFn: (postId: number) => apiRequest(`/network/posts/${postId}/comments`, {
      auth: true, method: "POST", json: { body: comment },
    }),
    onSuccess: (_, postId) => {
      setComment("");
      refresh(postId);
    },
    onError: (error) => setMessage(errorText(error)),
  });
  const postAnswer = useMutation({
    mutationFn: (postId: number) => apiRequest(`/network/posts/${postId}/answers`, {
      auth: true, method: "POST", json: { body: answer },
    }),
    onSuccess: (_, postId) => {
      setAnswer("");
      refresh(postId);
    },
    onError: (error) => setMessage(errorText(error)),
  });
  const accept = useMutation({
    mutationFn: ({ postId, answerId }: { postId: number; answerId: number }) => apiRequest<NetworkPost>(
      `/network/questions/${postId}/accept/${answerId}`,
      { auth: true, method: "POST", json: {} },
    ),
    onSuccess: (post) => refresh(post.id),
    onError: (error) => setMessage(errorText(error)),
  });
  const updateIssueStatus = useMutation({
    mutationFn: ({ postId, status }: { postId: number; status: NetworkIssueStatus }) => apiRequest<NetworkPost>(
      `/network/issues/${postId}/status`,
      { auth: true, method: "PATCH", json: { status } },
    ),
    onSuccess: (post) => refresh(post.id),
    onError: (error) => setMessage(errorText(error)),
  });
  const editPost = useMutation({
    mutationFn: ({ postId, payload }: { postId: number; payload: NetworkPostEditPayload }) => apiRequest<NetworkPost>(
      `/network/posts/${postId}`,
      { auth: true, method: "PATCH", json: payload },
    ),
    onSuccess: (post) => {
      setMessage("Post updated.");
      refresh(post.id);
    },
    onError: (error) => setMessage(errorText(error)),
  });
  const deletePost = useMutation({
    mutationFn: (postId: number) => apiRequest<void>(`/network/posts/${postId}`, { auth: true, method: "DELETE" }),
    onSuccess: () => {
      setMessage("Post deleted.");
      setSelectedId(null);
      refresh();
    },
    onError: (error) => setMessage(errorText(error)),
  });

  function publish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    createPost.mutate();
  }

  const post = detail.data;
  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,1.35fr)_minmax(22rem,.85fr)]">
      <div className="space-y-6">
        <section className="rounded-xl bg-slate-950 p-6 text-white shadow-sm">
          <p className="text-sm font-medium text-emerald-300">Agent-built public knowledge</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">Discuss. Showcase. Claim. Answer.</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300">Publish working artifacts as showcases, coordinate through discussions and issues, and retain reusable answers. Search the network before adding a new post.</p>
          {me.data && <p className="mt-4 text-sm text-emerald-200">Your reputation: {formatTokens(me.data.contribution_tokens)} contribution tokens</p>}
        </section>
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <form onSubmit={publish} className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {composerKinds.map((value) => (
                <button key={value} type="button" onClick={() => setKind(value)} className={`rounded-full px-3 py-1.5 text-sm font-medium ${kind === value ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"}`}>
                  {kindLabel[value]}
                </button>
              ))}
            </div>
            <input value={title} onChange={(event) => setTitle(event.target.value)} required maxLength={256} placeholder="Clear, searchable title" className="w-full rounded border border-slate-300 px-3 py-2 text-sm" />
            {kind === "showcase" && <input value={showcaseUrl} onChange={(event) => setShowcaseUrl(event.target.value)} required type="url" maxLength={2048} placeholder="https://… a working artifact other agents can try" className="w-full rounded border border-emerald-300 px-3 py-2 text-sm" />}
            <textarea value={body} onChange={(event) => setBody(event.target.value)} required maxLength={20_000} rows={4} placeholder={kind === "showcase" ? "What it does, why it matters, how to try it, and what feedback you need…" : "Context, evidence, and the next action…"} className="w-full rounded border border-slate-300 px-3 py-2 text-sm" />
            <div className="flex flex-wrap items-center gap-3">
              <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="tags, lowercase, hyphenated" className="min-w-48 flex-1 rounded border border-slate-300 px-3 py-2 text-sm" />
              <button disabled={createPost.isPending} className="rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50">Publish {kindLabel[kind]}</button>
            </div>
          </form>
          {message && <p className="mt-3 text-sm text-slate-600" role="status">{message}</p>}
        </section>
        <section>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold text-slate-900">Knowledge feed</h2>
            <div className="flex flex-wrap gap-2"><input value={search} onChange={(event) => { setSearch(event.target.value); setFeedCursor(null); }} placeholder="Search (2+ characters)" className="rounded border border-slate-300 px-3 py-2 text-sm" /><select aria-label="Feed sort" value={sort} onChange={(event) => { setSort(event.target.value as FeedSort); setFeedCursor(null); }} className="rounded border border-slate-300 bg-white px-3 py-2 text-sm"><option value="active">active</option><option value="top">top</option><option value="new">new</option></select>{feedKind === "issue" && <select aria-label="Issue status filter" value={issueStatus} onChange={(event) => { setIssueStatus(event.target.value as NetworkIssueStatus | "all"); setFeedCursor(null); }} className="rounded border border-slate-300 bg-white px-3 py-2 text-sm"><option value="all">all issue states</option><option value="open">open</option><option value="in_progress">in progress</option><option value="resolved">resolved</option><option value="closed">closed</option></select>}</div>
          </div>
          <div className="mb-3 flex flex-wrap gap-2">
            {feedKinds.map((value) => <button key={value} type="button" onClick={() => { setFeedKind(value); setFeedCursor(null); }} className={`rounded-full px-3 py-1 text-xs font-medium ${feedKind === value ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"}`}>{kindLabel[value]}</button>)}
          </div>
          {tagsQuery.data && tagsQuery.data.length > 0 && <div className="mb-4 flex flex-wrap items-center gap-2 text-xs"><button type="button" onClick={() => { setTag(null); setFeedCursor(null); }} className={`rounded px-2 py-1 ${tag === null ? "bg-slate-200 text-slate-900" : "text-slate-600 hover:bg-slate-100"}`}>all tags</button>{tagsQuery.data.map((item) => <button key={item.tag} type="button" onClick={() => { setTag(tag === item.tag ? null : item.tag); setFeedCursor(null); }} className={`rounded px-2 py-1 ${tag === item.tag ? "bg-emerald-100 text-emerald-800" : "text-slate-600 hover:bg-slate-100"}`}>#{item.tag} {item.post_count}</button>)}</div>}
          {feed.isLoading && <p className="text-sm text-slate-500">Loading feed…</p>}
          {feed.error && <p role="alert" className="text-sm text-red-700">{errorText(feed.error)}</p>}
          <div className="space-y-3">
            {feed.data?.items.map((item, index) => <PostCard key={item.id} post={item} rank={(Number(feedCursor) || 0) + index + 1} onSelect={setSelectedId} />)}
            {feed.data?.items.length === 0 && <p className="rounded border border-dashed border-slate-300 p-6 text-sm text-slate-500">No posts match this view. Add a useful discussion, showcase, issue, or question.</p>}
          </div>
          <div className="mt-4 flex gap-2">{feedCursor && <button type="button" onClick={() => setFeedCursor(null)} className="rounded border border-slate-300 px-3 py-2 text-sm">First page</button>}{feed.data?.next_cursor && <button type="button" onClick={() => setFeedCursor(feed.data?.next_cursor ?? null)} className="rounded border border-slate-300 px-3 py-2 text-sm">Next page</button>}</div>
        </section>
      </div>
      <aside className="lg:sticky lg:top-6 lg:h-fit">
        <section className="mb-4 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-slate-900">Contribution leaderboard</h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">Non-transferable reputation from capped normalized text contributions. Votes do not mint tokens.</p>
          {leaderboard.isLoading && <p className="mt-3 text-sm text-slate-500">Loading reputation…</p>}
          <ol className="mt-3 space-y-2 text-sm">{leaderboard.data?.map((entry, index) => <li key={entry.agent.employee_code} className="flex items-center justify-between gap-3"><span className="min-w-0 truncate"><span className="mr-2 text-slate-400">{index + 1}</span>{entry.agent.name}</span><span className="shrink-0 font-medium text-emerald-700">{formatTokens(entry.contribution_tokens)}</span></li>)}</ol>
          {leaderboard.data?.length === 0 && <p className="mt-3 text-sm text-slate-500">No earned contribution tokens yet.</p>}
        </section>
        {!selectedId && <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 text-sm text-slate-500">Select a post to inspect evidence, working artifacts, comments, and answers.</div>}
        {detail.isLoading && <div className="rounded-xl border border-slate-200 bg-white p-6 text-sm text-slate-500">Loading post…</div>}
        {detail.error && <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-6 text-sm text-red-700">{errorText(detail.error)}</div>}
        {post && <PostDetail post={post} me={me.data} comment={comment} answer={answer} onCommentChange={setComment} onAnswerChange={setAnswer} onClose={() => setSelectedId(null)} onComment={() => postComment.mutate(post.id)} onAnswer={() => postAnswer.mutate(post.id)} onVote={(value) => vote.mutate({ postId: post.id, value })} onClaim={() => claim.mutate(post.id)} onUpdateIssueStatus={(status) => updateIssueStatus.mutate({ postId: post.id, status })} onEdit={(payload) => editPost.mutate({ postId: post.id, payload })} onDelete={() => deletePost.mutate(post.id)} onAccept={(answerId) => {
          if (window.confirm("Accept this answer as the canonical answer?")) accept.mutate({ postId: post.id, answerId });
        }} />}
      </aside>
    </div>
  );
}

function PostDetail({ post, me, comment, answer, onCommentChange, onAnswerChange, onClose, onComment, onAnswer, onVote, onClaim, onUpdateIssueStatus, onEdit, onDelete, onAccept }: {
  post: NetworkPost;
  me: MeResponse | undefined;
  comment: string;
  answer: string;
  onCommentChange: (value: string) => void;
  onAnswerChange: (value: string) => void;
  onClose: () => void;
  onComment: () => void;
  onAnswer: () => void;
  onVote: (value: -1 | 1) => void;
  onClaim: () => void;
  onUpdateIssueStatus: (status: NetworkIssueStatus) => void;
  onEdit: (payload: NetworkPostEditPayload) => void;
  onDelete: () => void;
  onAccept: (answerId: number) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [editTitle, setEditTitle] = useState(post.title);
  const [editBody, setEditBody] = useState(post.body);
  const [editTags, setEditTags] = useState(post.tags.join(", "));
  const [editShowcaseUrl, setEditShowcaseUrl] = useState(post.showcase_url ?? "");
  const isAuthor = me?.employee_code === post.author.employee_code;
  const isAdmin = me?.role === "admin";
  const canManage = isAuthor || isAdmin;
  const canUpdateIssue = canManage || me?.employee_code === post.claimed_by?.employee_code;
  const canVote = me?.employee_code !== post.author.employee_code;

  function beginEdit() {
    setEditTitle(post.title);
    setEditBody(post.body);
    setEditTags(post.tags.join(", "));
    setEditShowcaseUrl(post.showcase_url ?? "");
    setEditing(true);
  }

  function saveEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const payload: NetworkPostEditPayload = { title: editTitle, body: editBody, tags: tagList(editTags) };
    if (post.kind === "showcase") payload.showcase_url = editShowcaseUrl;
    onEdit(payload);
    setEditing(false);
  }

  return (
    <article className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div><span className={`rounded-full px-2 py-1 text-xs font-medium ${post.kind === "answer" ? "bg-slate-100 text-slate-700" : kindTone[post.kind]}`}>{kindLabel[post.kind]}</span><h2 className="mt-3 text-xl font-semibold text-slate-900">{post.title}</h2></div>
        <button type="button" onClick={onClose} className="text-sm text-slate-500 hover:text-slate-900">Close</button>
      </div>
      {post.showcase_url && <a href={post.showcase_url} target="_blank" rel="noreferrer" className="mt-4 block rounded border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm font-medium text-emerald-800 hover:bg-emerald-100">Open showcase ↗</a>}
      <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-700">{post.body}</p>
      <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-slate-500"><span>{post.author.name}</span><span>▲ {post.score}</span><span>{formatTokens(post.contribution_tokens)} contribution tokens</span>{post.issue_status && <span className="rounded bg-slate-100 px-2 py-1">{post.issue_status}</span>}{post.claimed_by && <span>claimed by {post.claimed_by.name}</span>}</div>
      <div className="mt-4 flex flex-wrap gap-2"><button type="button" disabled={!canVote} onClick={() => onVote(1)} className="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 disabled:opacity-40">▲ Vote</button><button type="button" disabled={!canVote} onClick={() => onVote(-1)} className="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 disabled:opacity-40">▼</button>{post.kind === "issue" && !post.claimed_by && <button type="button" onClick={onClaim} className="rounded bg-amber-500 px-3 py-1.5 text-sm font-medium text-white">Claim issue</button>}{post.kind === "issue" && canUpdateIssue && <select aria-label="Issue status" value={post.issue_status ?? "open"} onChange={(event) => {
        const status = event.target.value as NetworkIssueStatus;
        if ((status === "resolved" || status === "closed") && !window.confirm(`Change this issue to ${status}?`)) return;
        onUpdateIssueStatus(status);
      }} className="rounded border border-slate-300 bg-white px-2 py-1.5 text-sm"><option value="open">open</option><option value="in_progress">in progress</option><option value="resolved">resolved</option><option value="closed">closed</option></select>}{canManage && <button type="button" onClick={beginEdit} className="rounded border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50">Edit</button>}{canManage && <button type="button" onClick={() => { if (window.confirm("Delete this post from the public network?")) onDelete(); }} className="rounded border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50">Delete</button>}</div>
      {editing && <form onSubmit={saveEdit} className="mt-5 space-y-3 rounded border border-slate-200 bg-slate-50 p-4"><h3 className="font-semibold text-slate-900">Edit post</h3><input value={editTitle} onChange={(event) => setEditTitle(event.target.value)} required maxLength={256} className="w-full rounded border border-slate-300 px-3 py-2 text-sm" />{post.kind === "showcase" && <input value={editShowcaseUrl} onChange={(event) => setEditShowcaseUrl(event.target.value)} required type="url" maxLength={2048} className="w-full rounded border border-slate-300 px-3 py-2 text-sm" />}<textarea value={editBody} onChange={(event) => setEditBody(event.target.value)} required maxLength={20_000} rows={4} className="w-full rounded border border-slate-300 px-3 py-2 text-sm" /><input value={editTags} onChange={(event) => setEditTags(event.target.value)} className="w-full rounded border border-slate-300 px-3 py-2 text-sm" placeholder="tags" /><div className="flex gap-2"><button className="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white">Save</button><button type="button" onClick={() => setEditing(false)} className="rounded border border-slate-300 px-3 py-2 text-sm">Cancel</button></div></form>}
      {post.kind === "question" && <section className="mt-6"><h3 className="font-semibold text-slate-900">Answers</h3><div className="mt-3 space-y-3">{post.answers.map((item) => <div key={item.id} className={`rounded border p-3 text-sm ${item.accepted ? "border-emerald-300 bg-emerald-50" : "border-slate-200"}`}><div className="flex justify-between gap-3"><span className="font-medium">{item.author.name}{item.accepted && " · Accepted"}</span>{!item.accepted && canManage && <button type="button" onClick={() => onAccept(item.id)} className="text-emerald-700 hover:underline">Accept</button>}</div><p className="mt-2 whitespace-pre-wrap text-slate-700">{item.body}</p><p className="mt-2 text-xs text-slate-500">{formatTokens(item.contribution_tokens)} contribution tokens</p></div>)}</div><textarea value={answer} onChange={(event) => onAnswerChange(event.target.value)} placeholder="Add a durable answer" rows={3} className="mt-3 w-full rounded border border-slate-300 px-3 py-2 text-sm" /><button type="button" disabled={!answer.trim()} onClick={onAnswer} className="mt-2 rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white disabled:opacity-50">Post answer</button></section>}
      <section className="mt-6"><h3 className="font-semibold text-slate-900">Comments</h3><div className="mt-3 space-y-3">{post.comments.map((item) => <div key={item.id} className="text-sm"><span className="font-medium text-slate-800">{item.author.name}</span><p className="mt-1 whitespace-pre-wrap text-slate-600">{item.body}</p><p className="mt-1 text-xs text-slate-500">{formatTokens(item.contribution_tokens)} contribution tokens</p></div>)}</div><textarea value={comment} onChange={(event) => onCommentChange(event.target.value)} placeholder="Add context or evidence" rows={3} className="mt-3 w-full rounded border border-slate-300 px-3 py-2 text-sm" /><button type="button" disabled={!comment.trim()} onClick={onComment} className="mt-2 rounded border border-slate-300 px-3 py-2 text-sm font-medium text-slate-800 disabled:opacity-50">Post comment</button></section>
    </article>
  );
}
