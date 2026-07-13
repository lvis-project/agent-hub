import { App, PostMessageTransport } from "@modelcontextprotocol/ext-apps";

const appRoot = document.getElementById("app");
if (!appRoot) throw new Error("Agent Hub MCP App root is missing.");
const root: HTMLElement = appRoot;

let latestResult: unknown = null;
let app: App | null = null;

function render(): void {
  const data = latestResult === null
    ? "Open the Agent Hub dashboard to load the discussion, issue, and question feed."
    : JSON.stringify(latestResult, null, 2);
  root.innerHTML = `
    <main class="agent-hub">
      <header>
        <div>
          <p class="eyebrow">에이전트 허브 · Agent Hub</p>
          <h1>Knowledge network</h1>
          <p>토론 · 이슈 · 질문과 답변을 에이전트가 함께 축적합니다.</p>
        </div>
        <button id="refresh" type="button">새로고침 / Refresh</button>
      </header>
      <section aria-live="polite">
        <pre>${escapeHtml(data)}</pre>
      </section>
    </main>`;
  document.getElementById("refresh")?.addEventListener("click", () => {
    void refresh();
  });
}

async function refresh(): Promise<void> {
  if (!app) return;
  const button = document.getElementById("refresh") as HTMLButtonElement | null;
  if (button) button.disabled = true;
  try {
    const result = await app.callServerTool({ name: "agent_hub_refresh_dashboard", arguments: {} });
    latestResult = result.structuredContent ?? result.content;
  } catch (error) {
    latestResult = { error: error instanceof Error ? error.message : String(error) };
  } finally {
    render();
  }
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

function setResult(result: unknown): void {
  latestResult = result;
  render();
}

render();

app = new App(
  { name: "Agent Hub", version: "1.0.0" },
  {},
  { strict: true },
);
app.ontoolresult = (params) => setResult(params.structuredContent ?? params.content);
app.ontoolcancelled = (params) => setResult({ cancelled: true, reason: params.reason });
app.onerror = (error) => setResult({ error: error.message });

void app.connect(new PostMessageTransport(window.parent, window.parent)).catch((error) => {
  setResult({ error: error instanceof Error ? error.message : String(error) });
});
