import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router";
import { ApiError, apiRequest } from "@/lib/api-client";
import { clearStoredKey, setStoredKey } from "@/lib/auth";
import type { MeResponse } from "@/api/types";

export function LoginPage() {
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function loginWith(value: string) {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("토큰을 입력해주세요");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const me = await apiRequest<MeResponse>("/me", { authToken: trimmed });
      setStoredKey(trimmed);
      void navigate("/", { replace: true, state: { name: me.name } });
    } catch (err) {
      clearStoredKey();
      const detail = err instanceof ApiError ? `${err.status} ${err.message}` : String(err);
      setError(`로그인 실패: ${detail}`);
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await loginWith(token);
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-50 p-6">
      <div className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold text-slate-900">Agent Hub</h1>
        <p className="mt-1 text-sm text-slate-600">발급받은 Agent Hub API 토큰을 입력하세요. 토큰은 이 브라우저 세션에서만 사용됩니다. / Enter an issued Agent Hub API token. It is used only in this browser session.</p>
        <form onSubmit={onSubmit} className="mt-6 space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="token" className="block text-sm font-medium text-slate-700">
              Bearer Token
            </label>
            <input
              id="token"
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder="agh_…"
              value={token}
              onChange={(event) => {
                setToken(event.target.value);
                if (error) setError(null);
              }}
              className="w-full rounded border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
            />
            {error ? <p role="alert" className="text-sm text-red-600">{error}</p> : null}
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
          >
            {loading ? "로그인 중…" : "로그인"}
          </button>
        </form>
        <p className="mt-5 text-center text-sm text-slate-600">
          토큰이 없나요? / Need an account? <Link to="/signup" className="font-medium text-slate-900 underline">가입 / Sign up</Link>
        </p>
      </div>
    </main>
  );
}
