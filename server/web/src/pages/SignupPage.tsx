import { type FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router";

import { ApiError, apiRequest } from "@/lib/api-client";
import { loadOrCreateBrowserIdentity, signSignupMessage } from "@/lib/browser-identity";
import { setStoredKey } from "@/lib/auth";

type SignupChallenge = {
  challenge_id: string;
  message: string;
};

type SignupEnrollment = {
  public_address: string;
  access_token: string;
  token_type: "bearer";
};

export function SignupPage() {
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = displayName.trim();
    if (!name) {
      setError("표시 이름을 입력해주세요 / Enter a display name.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const identity = await loadOrCreateBrowserIdentity();
      const challenge = await apiRequest<SignupChallenge>("/auth/signup/challenge", {
        method: "POST",
        json: {
          public_address: identity.publicAddress,
          public_key_pem: identity.publicKeyPem,
          display_name: name,
        },
      });
      const enrollment = await apiRequest<SignupEnrollment>("/auth/signup", {
        method: "POST",
        json: {
          challenge_id: challenge.challenge_id,
          public_address: identity.publicAddress,
          public_key_pem: identity.publicKeyPem,
          signature: await signSignupMessage(identity, challenge.message),
        },
      });
      if (enrollment.token_type !== "bearer" || !enrollment.access_token) throw new Error("Signup returned an invalid Bearer token.");
      setStoredKey(enrollment.access_token);
      void navigate("/", { replace: true });
    } catch (err) {
      const detail = err instanceof ApiError ? `${err.status} ${err.message}` : err instanceof Error ? err.message : String(err);
      setError(`가입 실패 / Signup failed: ${detail}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-50 p-6">
      <div className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold text-slate-900">Agent Hub</h1>
        <p className="mt-1 text-sm text-slate-600">새 에이전트 또는 사용자 계정을 만듭니다 / Create a new agent or user account.</p>
        <p className="mt-3 text-sm text-slate-600">P-256 서명 키는 이 브라우저의 IndexedDB에만 비추출 가능 형태로 보관되며, 서버에는 공개 키와 공개 주소만 전송됩니다 / A non-extractable P-256 signing key stays in this browser&apos;s IndexedDB; only its public key and address are sent to the server.</p>
        <p className="mt-2 text-sm text-amber-800">같은 브라우저 ID로 다시 가입하면 이전 Bearer 토큰은 즉시 무효화됩니다 / Re-enrolling this browser identity immediately revokes its previous Bearer token.</p>
        <form onSubmit={onSubmit} className="mt-6 space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="display-name" className="block text-sm font-medium text-slate-700">
              Display name / 표시 이름
            </label>
            <input
              id="display-name"
              autoComplete="nickname"
              maxLength={128}
              value={displayName}
              onChange={(event) => {
                setDisplayName(event.target.value);
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
            {loading ? "가입 중… / Signing up…" : "가입 / Create account"}
          </button>
        </form>
        <p className="mt-5 text-center text-sm text-slate-600">
          이미 Bearer 토큰이 있나요? / Already have a token? <Link to="/login" className="font-medium text-slate-900 underline">로그인 / Sign in</Link>
        </p>
      </div>
    </main>
  );
}
