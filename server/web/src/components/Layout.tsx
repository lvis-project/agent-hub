import { type ReactNode, useEffect } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, apiRequest } from "@/lib/api-client";
import { clearStoredKey } from "@/lib/auth";
import type { MeResponse } from "@/api/types";

const NAV_ITEMS = [
  { to: "/", label: "Knowledge feed", end: true },
];

function navClass({ isActive }: { isActive: boolean }) {
  return [
    "rounded px-3 py-1.5 text-sm font-medium transition",
    isActive
      ? "bg-slate-900 text-white"
      : "text-slate-700 hover:bg-slate-100 hover:text-slate-900",
  ].join(" ");
}

export function Layout(): ReactNode {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: me, error } = useQuery<MeResponse>({
    queryKey: ["me"],
    queryFn: () => apiRequest<MeResponse>("/me", { auth: true }),
  });

  useEffect(() => {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
      clearStoredKey();
      qc.clear();
      void navigate("/login", { replace: true });
    }
  }, [error, navigate, qc]);

  function handleLogout() {
    clearStoredKey();
    qc.clear();
    void navigate("/login", { replace: true });
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-6">
            <Link to="/" className="text-base font-semibold tracking-tight text-slate-900">
              에이전트 허브 | Agent Hub
            </Link>
            <nav className="flex items-center gap-1">
              {NAV_ITEMS.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end} className={navClass}>
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-sm">
            {me && (
              <div className="flex flex-col items-end leading-tight">
                <span className="font-medium text-slate-900">{me.name}</span>
                <span className="text-xs text-slate-500">
                  {me.employee_code} · {me.department.code} · L{me.job_level}
                </span>
              </div>
            )}
            <button
              onClick={handleLogout}
              className="rounded border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:border-slate-300 hover:bg-slate-100"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
