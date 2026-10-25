import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router";
import { queries, TODO_FIXABLE, TODO_KEV } from "./api/client";
import { useLiveStream } from "./api/stream";
import type { Meta } from "./api/types";
import { KpiRow } from "./components/KpiRow";
import { HistoryPanel } from "./components/HistoryPanel";
import { ScansProvider } from "./components/ScansDrawer";
import { ScopeBar } from "./components/ScopeBar";
import { SessionBanner } from "./components/SessionBanner";
import { EmptyState, ErrorState } from "./components/States";
import { TopBar } from "./components/TopBar";
import { EnvContext, withEnv, type EnvCtx } from "./lib/env";
import { parseScope, scopeKey, type Scope } from "./lib/scope";
import { ExceptionsView } from "./views/ExceptionsView";
import { FindingsView } from "./views/FindingsView";
import { TodoView } from "./views/TodoView";
import { WorkloadDetailView } from "./views/WorkloadDetailView";
import { WorkloadsView } from "./views/WorkloadsView";

export default function App() {
  const meta = useQuery(queries.meta());
  return (
    <>
      <SessionBanner />
      {meta.data ? (
        <Shell meta={meta.data} />
      ) : (
        <div className="grid min-h-[80vh] place-items-center px-4">
          {meta.isError ? (
            <ErrorState error={meta.error} onRetry={() => void meta.refetch()} />
          ) : (
            <div className="flex flex-col items-center gap-3 text-muted" role="status">
              <span className="text-2xl font-bold tracking-tight text-ink">paindash</span>
              <span className="h-1 w-24 animate-pulse rounded-full bg-surface-2" />
              <span className="text-sm">Loading…</span>
            </div>
          )}
        </div>
      )}
    </>
  );
}

function Shell({ meta }: { meta: Meta }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();

  const names = useMemo(() => meta.envs.map((e) => e.name), [meta.envs]);
  const search = new URLSearchParams(location.search);
  const raw = search.get("env");
  const env = raw && names.includes(raw) ? raw : (names[0] ?? ""); // PAINDASH_ENVS order
  const rawNs = search.get("ns");
  const rawWl = search.get("wl");
  const rawExp = search.get("exp");
  const exposureAvailable = meta.exposureAvailable;
  // Without exposure data every workload would be "none": ignore ?exp= then.
  const scope = useMemo(
    () => parseScope(rawNs, rawWl, exposureAvailable ? rawExp : null),
    [rawNs, rawWl, rawExp, exposureAvailable],
  );
  const onWorkloadPage = location.pathname.startsWith("/workloads/");
  // Exceptions apply to every env: no KPIs nor scope bar there (?env= and the
  // scope stay in the URL for the other tabs).
  const onExceptions = location.pathname === "/exceptions";

  // Keep ?env= in the URL so that every view is a shareable link.
  useEffect(() => {
    if (env && raw !== env) {
      navigate({ pathname: location.pathname, search: withEnv(location.search, env) }, { replace: true });
    }
  }, [env, raw, location.pathname, location.search, navigate]);

  const setEnv = useCallback(
    (next: string) => {
      if (next === env) return;
      // A workload belongs to one env: from a workload page go back to the list.
      // The scope is kept (?ns= and ?wl= stay in the search string).
      const pathname = onWorkloadPage ? "/workloads" : location.pathname;
      navigate({ pathname, search: withEnv(location.search, next) });
    },
    [env, onWorkloadPage, location.pathname, location.search, navigate],
  );

  // Like the view filters, scope edits replace the history entry.
  const setScope = useCallback(
    (next: Scope) =>
      navigate({ pathname: location.pathname, search: withEnv(location.search, env, next) }, { replace: true }),
    [env, location.pathname, location.search, navigate],
  );

  const prefetch = useCallback(
    (name: string) => {
      void qc.prefetchQuery(queries.summary(name, scope));
      void qc.prefetchQuery(queries.findings(name, TODO_FIXABLE, scope));
      void qc.prefetchQuery(queries.findings(name, TODO_KEV, scope));
      void qc.prefetchQuery(queries.events(name));
    },
    [qc, scope],
  );

  // Warm the cache of the other envs (current scope) so that switching is instant.
  useEffect(() => {
    const t = window.setTimeout(() => names.filter((n) => n !== env).forEach(prefetch), 1500);
    return () => window.clearTimeout(t);
  }, [names, env, prefetch]);

  // Keys 1..9 switch env (ignored while typing).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey || e.repeat) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      if (document.querySelector('[role="dialog"]')) return;
      const i = Number(e.key) - 1;
      if (Number.isInteger(i) && i >= 0 && i < names.length) setEnv(names[i]);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [names, setEnv]);

  useEffect(() => {
    document.title = env ? `${env} · paindash` : "paindash";
  }, [env]);

  const live = useLiveStream(env);
  const canEdit = !meta.user || meta.user.canEdit;
  const ctx = useMemo<EnvCtx>(
    () => ({
      env,
      envs: meta.envs,
      scope,
      setScope,
      href: (path) => withEnv(path, env, scope),
      viewKey: `${env}|${scopeKey(scope)}`,
      live,
      exposureAvailable,
      canEdit,
    }),
    [env, meta.envs, scope, setScope, live, exposureAvailable, canEdit],
  );

  if (!env) {
    return (
      <EmptyState icon="box" title="No environment configured">
        The backend declared no environment (prod, test, dev…).
      </EmptyState>
    );
  }

  return (
    <EnvContext value={ctx}>
      <ScansProvider>
        <TopBar meta={meta} live={live} onEnvChange={setEnv} onEnvHover={prefetch} />
        <main className="mx-auto max-w-[1600px] space-y-5 px-4 py-5 sm:px-6">
          {!onWorkloadPage && !onExceptions && <ScopeBar />}
          {!onExceptions && <KpiRow />}
          {!onExceptions && !onWorkloadPage && <HistoryPanel />}
          <Routes>
            <Route path="/" element={<TodoView />} />
            <Route path="/workloads" element={<WorkloadsView />} />
            <Route path="/workloads/:cluster/:namespace/:kind/:name" element={<WorkloadDetailView />} />
            <Route path="/vulns" element={<FindingsView />} />
            <Route path="/exceptions" element={<ExceptionsView />} />
            <Route path="*" element={<Navigate to={ctx.href("/")} replace />} />
          </Routes>
        </main>
      </ScansProvider>
    </EnvContext>
  );
}
