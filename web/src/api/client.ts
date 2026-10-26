import { queryOptions, type QueryClient } from "@tanstack/react-query";
import type { Scope } from "../lib/scope";
import {
  SEVERITIES,
  type AffectedContainer,
  type EventsResponse,
  type Exception,
  type ExceptionInput,
  type ExceptionsResponse,
  type Finding,
  type FindingsResponse,
  type HistoryResponse,
  type ImagesResponse,
  type OriginsResponse,
  type Meta,
  type Severity,
  type Summary,
  type Workload,
  type WorkloadDetail,
  type WorkloadRef,
  type WorkloadsResponse,
} from "./types";

// --- Session expiry -----------------------------------------------------------
// An ended session comes back as a 401 (paindash's own sessions, oidc and
// local), or as a redirect or an HTML page instead of JSON (Pomerium, 14 h
// after login). Any such answer flips this flag. A page load is all it takes
// to renew it (a silent login at the identity provider, or the sign-in form),
// so the page reloads by itself, at most once a minute (a broken login must
// not loop) and never while a form is open; else the UI shows a reload banner.

let sessionExpired = false;
const listeners = new Set<() => void>();
let holds = 0;
const RELOADED_AT = "paindash:session-reload";

/** Keeps the page from reloading by itself while a form is open; returns the release. */
export function holdReload(): () => void {
  holds++;
  return () => {
    holds--;
  };
}

function autoReload(): boolean {
  if (holds > 0) return false;
  try {
    if (Date.now() - Number(sessionStorage.getItem(RELOADED_AT) ?? 0) < 60_000) return false;
    sessionStorage.setItem(RELOADED_AT, String(Date.now()));
  } catch {
    return false; // no storage: no loop guard, keep the banner
  }
  window.location.reload();
  return true;
}

export function markSessionExpired() {
  if (sessionExpired) return;
  sessionExpired = true;
  if (autoReload()) return;
  listeners.forEach((l) => l());
}

export const sessionStore = {
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  get: () => sessionExpired,
};

export class SessionExpiredError extends Error {
  constructor() {
    super("Session expired");
  }
}

export class ApiError extends Error {
  readonly status: number;
  /** The server's own words ({"error": "..."} body), "" if none. */
  readonly detail: string;
  constructor(status: number, message: string, detail = "") {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...init.headers },
    credentials: "same-origin",
    // A redirect means the auth proxy wants a new login: do not follow it.
    redirect: "manual",
  });
  // A JSON 403 is paindash itself refusing (a read-only user): an error, not
  // an ended session like a 401 or the HTML 403 of an auth proxy.
  const json = (res.headers.get("content-type") ?? "").includes("json");
  if (res.type === "opaqueredirect" || res.status === 401 || (res.status === 403 && !json)) {
    markSessionExpired();
    throw new SessionExpiredError();
  }
  if (!res.ok) {
    const body = json ? ((await res.json().catch(() => null)) as { error?: string } | null) : null;
    throw new ApiError(res.status, `${res.status} ${res.statusText}`.trim(), body?.error ?? "");
  }
  if (!json) {
    markSessionExpired();
    throw new SessionExpiredError();
  }
  try {
    return (await res.json()) as T;
  } catch {
    markSessionExpired();
    throw new SessionExpiredError();
  }
}

const getJson = <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal });

const postJson = <T>(path: string, body?: unknown) =>
  request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

function qs(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") sp.set(k, String(v));
  }
  return sp.toString();
}

// --- Normalisation ---------------------------------------------------------------
// Defensive against Go encoding: nil slices arrive as null and sparse maps
// omit keys. Normalise once here so components can trust the contract.

const arr = <T>(a: T[] | null | undefined): T[] => a ?? [];

const counts = (c: Partial<Record<Severity, number>> | null | undefined) =>
  Object.fromEntries(SEVERITIES.map((s) => [s, c?.[s] ?? 0])) as Record<Severity, number>;

const container = (c: AffectedContainer): AffectedContainer => ({ ...c, exposure: c.exposure ?? "none" });

const finding = (f: Finding): Finding => ({
  ...f,
  aliases: arr(f.aliases),
  fixedIn: arr(f.fixedIn),
  exposure: f.exposure ?? "none",
  workloads: arr(f.workloads).map(container),
  promotion: arr(f.promotion),
  source: f.source ?? "unknown",
  location: f.location ?? "",
  suspect: Boolean(f.suspect),
  exception: f.exception ?? null,
});

const workload = (w: Workload): Workload => ({
  ...w,
  exposure: w.exposure ?? "none",
  containers: arr(w.containers),
  counts: counts(w.counts),
});

// --- Fetchers -------------------------------------------------------------------

/** Images listed by /api/images: "pending" also returns the ones being scanned. */
export type ScanFilter = "failed" | "pending";

/** Findings left out of /api/findings unless asked for (include=suspect,excepted). */
export type FindingInclude = "suspect" | "excepted";

export interface FindingsFilter {
  include?: FindingInclude[];
  severity?: Severity[];
  kev?: boolean;
  fixable?: boolean;
  q?: string;
  limit?: number;
}

const enc = encodeURIComponent;

// ?ns=a,b&wl=ns/name,…&exp=internet,… (omitted when empty).
const scopeParams = (s: Scope) => ({ ns: s.ns.join(","), wl: s.wl.join(","), exp: s.exp.join(",") });

export const api = {
  meta: (signal?: AbortSignal) =>
    getJson<Meta>("/api/meta", signal).then((m) => ({
      ...m,
      envs: arr(m.envs).map((e) => ({ ...e, clusters: arr(e.clusters) })),
      user: m.user ? { ...m.user, groups: arr(m.user.groups) } : null,
      exposureAvailable: Boolean(m.exposureAvailable),
      gitopsRepo: m.gitopsRepo ?? "",
      promotion: arr(m.promotion),
      authDisabled: Boolean(m.authDisabled),
    })),
  summary: (env: string, scope: Scope, signal?: AbortSignal) =>
    getJson<Summary>(`/api/summary?${qs({ env, ...scopeParams(scope) })}`, signal).then((s) => ({
      ...s,
      bySeverity: counts(s.bySeverity),
      internetAffected: s.internetAffected ?? 0,
      highFixableInternet: s.highFixableInternet ?? 0,
      suspect: s.suspect ?? 0,
      excepted: s.excepted ?? 0,
      exceptionsExpiring: s.exceptionsExpiring ?? 0,
    })),
  findings: (env: string, f: FindingsFilter, scope: Scope, signal?: AbortSignal) =>
    getJson<FindingsResponse>(
      `/api/findings?${qs({
        env,
        ...scopeParams(scope),
        severity: f.severity?.length ? f.severity.join(",") : undefined,
        kev: f.kev ? 1 : undefined,
        fixable: f.fixable ? 1 : undefined,
        q: f.q?.trim(),
        include: f.include?.length ? f.include.join(",") : undefined,
        limit: f.limit,
      })}`,
      signal,
    ).then((r) => ({ ...r, items: arr(r.items).map(finding) })),
  workloads: (env: string, scope: Scope, signal?: AbortSignal) =>
    getJson<WorkloadsResponse>(`/api/workloads?${qs({ env, ...scopeParams(scope) })}`, signal).then((r) => ({
      items: arr(r.items).map(workload),
    })),
  workload: (w: WorkloadRef, signal?: AbortSignal) =>
    getJson<WorkloadDetail>(
      `/api/workloads/${enc(w.cluster)}/${enc(w.namespace)}/${enc(w.kind)}/${enc(w.name)}`,
      signal,
    ).then((r) => ({ workload: workload(r.workload), findings: arr(r.findings).map(finding) })),
  images: (env: string, status: ScanFilter, scope: Scope, signal?: AbortSignal) =>
    getJson<ImagesResponse>(`/api/images?${qs({ env, status, ...scopeParams(scope) })}`, signal).then((r) => ({
      items: arr(r.items).map((i) => ({ ...i, workloads: arr(i.workloads).map(container) })),
    })),
  origins: (signal?: AbortSignal) =>
    getJson<OriginsResponse>("/api/origins", signal).then((r) => r.items ?? {}),
  exceptions: (signal?: AbortSignal) =>
    getJson<ExceptionsResponse>("/api/exceptions", signal).then((r) => ({ items: arr(r.items) })),
  /** The author is taken from the Pomerium identity server-side, never sent. */
  createException: (input: ExceptionInput) => postJson<Exception>("/api/exceptions", input),
  revokeException: (id: number) => postJson<Exception>(`/api/exceptions/${id}/revoke`),
  history: (days: number, scope: Scope, signal?: AbortSignal) =>
    getJson<HistoryResponse>(`/api/history?${qs({ days, ...scopeParams(scope) })}`, signal).then((r) => ({
      ...r,
      // Go encodes "no point yet" as the zero time.
      start: r.start && !r.start.startsWith("0001-") ? r.start : null,
      envs: Object.fromEntries(
        Object.entries(r.envs ?? {}).map(([env, ps]) => [env, arr(ps).map((p) => ({ ...p, changes: arr(p.changes) }))]),
      ),
      scopedSince: r.scopedSince ?? null,
    })),
  events: (env: string, limit: number, signal?: AbortSignal) =>
    getJson<EventsResponse>(`/api/events?${qs({ env, limit })}`, signal).then((r) => ({
      items: arr(r.items),
    })),
};

// --- Query options ------------------------------------------------------------------
// Every env-scoped key starts with [family, env] so that an SSE "invalidate"
// message maps to invalidateQueries({ queryKey: [family, env] }) (the stream
// calls these families "scopes"). Queries restricted to namespaces/components
// carry the Scope after env (and after the filter): one cache entry per scope.

export const EVENTS_LIMIT = 50;
export const FEED_CAP = 200;
export const TODO_LIMIT = 500;

export const queries = {
  meta: () =>
    queryOptions({
      queryKey: ["meta"],
      queryFn: ({ signal }) => api.meta(signal),
      refetchInterval: 5 * 60_000,
    }),
  summary: (env: string, scope: Scope) =>
    queryOptions({
      queryKey: ["summary", env, scope],
      queryFn: ({ signal }) => api.summary(env, scope, signal),
    }),
  findings: (env: string, f: FindingsFilter, scope: Scope) =>
    queryOptions({
      queryKey: ["findings", env, f, scope],
      queryFn: ({ signal }) => api.findings(env, f, scope, signal),
    }),
  /** Pass NO_SCOPE for the full list of the env (e.g. the scope pickers). */
  workloads: (env: string, scope: Scope) =>
    queryOptions({
      queryKey: ["workloads", env, scope],
      queryFn: ({ signal }) => api.workloads(env, scope, signal),
    }),
  workload: (env: string, w: WorkloadRef) =>
    queryOptions({
      // Not a "workloads" key on purpose: a detail depends on both the
      // "findings" and "workloads" scopes, the stream invalidates it for either.
      queryKey: ["workload", env, w.cluster, w.namespace, w.kind, w.name],
      queryFn: ({ signal }) => api.workload(w, signal),
    }),
  images: (env: string, status: ScanFilter, scope: Scope) =>
    queryOptions({
      // No "images" family on the stream: invalidated along with "summary".
      queryKey: ["images", env, status, scope],
      queryFn: ({ signal }) => api.images(env, status, scope, signal),
    }),
  /** Not env-scoped: digest -> origin over all envs, for the fix prompts. */
  origins: () =>
    queryOptions({
      queryKey: ["origins"],
      queryFn: ({ signal }) => api.origins(signal),
      staleTime: 5 * 60_000,
    }),
  /** Not env-scoped: exceptions apply to every env. */
  exceptions: () =>
    queryOptions({
      queryKey: ["exceptions"],
      queryFn: ({ signal }) => api.exceptions(signal),
    }),
  /** Every env at once (the chart compares them); 0 days = all. */
  history: (days: number, scope: Scope) =>
    queryOptions({
      // Not env-scoped: invalidated along with any "summary".
      queryKey: ["history", days, scope],
      queryFn: ({ signal }) => api.history(days, scope, signal),
      refetchInterval: 5 * 60_000,
    }),
  events: (env: string) =>
    queryOptions({
      queryKey: ["events", env],
      queryFn: ({ signal }) => api.events(env, EVENTS_LIMIT, signal),
      // Kept fresh by the SSE stream (live events are prepended to the cache).
      staleTime: Infinity,
    }),
};

// "To fix" = Critical/High with a fix + anything in CISA KEV.
export const TODO_FIXABLE: FindingsFilter = {
  severity: ["Critical", "High"],
  fixable: true,
  limit: TODO_LIMIT,
};
export const TODO_KEV: FindingsFilter = { kev: true, limit: TODO_LIMIT };

/** For auditors: every exception as one OpenVEX document. */
export const OPENVEX_URL = "/api/exceptions/openvex";

/**
 * After creating or revoking an exception: what it hides (or shows again)
 * changes in every env, not only the selected one.
 */
export function invalidateExceptionViews(qc: QueryClient) {
  for (const family of ["exceptions", "findings", "summary", "workloads", "workload"]) {
    void qc.invalidateQueries({ queryKey: [family] });
  }
}
