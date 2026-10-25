import { createContext, use } from "react";
import type { LiveStatus } from "../api/stream";
import type { EnvInfo } from "../api/types";
import type { Scope } from "./scope";

export interface EnvCtx {
  env: string;
  envs: EnvInfo[];
  /** Namespaces / components / exposures the views are restricted to (?ns=, ?wl=, ?exp=). */
  scope: Scope;
  /** Replaces the scope in the URL, on the current view and env. */
  setScope: (scope: Scope) => void;
  /** Same path, with the current ?env=, ?ns=, ?wl= and ?exp= appended. */
  href: (path: string) => string;
  /** Env + scope as a string: what the views show. Live highlights reset when it changes. */
  viewKey: string;
  /** State of the SSE stream for this env. */
  live: LiveStatus;
  /** Meta.exposureAvailable: when false, no exposure badge, scope or KPI is shown. */
  exposureAvailable: boolean;
  /** Meta.user.canEdit (true without authentication): exceptions can be recorded and revoked. */
  canEdit: boolean;
}

export const EnvContext = createContext<EnvCtx | null>(null);

export function useEnv(): EnvCtx {
  const ctx = use(EnvContext);
  if (!ctx) throw new Error("useEnv outside EnvContext");
  return ctx;
}

/** URLSearchParams.toString(), keeping "," and "/" readable: ?wl=checkout/checkout-api,storefront/storefront. */
export function searchString(sp: URLSearchParams): string {
  return sp.toString().replace(/%2C/gi, ",").replace(/%2F/gi, "/");
}

/**
 * Sets ?env= (and ?ns= / ?wl= / ?exp= when a scope is given, removed when
 * empty) on a path or a search string. Other params are kept.
 */
export function withEnv(path: string, env: string, scope?: Scope): string {
  const [base, query = ""] = path.split("?");
  const sp = new URLSearchParams(query);
  sp.set("env", env);
  if (scope) {
    for (const [k, v] of [["ns", scope.ns], ["wl", scope.wl], ["exp", scope.exp]] as const) {
      if (v.length) sp.set(k, v.join(","));
      else sp.delete(k);
    }
  }
  return `${base}?${searchString(sp)}`;
}
