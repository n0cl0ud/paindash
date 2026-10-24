import type { Exposure } from "../api/types";
import { EXPOSURE_LABEL, EXPOSURES } from "./format";

/**
 * Restricts the dashboard to some namespaces, components (workloads) and/or
 * exposures, kept in the URL as
 * ?ns=checkout,catalog&wl=checkout/checkout-api&exp=internet. A workload is in
 * scope when its namespace is in `ns` (if any) AND its "namespace/name" is in
 * `wl` (if any) AND its exposure is in `exp` (if any). Lists are deduplicated
 * and sorted (exposures widest first), so that equal scopes give equal query
 * keys.
 */
export interface Scope {
  ns: string[];
  wl: string[]; // "namespace/name"
  exp: Exposure[];
}

export const NO_SCOPE: Scope = { ns: [], wl: [], exp: [] };

type Named = { namespace: string; name: string };

export const componentId = (w: Named) => `${w.namespace}/${w.name}`;
export const namespaceOf = (id: string) => id.slice(0, id.indexOf("/"));

const list = (raw: string | null, valid: (s: string) => boolean) =>
  [...new Set((raw ?? "").split(",").map((s) => s.trim()).filter(valid))].sort();

/** From the raw ?ns=, ?wl= and ?exp= values; malformed entries are dropped. */
export function parseScope(ns: string | null, wl: string | null, exp: string | null): Scope {
  const exps = new Set((exp ?? "").split(","));
  return {
    ns: list(ns, (s) => s !== "" && !s.includes("/")),
    wl: list(wl, (s) => /^[^/]+\/[^/]+$/.test(s)),
    exp: EXPOSURES.filter((e) => exps.has(e)),
  };
}

export const isScoped = (s: Scope) => s.ns.length > 0 || s.wl.length > 0 || s.exp.length > 0;

/** Stable string form, e.g. to reset per-view state when the scope changes. */
export const scopeKey = (s: Scope) => `${s.ns.join(",")}|${s.wl.join(",")}|${s.exp.join(",")}`;

/** `exposure` undefined (unknown workload) never matches an exposure scope. */
export function inScope(s: Scope, w: Named & { exposure?: Exposure }): boolean {
  return (
    (s.ns.length === 0 || s.ns.includes(w.namespace)) &&
    (s.wl.length === 0 || s.wl.includes(componentId(w))) &&
    (s.exp.length === 0 || (w.exposure !== undefined && s.exp.includes(w.exposure)))
  );
}

/**
 * Short description for headings: "checkout", "2 namespaces",
 * "checkout/checkout-api", "3 components", "internet-facing"… Components
 * narrow namespaces down (AND), so when some are selected they are what the
 * views show.
 */
export function scopeLabel(s: Scope): string {
  const parts: string[] = [];
  if (s.wl.length) parts.push(s.wl.length === 1 ? s.wl[0] : `${s.wl.length} components`);
  else if (s.ns.length) parts.push(s.ns.length === 1 ? s.ns[0] : `${s.ns.length} namespaces`);
  if (s.exp.length) parts.push(s.exp.map((e) => EXPOSURE_LABEL[e].toLowerCase()).join(" or "));
  return parts.join(", ");
}

/** Full description, for tooltips. */
export function scopeTitle(s: Scope): string {
  return [
    s.ns.length && `Namespaces: ${s.ns.join(", ")}`,
    s.wl.length && `Components: ${s.wl.join(", ")}`,
    s.exp.length && `Exposure: ${s.exp.map((e) => EXPOSURE_LABEL[e]).join(", ")}`,
  ]
    .filter(Boolean)
    .join(" · ");
}
