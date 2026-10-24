import type { Exposure, Finding, WorkloadRef } from "../api/types";
import { EXPOSURE_RANK, SEV_RANK } from "./format";

export const findingKey = (f: Finding) =>
  `${f.vulnId}|${f.package.name}|${f.package.version}|${f.package.type}`;

/** KEV first, then severity, exposure (internet first), EPSS (desc), like the API; then blast radius. */
export function byPriority(a: Finding, b: Finding): number {
  return (
    Number(b.kev) - Number(a.kev) ||
    SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
    EXPOSURE_RANK[a.exposure] - EXPOSURE_RANK[b.exposure] ||
    (b.epss ?? -1) - (a.epss ?? -1) ||
    b.workloads.length - a.workloads.length ||
    a.vulnId.localeCompare(b.vulnId)
  );
}

/** Merge finding lists (same finding may come from several queries) and sort. */
export function mergeFindings(...lists: (Finding[] | undefined)[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const list of lists) for (const f of list ?? []) map.set(findingKey(f), f);
  return [...map.values()].sort(byPriority);
}

/**
 * "To fix": what the TODO_FIXABLE and TODO_KEV queries return, merged. Suspect
 * and excepted findings never belong there (the API leaves them out by
 * default; this guards the lists anyway).
 */
export function todoFindings(...lists: (Finding[] | undefined)[]): Finding[] {
  return mergeFindings(...lists).filter((f) => !f.suspect && !f.exception);
}

/** The "To fix" list of a workload: KEV, or Critical/High with a fix. */
export const isPriority = (f: Finding) =>
  !f.suspect &&
  !f.exception &&
  (f.kev || ((f.severity === "Critical" || f.severity === "High") && f.fixedIn.length > 0));

export const workloadKey = (w: WorkloadRef) => `${w.cluster}/${w.namespace}/${w.kind}/${w.name}`;

/** Affected containers collapsed to distinct workloads. */
export function uniqueWorkloads(f: Finding): (WorkloadRef & { exposure: Exposure })[] {
  const map = new Map<string, WorkloadRef & { exposure: Exposure }>();
  for (const w of f.workloads) {
    const k = workloadKey(w);
    if (!map.has(k)) {
      map.set(k, { cluster: w.cluster, namespace: w.namespace, kind: w.kind, name: w.name, exposure: w.exposure });
    }
  }
  return [...map.values()];
}

const enc = encodeURIComponent;
export const workloadPath = (w: WorkloadRef) =>
  `/workloads/${enc(w.cluster)}/${enc(w.namespace)}/${enc(w.kind)}/${enc(w.name)}`;

/** Envs where the vuln is already fixed, e.g. "test, dev". */
export function promotionEnvs(f: Finding): string[] {
  return [...new Set(f.promotion.map((p) => p.env))];
}
