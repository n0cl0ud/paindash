import type { Exception, FindingSource, VexJustification } from "../api/types";

const DAY = 86_400_000;

/** "Identified from: …" */
export const SOURCE_LABEL: Record<FindingSource, string> = {
  os: "OS package database",
  "build-info": "Go build info (binary metadata)",
  manifest: "language manifest",
  heuristic: "heuristic (version pattern in a binary)",
  unknown: "unknown",
};

export const JUSTIFICATION_LABEL: Record<VexJustification, string> = {
  component_not_present: "Component not present",
  vulnerable_code_not_present: "Vulnerable code not present",
  vulnerable_code_not_in_execute_path: "Vulnerable code not in execute path",
  vulnerable_code_cannot_be_controlled_by_adversary: "Vulnerable code cannot be controlled by an adversary",
  inline_mitigations_already_exist: "Inline mitigations already exist",
};

/** Where an exception applies: "All workloads", "checkout", "checkout/checkout-api". */
export function exceptionScope(e: Pick<Exception, "namespace" | "workload">): string {
  if (!e.namespace) return "All workloads";
  return e.workload ? `${e.namespace}/${e.workload}` : e.namespace;
}

/** Whole days left before `iso`, rounded up (0 once past). */
export function daysLeft(iso: string, now = Date.now()): number {
  return Math.max(0, Math.ceil((Date.parse(iso) - now) / DAY));
}

/** Local "YYYY-MM-DD" for a date input, `days` from today. */
export function dateInput(days: number, from = new Date()): string {
  const d = new Date(from.getFullYear(), from.getMonth(), from.getDate() + days);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
