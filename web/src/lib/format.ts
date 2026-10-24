import { useEffect, useState } from "react";
import type { Exposure, Severity } from "../api/types";

export const SEV_LABEL: Record<Severity, string> = {
  Critical: "Critical",
  High: "High",
  Medium: "Medium",
  Low: "Low",
  Negligible: "Negligible",
  Unknown: "Unknown",
};

/** Widest first. */
export const EXPOSURES: Exposure[] = ["internet", "internal", "none"];

export const EXPOSURE_LABEL: Record<Exposure, string> = {
  internet: "Internet-facing",
  internal: "Internal",
  none: "Not exposed",
};

export const EXPOSURE_RANK: Record<Exposure, number> = { internet: 0, internal: 1, none: 2 };

export const SEV_RANK: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Negligible: 4,
  Unknown: 5,
};

// Static class names so Tailwind picks them up.
export const SEV_BG: Record<Severity, string> = {
  Critical: "bg-sev-critical",
  High: "bg-sev-high",
  Medium: "bg-sev-medium",
  Low: "bg-sev-low",
  Negligible: "bg-sev-none",
  Unknown: "bg-sev-none",
};

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto", style: "narrow" });
const dtf = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
const dayFmt = new Intl.DateTimeFormat("en", { dateStyle: "medium" });
const intFmt = new Intl.NumberFormat("en");
const pctFmt = new Intl.NumberFormat("en", { style: "percent", maximumFractionDigits: 1 });
const pctSmallFmt = new Intl.NumberFormat("en", { style: "percent", maximumFractionDigits: 2 });
const compactFmt = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const ordinalRules = new Intl.PluralRules("en", { type: "ordinal" });
const ORDINAL: Partial<Record<Intl.LDMLPluralRule, string>> = { one: "st", two: "nd", few: "rd" };

/** "12s ago", "2h ago", "yesterday"… */
export function relTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = (t - now) / 1000;
  const a = Math.abs(s);
  if (a < 5) return "just now";
  if (a < 60) return rtf.format(Math.round(s), "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86_400) return rtf.format(Math.round(s / 3600), "hour");
  if (a < 30 * 86_400) return rtf.format(Math.round(s / 86_400), "day");
  if (a < 365 * 86_400) return rtf.format(Math.round(s / (30 * 86_400)), "month");
  return rtf.format(Math.round(s / (365 * 86_400)), "year");
}

export function absDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "—" : dtf.format(t);
}

/** Date only: "Jan 20, 2027". */
export function day(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "—" : dayFmt.format(t);
}

export function ageMs(iso: string | null | undefined, now: number = Date.now()): number {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? Infinity : now - t;
}

/** EPSS probability (0..1) as a percentage: "94.2%", "0.04%". */
export function pct(p: number | null | undefined): string {
  if (p == null) return "—";
  return (p >= 0.01 ? pctFmt : pctSmallFmt).format(p);
}

export const int = (n: number) => intFmt.format(n);
/** "1 image", "3 images"; irregular plurals are passed: plural(n, "vulnerability", "vulnerabilities"). */
export const plural = (n: number, one: string, many = `${one}s`) => `${intFmt.format(n)} ${n === 1 ? one : many}`;
/** "1st", "2nd", "94th". */
export const ordinal = (n: number) => `${n}${ORDINAL[ordinalRules.select(n)] ?? "th"}`;
export const compact = (n: number) => (n < 10_000 ? intFmt.format(n) : compactFmt.format(n));

export function shortDigest(d: string): string {
  const hex = d.replace(/^sha256:/, "");
  return hex.slice(0, 12);
}

/** Re-renders the caller every `ms` and returns the current time. */
export function useNow(ms = 5000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(id);
  }, [ms]);
  return now;
}
