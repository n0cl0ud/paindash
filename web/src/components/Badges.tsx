import type { Exception, Exposure, Finding, Severity } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { JUSTIFICATION_LABEL } from "../lib/exceptions";
import { absDate, day, plural, SEV_BG, SEV_LABEL } from "../lib/format";
import { Icon } from "./Icon";

/** Swatch + word: severity is never conveyed by colour alone. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 text-xs font-medium text-ink-2", className)}>
      <span className={cx("size-2.5 shrink-0 rounded-[3px]", SEV_BG[severity])} aria-hidden="true" />
      {SEV_LABEL[severity]}
    </span>
  );
}

export function KevBadge({ addedAt }: { addedAt?: string | null }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded bg-kev px-1.5 py-px text-[11px] font-bold tracking-wide text-white"
      title={`Actively exploited (CISA KEV catalog)${addedAt ? `, added ${absDate(addedAt)}` : ""}`}
    >
      <Icon name="flame" className="size-3" />
      KEV
    </span>
  );
}

export function NewBadge() {
  return (
    <span className="rounded border border-accent/40 px-1.5 py-px text-[11px] font-semibold text-accent">
      new
    </span>
  );
}

const INTERNET_HINT = "Reachable from the internet (public Ingress class or Traefik entrypoint, or internet-facing LoadBalancer)";

/**
 * "Internet-facing" stands out, "internal" is discreet, "none" shows nothing.
 * Nothing at all without exposure data, rather than a misleading "none".
 */
export function ExposureBadge({ exposure, className }: { exposure: Exposure; className?: string }) {
  const { exposureAvailable } = useEnv();
  if (!exposureAvailable || exposure === "none") return null;
  if (exposure === "internal") {
    return (
      <span
        className={cx("rounded border border-line px-1.5 py-px text-[11px] font-medium text-muted", className)}
        title="Reachable through internal entrypoints or LoadBalancers only"
      >
        internal
      </span>
    );
  }
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded border border-accent/50 bg-accent-fill/15 px-1.5 py-px text-[11px] font-semibold whitespace-nowrap text-accent",
        className,
      )}
      title={INTERNET_HINT}
    >
      <Icon name="globe" className="size-3" />
      Internet-facing
    </span>
  );
}

/** Compact form for workload chips: a globe for internet-facing, nothing otherwise. */
export function ExposureMark({ exposure }: { exposure: Exposure }) {
  const { exposureAvailable } = useEnv();
  if (!exposureAvailable || exposure !== "internet") return null;
  return (
    // relative: keeps the sr-only text inside scrolling tables.
    <span title={INTERNET_HINT} className="relative inline-flex text-accent">
      <Icon name="globe" className="size-3" />
      <span className="sr-only">internet-facing</span>
    </span>
  );
}

export const SUSPECT_HINT =
  "Package named like the image but with a different major version than the image tag: likely misidentified";

export function SuspectBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-warn/50 bg-warn/15 px-1.5 py-px text-[11px] font-semibold text-warn-text"
      title={SUSPECT_HINT}
    >
      <Icon name="alert" className="size-3" />
      Suspect
    </span>
  );
}

/** Only for the heuristic source: the other ones come from package metadata. */
export function HeuristicBadge() {
  return (
    <span
      className="rounded border border-line-strong px-1.5 py-px text-[11px] font-medium text-ink-2"
      title="Identified from a version pattern in a binary, without package metadata: worth a second look"
    >
      heuristic
    </span>
  );
}

/** Markers of a doubtful identification; nothing for a well-identified finding. */
export function IdentificationBadges({ f }: { f: Pick<Finding, "suspect" | "source"> }) {
  return (
    <>
      {f.suspect && <SuspectBadge />}
      {f.source === "heuristic" && <HeuristicBadge />}
    </>
  );
}

/** "Excepted until Jan 20, 2027 by alice@example.com" */
export function ExceptionNote({ e, className }: { e: Exception; className?: string }) {
  return (
    <span
      className={cx("inline-flex items-center gap-1 text-xs text-muted", className)}
      title={`${JUSTIFICATION_LABEL[e.justification] ?? e.justification}: ${e.statement}`}
    >
      <Icon name="shieldOff" className="size-3.5 shrink-0" />
      Excepted until {day(e.expiresAt)} by {e.author}
    </span>
  );
}

/** "✓ already fixed in test → promote" */
export function PromotionHint({ envs, className }: { envs: string[]; className?: string }) {
  if (envs.length === 0) return null;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-md border border-good/40 bg-good/10 px-2 py-0.5 text-xs font-semibold text-good-text",
        className,
      )}
    >
      <Icon name="check" className="size-3.5" />
      already fixed in {envs.join(", ")}
      <Icon name="arrowRight" className="size-3.5" />
      promote
    </span>
  );
}

export function Delta({ added, removed, kev }: { added: number; removed: number; kev: number }) {
  return (
    <>
      {added > 0 && (
        <span
          className="rounded bg-bad/10 px-1.5 font-semibold tabular-nums text-bad-text"
          title={plural(added, "new vulnerability", "new vulnerabilities")}
        >
          +{added}
        </span>
      )}
      {removed > 0 && (
        <span
          className="rounded bg-good/10 px-1.5 font-semibold tabular-nums text-good-text"
          title={`${plural(removed, "vulnerability", "vulnerabilities")} fixed`}
        >
          −{removed}
        </span>
      )}
      {kev > 0 && (
        <span
          className="rounded bg-kev px-1.5 font-bold tabular-nums text-white"
          title={plural(kev, "actively exploited vulnerability", "actively exploited vulnerabilities")}
        >
          KEV +{kev}
        </span>
      )}
    </>
  );
}

/** A feature whose output and conventions may still change. */
export function ExperimentalBadge() {
  return (
    <span
      title="Experimental: the prompt and its conventions may change"
      className="rounded border border-line px-1.5 py-px text-[10px] font-semibold tracking-wide text-muted uppercase"
    >
      Experimental
    </span>
  );
}
