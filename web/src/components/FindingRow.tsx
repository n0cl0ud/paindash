import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import type { Finding } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { findingKey, promotionEnvs, uniqueWorkloads, workloadKey, workloadPath } from "../lib/findings";
import { ageMs, pct, SEV_BG } from "../lib/format";
import { useArrivals } from "../lib/useArrivals";
import { fixTargets } from "../lib/versions";
import {
  ExceptionNote,
  ExposureBadge,
  ExposureMark,
  IdentificationBadges,
  KevBadge,
  NewBadge,
  PromotionHint,
  SeverityBadge,
} from "./Badges";

const VISIBLE_WORKLOADS = 3;
const DAY = 86_400_000;

export function FixVersion({ f }: { f: Finding }) {
  return (
    <span className="font-mono text-[13px]">
      <span className="text-ink">{f.package.name}</span>{" "}
      <span className="text-ink-2">{f.package.version}</span>
      {f.fixedIn.length > 0 ? (
        <>
          <span className="px-1.5 text-muted">→</span>
          <span className="font-semibold text-good-text">{fixTargets(f.package.version, f.fixedIn).join(" / ")}</span>
        </>
      ) : (
        <span className="pl-2 font-sans text-xs text-muted">no fix</span>
      )}
    </span>
  );
}

function FindingRow({ f, fresh, onOpen }: { f: Finding; fresh: boolean; onOpen: () => void }) {
  const { envs, env, href } = useEnv();
  const [expanded, setExpanded] = useState(false);
  const workloads = uniqueWorkloads(f);
  const shown = expanded ? workloads : workloads.slice(0, VISIBLE_WORKLOADS);
  const showCluster = (envs.find((e) => e.name === env)?.clusters.length ?? 0) > 1;
  const promo = promotionEnvs(f);

  return (
    <li
      className={cx(
        "relative cursor-pointer border-b border-line py-3 pr-4 pl-5 last:border-b-0 hover:bg-surface-2",
        fresh && "animate-arrive",
        f.exception && "opacity-60",
      )}
      onClick={onOpen}
    >
      <span
        className={cx("absolute top-3 bottom-3 left-0 w-1 rounded-r", SEV_BG[f.severity])}
        aria-hidden="true"
      />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onOpen();
          }}
          className="font-mono text-sm font-semibold text-ink hover:underline"
        >
          {f.vulnId}
        </button>
        {f.kev && <KevBadge addedAt={f.kevAddedAt} />}
        <SeverityBadge severity={f.severity} />
        <span className="text-xs text-muted">
          CVSS <span className="font-medium tabular-nums text-ink-2">{f.cvss == null ? "—" : f.cvss.toFixed(1)}</span>
        </span>
        <span className="text-xs text-muted">
          EPSS <span className="font-medium tabular-nums text-ink-2">{f.epss == null ? "—" : pct(f.epss)}</span>
        </span>
        {ageMs(f.firstSeen) < DAY && <NewBadge />}
        <ExposureBadge exposure={f.exposure} />
        <IdentificationBadges f={f} />
        {f.exception ? (
          <ExceptionNote e={f.exception} className="sm:ml-auto" />
        ) : (
          promo.length > 0 && <PromotionHint envs={promo} className="sm:ml-auto" />
        )}
      </div>
      <div className="mt-1">
        <FixVersion f={f} />
      </div>
      {workloads.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs">
          {shown.map((w) => (
            <Link
              key={workloadKey(w)}
              to={href(workloadPath(w))}
              onClick={(e) => e.stopPropagation()}
              title={`${w.kind} ${w.namespace}/${w.name} on ${w.cluster}`}
              className="inline-flex items-center gap-1 rounded border border-line bg-page px-1.5 py-0.5 font-mono text-ink-2 hover:border-line-strong hover:text-ink"
            >
              <ExposureMark exposure={w.exposure} />
              {w.namespace}/{w.name}
              {showCluster && <span className="font-sans text-muted"> · {w.cluster}</span>}
            </Link>
          ))}
          {workloads.length > VISIBLE_WORKLOADS && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setExpanded((x) => !x);
              }}
              className="rounded px-1.5 py-0.5 font-medium text-accent hover:bg-accent-fill/10"
            >
              {expanded ? "show less" : `+${workloads.length - VISIBLE_WORKLOADS} more`}
            </button>
          )}
        </div>
      )}
    </li>
  );
}

/** Prioritised finding rows; rows added by a live refresh slide in highlighted. */
export function FindingList({
  findings,
  onOpen,
  empty,
}: {
  findings: Finding[];
  onOpen: (f: Finding) => void;
  empty: ReactNode;
}) {
  const { viewKey } = useEnv();
  const keys = findings.map(findingKey);
  const isNew = useArrivals(keys, viewKey);
  if (findings.length === 0) return <>{empty}</>;
  return (
    <ul>
      {findings.map((f, i) => (
        <FindingRow key={keys[i]} f={f} fresh={isNew(keys[i])} onOpen={() => onOpen(f)} />
      ))}
    </ul>
  );
}
