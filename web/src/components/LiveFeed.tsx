import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { useNavigate } from "react-router";
import { queries } from "../api/client";
import type { Exposure } from "../api/types";
import type { LiveEvent, LiveEventType } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { workloadKey, workloadPath } from "../lib/findings";
import { absDate, plural, relTime, useNow } from "../lib/format";
import { inScope, isScoped, NO_SCOPE, scopeLabel } from "../lib/scope";
import { useArrivals } from "../lib/useArrivals";
import { Delta, SeverityBadge } from "./Badges";
import { Icon, type IconName } from "./Icon";
import { useShowScans } from "./ScansDrawer";
import { EmptyState, ErrorState, Skeleton } from "./States";

export const EVENT_TYPES: Record<LiveEventType, { icon: IconName; label: string; tone: string }> = {
  deployed: { icon: "deploy", label: "Deployed", tone: "bg-accent-fill/15 text-accent" },
  removed: { icon: "removed", label: "Removed", tone: "bg-surface-2 text-muted" },
  scan_completed: { icon: "scanOk", label: "Scan completed", tone: "bg-surface-2 text-muted" },
  scan_failed: { icon: "scanFail", label: "Scan failed", tone: "bg-warn/20 text-warn-text" },
  vulns_new: { icon: "vulnNew", label: "New vulnerabilities", tone: "bg-bad/15 text-bad-text" },
  vulns_fixed: { icon: "vulnFixed", label: "Vulnerabilities fixed", tone: "bg-good/15 text-good-text" },
  kev_added: { icon: "flame", label: "Added to CISA KEV", tone: "bg-kev text-white" },
  db_updated: { icon: "database", label: "CVE DB updated", tone: "bg-accent-fill/15 text-accent" },
  exception_added: { icon: "shieldOff", label: "Exception added", tone: "bg-surface-2 text-ink-2" },
  exception_revoked: { icon: "undo", label: "Exception revoked", tone: "bg-warn/20 text-warn-text" },
  exception_expired: { icon: "clock", label: "Exception expired (back in the lists)", tone: "bg-warn/20 text-warn-text" },
};

const isExceptionEvent = (t: LiveEventType) =>
  t === "exception_added" || t === "exception_revoked" || t === "exception_expired";

export const EVENT_FALLBACK = { icon: "alert", label: "Event", tone: "bg-surface-2 text-muted" } as const;

function FeedItem({ ev, now, fresh }: { ev: LiveEvent; now: number; fresh: boolean }) {
  const { href } = useEnv();
  const navigate = useNavigate();
  const showScans = useShowScans();
  const t = EVENT_TYPES[ev.type] ?? EVENT_FALLBACK;
  // Exception events open the Exceptions tab, workload events the workload
  // page, an image-level scan failure the failed scans.
  const wl = ev.workload;
  const open = isExceptionEvent(ev.type)
    ? () => navigate(href("/exceptions"))
    : wl
      ? () => navigate(href(workloadPath(wl)))
      : ev.type === "scan_failed"
        ? () => showScans("failed")
        : null;

  const body = (
    <>
      <span
        className={cx("mt-0.5 grid size-7 shrink-0 place-items-center rounded-full", t.tone)}
        title={t.label}
      >
        <Icon name={t.icon} className="size-3.5" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm leading-snug text-ink">{ev.title}</span>
        <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
          <time dateTime={ev.ts} title={absDate(ev.ts)} className="tabular-nums">
            {relTime(ev.ts, now)}
          </time>
          {ev.cluster && <span>· {ev.cluster}</span>}
          {ev.severity && ev.type === "vulns_new" && <SeverityBadge severity={ev.severity} />}
          {ev.delta && <Delta {...ev.delta} />}
        </span>
      </span>
    </>
  );

  return (
    <li className={cx("border-b border-line last:border-b-0", fresh && "animate-arrive")}>
      {open ? (
        <button type="button" onClick={open} className="flex w-full gap-3 px-4 py-2.5 text-left hover:bg-surface-2">
          {body}
        </button>
      ) : (
        <div className="flex gap-3 px-4 py-2.5">{body}</div>
      )}
    </li>
  );
}

/**
 * "Live": recent events, then SSE "live" events prepended (see api/stream.ts).
 * Events are not scoped server-side: env-wide ones (no workload: DB updates,
 * scan progress…) are always shown, workload ones only when in scope. Their
 * exposure comes from the env's workload list (the one the scope pickers use).
 */
export function LiveFeed({ className }: { className?: string }) {
  const { env, scope, viewKey, live } = useEnv();
  const { data, isPending, error, refetch } = useQuery(queries.events(env));
  const workloads = useQuery({ ...queries.workloads(env, NO_SCOPE), enabled: scope.exp.length > 0 }).data;
  const now = useNow(5000);
  const items = useMemo(() => {
    const exposure = new Map<string, Exposure>(workloads?.items.map((w) => [workloadKey(w), w.exposure]));
    return (data?.items ?? [])
      .filter((e) => !e.workload || inScope(scope, { ...e.workload, exposure: exposure.get(workloadKey(e.workload)) }))
      .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts) || b.id - a.id);
  }, [data, scope, workloads]);
  const isNew = useArrivals(
    items.map((e) => e.id),
    isPending ? `${viewKey}:loading` : viewKey,
  );
  const where = isScoped(scope) ? `${env} (${scopeLabel(scope)})` : env;

  return (
    <section className={cx("flex min-h-0 flex-col rounded-xl border border-line bg-surface", className)}>
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span
          className={cx(
            "size-2 rounded-full",
            live === "open" ? "animate-pulse-dot bg-good" : live === "offline" ? "bg-bad" : "bg-warn",
          )}
          aria-hidden="true"
        />
        <h2 className="text-base font-semibold text-ink">Live</h2>
        {live !== "open" && (
          <span className="text-xs text-muted">
            {live === "offline" ? "stream interrupted" : live === "connecting" ? "connecting…" : "reconnecting…"}
          </span>
        )}
        <span className="ml-auto text-xs text-muted">{data ? plural(items.length, "event") : ""}</span>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {isPending ? (
          <div className="space-y-4 p-4" role="status" aria-label="Loading…">
            {Array.from({ length: 7 }, (_, i) => (
              <div key={i} className="flex gap-3">
                <Skeleton className="size-7 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-3.5 w-11/12" />
                  <Skeleton className="h-3 w-1/3" />
                </div>
              </div>
            ))}
          </div>
        ) : error ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : items.length === 0 ? (
          <EmptyState icon="refresh" title="No recent events">
            Deployments, scans and new vulnerabilities in {where} will show up here in real time.
          </EmptyState>
        ) : (
          <ol aria-live="polite" aria-relevant="additions">
            {items.map((ev) => (
              <FeedItem key={ev.id} ev={ev} now={now} fresh={isNew(ev.id)} />
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}
