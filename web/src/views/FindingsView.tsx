import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { queries, type FindingInclude, type FindingsFilter } from "../api/client";
import { SEVERITIES, type Finding, type Severity } from "../api/types";
import {
  ExceptionNote,
  ExposureBadge,
  ExposureMark,
  IdentificationBadges,
  KevBadge,
  PromotionHint,
  SeverityBadge,
  SUSPECT_HINT,
} from "../components/Badges";
import { FindingDrawer, useFindingSelection } from "../components/FindingDrawer";
import { Icon } from "../components/Icon";
import { OutOfScope, ScopeHint } from "../components/ScopeBar";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { byPriority, findingKey, promotionEnvs, uniqueWorkloads } from "../lib/findings";
import { absDate, compact, int, pct, plural, relTime, SEV_BG, SEV_LABEL, useNow } from "../lib/format";
import { isScoped } from "../lib/scope";
import { fixTargets } from "../lib/versions";

const LIMIT = 1000;

function Toggle({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-sm font-medium",
        on ? "border-ink bg-ink text-page" : "border-line bg-surface text-ink-2 hover:border-line-strong hover:text-ink",
      )}
    >
      {children}
    </button>
  );
}

function Row({ f, now, onOpen }: { f: Finding; now: number; onOpen: () => void }) {
  const workloads = uniqueWorkloads(f);
  const promo = promotionEnvs(f);
  return (
    <tr
      onClick={onOpen}
      className={cx(
        "cursor-pointer border-b border-line align-top last:border-0 hover:bg-surface-2",
        f.exception && "opacity-60",
      )}
    >
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onOpen();
            }}
            className="font-mono font-semibold whitespace-nowrap text-ink hover:underline"
          >
            {f.vulnId}
          </button>
          {f.kev && <KevBadge addedAt={f.kevAddedAt} />}
          <ExposureBadge exposure={f.exposure} />
          <IdentificationBadges f={f} />
        </div>
        {f.exception ? (
          <ExceptionNote e={f.exception} className="mt-1.5" />
        ) : (
          promo.length > 0 && <PromotionHint envs={promo} className="mt-1.5" />
        )}
      </td>
      <td className="px-4 py-2.5 whitespace-nowrap">
        <SeverityBadge severity={f.severity} />
      </td>
      <td className="px-4 py-2.5 text-right whitespace-nowrap tabular-nums text-ink-2">{f.cvss == null ? "—" : f.cvss.toFixed(1)}</td>
      <td className="px-4 py-2.5 text-right whitespace-nowrap tabular-nums text-ink-2">{pct(f.epss)}</td>
      <td className="px-4 py-2.5 font-mono text-[13px]">
        <span className="text-ink">{f.package.name}</span> <span className="text-ink-2">{f.package.version}</span>
      </td>
      <td className="px-4 py-2.5 font-mono text-[13px]">
        {f.fixedIn.length > 0 ? (
          <span className="font-semibold text-good-text">{fixTargets(f.package.version, f.fixedIn).join(" / ")}</span>
        ) : (
          <span className="font-sans text-xs text-muted">none</span>
        )}
      </td>
      <td className="px-4 py-2.5 text-ink-2">
        {workloads.length > 0 && (
          <span className="inline-flex items-center gap-1 font-mono text-xs">
            <ExposureMark exposure={workloads[0].exposure} />
            {workloads[0].namespace}/{workloads[0].name}
          </span>
        )}
        {workloads.length > 1 && <span className="ml-1.5 text-xs text-muted">+{workloads.length - 1}</span>}
      </td>
      <td className="px-4 py-2.5 whitespace-nowrap text-ink-2" title={absDate(f.firstSeen)}>
        {relTime(f.firstSeen, now)}
      </td>
    </tr>
  );
}

export function FindingsView() {
  const { env, scope } = useEnv();
  const now = useNow(30_000);
  const [params, setParams] = useSearchParams();

  const filter: FindingsFilter = useMemo(
    () => ({
      severity: (params.get("severity") ?? "")
        .split(",")
        .filter((s): s is Severity => (SEVERITIES as string[]).includes(s)),
      kev: params.get("kev") === "1",
      fixable: params.get("fixable") === "1",
      q: params.get("q") ?? "",
      include: (["suspect", "excepted"] as const).filter((k) => params.get(k) === "1"),
      limit: LIMIT,
    }),
    [params],
  );
  // Filters that narrow the list down (the include toggles widen it).
  const active = Boolean(filter.severity?.length || filter.kev || filter.fixable || filter.q);
  const shows = (k: FindingInclude) => filter.include?.includes(k) ?? false;

  const update = (patch: Record<string, string | null>) =>
    setParams(
      (p) => {
        for (const [k, v] of Object.entries(patch)) {
          if (v) p.set(k, v);
          else p.delete(k);
        }
        return p;
      },
      { replace: true },
    );

  // Free-text search: typed locally, pushed to the URL after a short pause.
  const [text, setText] = useState(filter.q ?? "");
  useEffect(() => {
    if (text === (params.get("q") ?? "")) return;
    const t = window.setTimeout(() => update({ q: text.trim() || null }), 250);
    return () => window.clearTimeout(t);
  }, [text]); // only when the text changes, not when other filters do

  const toggleSeverity = (s: Severity) => {
    const cur = new Set(filter.severity);
    if (cur.has(s)) cur.delete(s);
    else cur.add(s);
    update({ severity: SEVERITIES.filter((x) => cur.has(x)).join(",") || null });
  };

  const summary = useQuery(queries.summary(env, scope));
  const { data, error, refetch, isPlaceholderData } = useQuery({
    ...queries.findings(env, filter, scope),
    // Keep the current rows (dimmed) while a filter or scope change loads, but
    // never show another env's rows.
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === env ? prev : undefined),
  });
  const rows = useMemo(() => [...(data?.items ?? [])].sort(byPriority), [data]);
  const sel = useFindingSelection(data && !isPlaceholderData ? rows : undefined);

  // Left out of the list (and of the counts) unless asked for.
  const hidden = [
    !shows("suspect") && summary.data?.suspect ? `${int(summary.data.suspect)} suspect` : "",
    !shows("excepted") && summary.data?.excepted ? `${int(summary.data.excepted)} excepted` : "",
  ].filter(Boolean);

  return (
    <section aria-labelledby="all-title">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3">
        <h1 id="all-title" className="text-xl font-semibold text-ink">
          All vulnerabilities <span className="font-normal text-muted">in {env}</span>
          <ScopeHint />
        </h1>
        {data && (
          <p className="text-sm text-muted">
            {plural(data.total, "result")}
            {data.total > data.items.length && ` · ${int(data.items.length)} shown, refine the filters`}
            {hidden.length > 0 && (
              <span title={!shows("suspect") && summary.data?.suspect ? `Suspect: ${SUSPECT_HINT}` : undefined}>
                {" "}
                · {hidden.join(" and ")} hidden
              </span>
            )}
          </p>
        )}
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Severity">
          {SEVERITIES.map((s) => {
            const on = filter.severity?.includes(s) ?? false;
            const count = summary.data?.bySeverity[s];
            return (
              <Toggle key={s} on={on} onClick={() => toggleSeverity(s)}>
                <span className={cx("size-2.5 rounded-[3px]", SEV_BG[s])} aria-hidden="true" />
                {SEV_LABEL[s]}
                {count !== undefined && (
                  <span className={cx("text-xs tabular-nums", on ? "opacity-80" : "text-muted")}>{compact(count)}</span>
                )}
              </Toggle>
            );
          })}
        </div>
        <span className="mx-1 hidden h-5 w-px bg-line sm:block" aria-hidden="true" />
        <Toggle on={!!filter.kev} onClick={() => update({ kev: filter.kev ? null : "1" })}>
          <Icon name="flame" className="size-3.5" /> KEV only
        </Toggle>
        <Toggle on={!!filter.fixable} onClick={() => update({ fixable: filter.fixable ? null : "1" })}>
          <Icon name="check" className="size-3.5" /> Fix available
        </Toggle>
        <span className="mx-1 hidden h-5 w-px bg-line sm:block" aria-hidden="true" />
        {(
          [
            { k: "suspect", label: "Show suspect", count: summary.data?.suspect },
            { k: "excepted", label: "Show excepted", count: summary.data?.excepted },
          ] as const
        ).map(({ k, label, count }) => (
          <Toggle key={k} on={shows(k)} onClick={() => update({ [k]: shows(k) ? null : "1" })}>
            {label}
            {count !== undefined && (
              <span className={cx("text-xs tabular-nums", shows(k) ? "opacity-80" : "text-muted")}>{compact(count)}</span>
            )}
          </Toggle>
        ))}
        <label className="relative w-full sm:ml-auto sm:w-80">
          <span className="sr-only">Search</span>
          <Icon name="search" className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="CVE, package or workload"
            className="w-full rounded-lg border border-line bg-surface py-1.5 pr-3 pl-8 text-sm text-ink placeholder:text-muted focus:border-accent-fill focus:outline-none"
          />
        </label>
        {(active || Boolean(filter.include?.length)) && (
          <button
            type="button"
            onClick={() => {
              setText("");
              update({ severity: null, kev: null, fixable: null, q: null, suspect: null, excepted: null });
            }}
            className="text-sm font-medium text-accent hover:underline"
          >
            Reset
          </button>
        )}
      </div>

      <Card className={cx("transition-opacity", isPlaceholderData && "opacity-60")}>
        {!data && error ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : !data ? (
          <SkeletonRows rows={8} />
        ) : rows.length === 0 ? (
          active ? (
            <EmptyState icon="search" title="No results for these filters">
              Widen the severity or change the search.
            </EmptyState>
          ) : summary.data?.workloadsTotal === 0 && isScoped(scope) ? (
            <OutOfScope />
          ) : (
            <EmptyState icon="check" tone="good" title={`No vulnerabilities detected in ${env}`}>
              {summary.data && summary.data.images.pending > 0
                ? `${plural(summary.data.images.pending, "image")} still waiting to be scanned.`
                : "Results will show up here after the first scans."}
            </EmptyState>
          )
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line bg-page text-left text-xs text-muted">
                <tr>
                  <th scope="col" className="px-4 py-2 font-medium">Vulnerability</th>
                  <th scope="col" className="px-4 py-2 font-medium">Severity</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">CVSS</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">EPSS</th>
                  <th scope="col" className="px-4 py-2 font-medium">Package</th>
                  <th scope="col" className="px-4 py-2 font-medium">Fix</th>
                  <th scope="col" className="px-4 py-2 font-medium">Workloads</th>
                  <th scope="col" className="px-4 py-2 font-medium">First seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <Row key={findingKey(f)} f={f} now={now} onOpen={() => sel.open(f)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {sel.finding && <FindingDrawer finding={sel.finding} gone={sel.gone} onClose={sel.close} />}
    </section>
  );
}
