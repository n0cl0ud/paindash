import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { queries } from "../api/client";
import type { Workload } from "../api/types";
import { ExposureBadge } from "../components/Badges";
import { Icon } from "../components/Icon";
import { OutOfScope, ScopeHint } from "../components/ScopeBar";
import { SeverityBar, SeverityLegend } from "../components/SeverityBar";
import { Card, EmptyState, ErrorState, Skeleton } from "../components/States";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { workloadKey, workloadPath } from "../lib/findings";
import { absDate, EXPOSURE_RANK, int, plural, relTime, useNow } from "../lib/format";
import { isScoped } from "../lib/scope";

type SortKey = "name" | "namespace" | "cluster" | "exposure" | "risk" | "kev" | "fixable" | "lastChange";

const COLUMNS: { key: SortKey; label: string; numeric?: boolean }[] = [
  { key: "name", label: "Workload" },
  { key: "namespace", label: "Namespace" },
  { key: "cluster", label: "Cluster" },
  { key: "exposure", label: "Exposure" }, // only with exposure data
  { key: "risk", label: "Vulnerabilities" },
  { key: "kev", label: "KEV", numeric: true },
  { key: "fixable", label: "Fixable", numeric: true },
  { key: "lastChange", label: "Last change" },
];

const risk = (w: Workload) => [w.kev, w.counts.Critical, w.counts.High, w.counts.Medium, w.counts.Low];

function compare(a: Workload, b: Workload, key: SortKey): number {
  switch (key) {
    case "name":
      return a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind);
    case "namespace":
      return a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name);
    case "cluster":
      return a.cluster.localeCompare(b.cluster) || a.name.localeCompare(b.name);
    case "exposure": // descending = internet first
      return EXPOSURE_RANK[b.exposure] - EXPOSURE_RANK[a.exposure];
    case "kev":
      return a.kev - b.kev;
    case "fixable":
      return a.fixable - b.fixable;
    case "lastChange":
      return Date.parse(a.lastChangeAt) - Date.parse(b.lastChangeAt);
    case "risk": {
      const ra = risk(a);
      const rb = risk(b);
      for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] - rb[i];
      return 0;
    }
  }
}

const TEXT_KEYS: SortKey[] = ["name", "namespace", "cluster"];

export function WorkloadsView() {
  const { env, scope, href, exposureAvailable } = useEnv();
  const columns = exposureAvailable ? COLUMNS : COLUMNS.filter((c) => c.key !== "exposure");
  const navigate = useNavigate();
  const now = useNow(30_000);
  const { data, error, refetch } = useQuery(queries.workloads(env, scope));
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "risk", desc: true });
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const items = (data?.items ?? []).filter(
      (w) => !q || `${w.kind}/${w.name} ${w.namespace} ${w.cluster}`.toLowerCase().includes(q),
    );
    const dir = sort.desc ? -1 : 1;
    return items.sort((a, b) => dir * compare(a, b, sort.key) || a.name.localeCompare(b.name));
  }, [data, sort, filter]);

  const max = useMemo(
    () =>
      Math.max(
        1,
        ...(data?.items ?? []).map((w) => w.counts.Critical + w.counts.High + w.counts.Medium + w.counts.Low),
      ),
    [data],
  );
  const affected = (data?.items ?? []).filter((w) => w.counts.Critical + w.counts.High > 0).length;

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, desc: !s.desc } : { key, desc: !TEXT_KEYS.includes(key) }));

  return (
    <section aria-labelledby="wl-title">
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <h1 id="wl-title" className="text-xl font-semibold text-ink">
          Workloads <span className="font-normal text-muted">in {env}</span>
          <ScopeHint />
        </h1>
        {data && (
          <p className="text-sm text-muted">
            {plural(data.items.length, "workload")} · {int(affected)} with critical or high
          </p>
        )}
        <label className="relative ml-auto w-full sm:w-72">
          <span className="sr-only">Filter workloads</span>
          <Icon name="search" className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter (name, namespace, cluster)"
            className="w-full rounded-lg border border-line bg-surface py-1.5 pr-3 pl-8 text-sm text-ink placeholder:text-muted focus:border-accent-fill focus:outline-none"
          />
        </label>
      </div>

      <Card>
        {!data && error ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : !data ? (
          <div className="space-y-3 p-4" role="status" aria-label="Loading…">
            {Array.from({ length: 8 }, (_, i) => (
              <div key={i} className="flex gap-6">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-40" />
              </div>
            ))}
          </div>
        ) : data.items.length === 0 && isScoped(scope) ? (
          <OutOfScope />
        ) : data.items.length === 0 ? (
          <EmptyState icon="box" title="No workloads inventoried">
            The {env} inventory has not reported any workload yet.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line bg-page text-left text-xs text-muted">
                <tr>
                  {columns.map((c) => {
                    const active = sort.key === c.key;
                    return (
                      <th
                        key={c.key}
                        scope="col"
                        aria-sort={active ? (sort.desc ? "descending" : "ascending") : undefined}
                        className={cx("px-4 py-2 font-medium whitespace-nowrap", c.numeric && "text-right")}
                      >
                        <button
                          type="button"
                          onClick={() => toggleSort(c.key)}
                          className={cx(
                            "inline-flex items-center gap-1 hover:text-ink",
                            c.numeric && "flex-row-reverse",
                            active && "text-ink",
                          )}
                        >
                          {c.label}
                          <Icon
                            name="chevronDown"
                            className={cx(
                              "size-3 transition-transform",
                              active ? "opacity-100" : "opacity-0",
                              active && !sort.desc && "rotate-180",
                            )}
                          />
                        </button>
                        {c.key === "risk" && <SeverityLegend className="mt-1 font-normal" />}
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {rows.map((w) => {
                  const to = href(workloadPath(w));
                  return (
                    <tr
                      key={workloadKey(w)}
                      onClick={() => navigate(to)}
                      className="cursor-pointer border-b border-line last:border-0 hover:bg-surface-2"
                    >
                      <td className="px-4 py-2.5">
                        <Link
                          to={to}
                          onClick={(e) => e.stopPropagation()}
                          className="font-medium text-ink hover:underline"
                        >
                          {w.name}
                        </Link>
                        <span className="ml-2 text-xs text-muted">{w.kind}</span>
                      </td>
                      <td className="px-4 py-2.5 text-ink-2">{w.namespace}</td>
                      <td className="px-4 py-2.5 whitespace-nowrap text-ink-2">{w.cluster}</td>
                      {exposureAvailable && (
                        <td className="px-4 py-2.5">
                          <ExposureBadge exposure={w.exposure} />
                        </td>
                      )}
                      <td className="px-4 py-2.5">
                        <SeverityBar counts={w.counts} max={max} />
                      </td>
                      <td className="px-4 py-2.5 text-right tabular-nums">
                        {w.kev > 0 ? (
                          <span className="rounded bg-kev px-1.5 py-px text-xs font-bold text-white">{w.kev}</span>
                        ) : (
                          <span className="text-muted">0</span>
                        )}
                      </td>
                      <td className={cx("px-4 py-2.5 text-right tabular-nums", w.fixable > 0 ? "text-ink" : "text-muted")}>
                        {int(w.fixable)}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap text-ink-2" title={absDate(w.lastChangeAt)}>
                        {relTime(w.lastChangeAt, now)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {rows.length === 0 && (
              <p className="px-4 py-8 text-center text-sm text-muted">No workload matches “{filter}”.</p>
            )}
          </div>
        )}
      </Card>
    </section>
  );
}
