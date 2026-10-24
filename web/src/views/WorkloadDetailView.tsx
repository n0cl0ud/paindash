import { useQuery } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ApiError, queries } from "../api/client";
import type { ImageOrigin, WorkloadRef } from "../api/types";
import { ExposureBadge } from "../components/Badges";
import { FindingDrawer, useFindingSelection } from "../components/FindingDrawer";
import { FindingList } from "../components/FindingRow";
import { FixPromptDrawer } from "../components/FixPromptDrawer";
import { Icon } from "../components/Icon";
import { SeverityBar, SeverityLegend } from "../components/SeverityBar";
import { Card, EmptyState, ErrorState, Skeleton, SkeletonRows } from "../components/States";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { byPriority, isPriority } from "../lib/findings";
import { scoped } from "../lib/fixPrompt";
import { absDate, int, relTime, shortDigest, useNow } from "../lib/format";

/** Where the image is built from (first-party) or comes from (upstream). */
function Origin({ o }: { o: ImageOrigin }) {
  if (!o.repo) return <div className="mt-1 text-xs text-muted">Third-party</div>;
  const url = `https://github.com/${o.repo}${o.revision ? `/commit/${o.revision}` : ""}`;
  return (
    <div className="mt-1 flex items-center gap-1 text-xs text-muted">
      {!o.firstParty && <span>Third-party ·</span>}
      <a
        href={url}
        target="_blank"
        rel="noreferrer"
        title={o.guessed ? "Guessed from the image name: the image has no source label" : undefined}
        className="inline-flex min-w-0 items-center gap-1 font-mono hover:text-accent"
      >
        <Icon name="github" className="size-3 shrink-0" />
        <span className="truncate">
          {o.repo}
          {o.guessed && "?"}
          {o.revision && <span className="text-muted"> @ {o.revision.slice(0, 7)}</span>}
        </span>
      </a>
    </div>
  );
}

export function WorkloadDetailView() {
  const { env, href } = useEnv();
  const params = useParams();
  const ref: WorkloadRef = {
    cluster: params.cluster ?? "",
    namespace: params.namespace ?? "",
    kind: params.kind ?? "",
    name: params.name ?? "",
  };
  const now = useNow(30_000);
  const { data, error, refetch } = useQuery(queries.workload(env, ref));
  const [showAll, setShowAll] = useState(false);

  const findings = useMemo(() => [...(data?.findings ?? [])].sort(byPriority), [data]);
  const priority = useMemo(() => findings.filter(isPriority), [findings]);
  const all = showAll || priority.length === 0;
  const visible = all ? findings : priority;
  const sel = useFindingSelection(data ? findings : undefined);
  const fixable = useMemo(() => (data ? scoped(data.findings, "fixable").work.length : 0), [data]);
  const [fixOpen, setFixOpen] = useState(false);
  const closeFix = useCallback(() => setFixOpen(false), []);

  const back = (
    <Link to={href("/workloads")} className="inline-flex items-center gap-1 text-sm text-muted hover:text-ink">
      <Icon name="arrowRight" className="size-3.5 rotate-180" /> Workloads
    </Link>
  );

  if (!data) {
    if (error instanceof ApiError && error.status === 404) {
      return (
        <div>
          {back}
          <Card className="mt-3">
            <EmptyState icon="box" title="Workload not found">
              {ref.namespace}/{ref.name} no longer exists on {ref.cluster}: it may have been deleted or renamed.
            </EmptyState>
          </Card>
        </div>
      );
    }
    return (
      <div>
        {back}
        <Card className="mt-3">
          {error ? (
            <ErrorState error={error} onRetry={() => void refetch()} />
          ) : (
            <div className="p-5" role="status" aria-label="Loading…">
              <Skeleton className="h-6 w-72" />
              <Skeleton className="mt-3 h-4 w-96 max-w-full" />
              <SkeletonRows rows={3} />
            </div>
          )}
        </Card>
      </div>
    );
  }

  const w = data.workload;
  const max = w.counts.Critical + w.counts.High + w.counts.Medium + w.counts.Low;

  return (
    <div className="space-y-5">
      <div>
        {back}
        <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="text-xl font-semibold break-all text-ink">
            <span className="text-muted">{w.namespace}/</span>
            {w.name}
          </h1>
          <span className="rounded border border-line px-1.5 py-0.5 text-xs text-ink-2">{w.kind}</span>
          <ExposureBadge exposure={w.exposure} className="self-center" />
        </div>
        <p className="mt-1 text-sm text-muted">
          {w.cluster} · {w.env} · image changed{" "}
          <span title={absDate(w.lastChangeAt)}>{relTime(w.lastChangeAt, now)}</span>
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <h2 className="border-b border-line px-4 py-3 text-base font-semibold text-ink">
            Containers ({w.containers.length})
          </h2>
          <ul className="divide-y divide-line">
            {w.containers.map((c) => (
              <li key={c.name} className="px-4 py-3">
                <div className="text-sm font-medium text-ink">{c.name}</div>
                <div className="mt-0.5 font-mono text-xs break-all text-ink-2">{c.image}</div>
                <div className="font-mono text-xs text-muted" title={c.digest}>
                  {c.digest ? shortDigest(c.digest) : "unknown digest"}
                </div>
                {c.origin && <Origin o={c.origin} />}
              </li>
            ))}
          </ul>
          <div className="space-y-2 border-t border-line px-4 py-3">
            <SeverityBar counts={w.counts} max={max} width={160} />
            <SeverityLegend />
            <p className="text-xs text-muted">
              {w.kev > 0 && (
                <span className="mr-2 rounded bg-kev px-1.5 py-px font-bold text-white">{int(w.kev)} KEV</span>
              )}
              {int(w.fixable)} fixable
            </p>
          </div>
        </Card>

        <section className="min-w-0 lg:col-span-2" aria-labelledby="wl-findings">
          <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2">
            <h2 id="wl-findings" className="text-base font-semibold text-ink">
              Vulnerabilities
            </h2>
            {findings.length > 0 && (
              <div className="ml-auto inline-flex rounded-lg border border-line bg-page p-0.5 text-sm">
                {[
                  { v: false, label: `To fix (${priority.length})`, disabled: priority.length === 0 },
                  { v: true, label: `All (${findings.length})`, disabled: false },
                ].map((o) => (
                  <button
                    key={String(o.v)}
                    type="button"
                    disabled={o.disabled}
                    aria-pressed={all === o.v}
                    onClick={() => setShowAll(o.v)}
                    className={cx(
                      "rounded-md px-3 py-0.5 font-medium disabled:opacity-40",
                      all === o.v ? "bg-ink text-page" : "text-ink-2 hover:text-ink",
                    )}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
            )}
            {fixable > 0 && (
              <button
                type="button"
                onClick={() => setFixOpen(true)}
                title="Prompt for Claude Code or any coding agent: fix these vulnerabilities and open the pull requests"
                className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1 text-sm font-medium text-ink-2 hover:border-line-strong hover:text-ink"
              >
                <Icon name="terminal" className="size-4 text-accent" />
                Fix prompt
              </button>
            )}
          </div>
          <Card>
            <FindingList
              findings={visible}
              onOpen={sel.open}
              empty={
                <EmptyState icon="check" tone="good" title="No known vulnerabilities">
                  No vulnerabilities detected in the images of this workload.
                </EmptyState>
              }
            />
          </Card>
        </section>
      </div>

      {fixOpen && <FixPromptDrawer detail={data} onClose={closeFix} />}
      {sel.finding && <FindingDrawer finding={sel.finding} gone={sel.gone} onClose={sel.close} />}
    </div>
  );
}
