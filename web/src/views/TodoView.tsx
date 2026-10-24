import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link } from "react-router";
import { queries, TODO_FIXABLE, TODO_KEV } from "../api/client";
import type { Summary } from "../api/types";
import { FindingDrawer, useFindingSelection } from "../components/FindingDrawer";
import { FindingList } from "../components/FindingRow";
import { Icon } from "../components/Icon";
import { LiveFeed } from "../components/LiveFeed";
import { OutOfScope, ScopeHint } from "../components/ScopeBar";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { useEnv } from "../lib/env";
import { todoFindings } from "../lib/findings";
import { int, plural } from "../lib/format";
import { isScoped } from "../lib/scope";

function TodoEmpty({ summary }: { summary: Summary | undefined }) {
  const { env, scope, href } = useEnv();
  const images = summary?.images;
  if (summary && summary.workloadsTotal === 0 && isScoped(scope)) return <OutOfScope />;
  if (images && images.total === 0) {
    return (
      <EmptyState icon="box" title="No images inventoried yet">
        The {env} inventory has not reported any workload yet. Results will show up here after the first scans.
      </EmptyState>
    );
  }
  if (images && images.scanned === 0 && images.pending > 0) {
    return (
      <EmptyState icon="refresh" tone="accent" title="Scanning…">
        {plural(images.pending, "image")} waiting to be scanned. Vulnerabilities will show up here as they come in.
      </EmptyState>
    );
  }
  return (
    <EmptyState icon="check" tone="good" title={`Nothing urgent in ${env}`}>
      <p>No KEV vulnerabilities, and no critical or high ones with a fix available.</p>
      {images && images.pending > 0 && (
        <p className="mt-1 text-muted">{plural(images.pending, "image")} still waiting to be scanned.</p>
      )}
      <Link
        to={href("/vulns")}
        className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-accent hover:underline"
      >
        See all vulnerabilities <Icon name="arrowRight" className="size-3.5" />
      </Link>
    </EmptyState>
  );
}

export function TodoView() {
  const { env, scope } = useEnv();
  const fixable = useQuery(queries.findings(env, TODO_FIXABLE, scope));
  const kev = useQuery(queries.findings(env, TODO_KEV, scope));
  const summary = useQuery(queries.summary(env, scope));

  const ready = Boolean(fixable.data && kev.data);
  const list = useMemo(
    () => todoFindings(kev.data?.items, fixable.data?.items),
    [kev.data, fixable.data],
  );
  const truncated =
    (fixable.data?.total ?? 0) > (fixable.data?.items.length ?? 0) ||
    (kev.data?.total ?? 0) > (kev.data?.items.length ?? 0);
  const promoCount = list.filter((f) => f.promotion.length > 0).length;
  const sel = useFindingSelection(ready ? list : undefined);
  const error = fixable.error ?? kev.error;

  return (
    <div className="grid items-start gap-5 lg:grid-cols-3">
      <section className="min-w-0 lg:col-span-2" aria-labelledby="todo-title">
        <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 id="todo-title" className="text-xl font-semibold text-ink">
            To fix <span className="font-normal text-muted">in {env}</span>
            <ScopeHint />
          </h1>
          <p className="text-sm text-muted">
            {ready && `${int(list.length)} · `}KEV first, then critical and high with a fix
          </p>
          {promoCount > 0 && (
            <span className="inline-flex items-center gap-1 text-sm font-medium text-good-text sm:ml-auto">
              <Icon name="check" className="size-3.5" />
              {int(promoCount)} already fixed elsewhere
            </span>
          )}
        </div>
        <Card>
          {!ready && error ? (
            <ErrorState
              error={error}
              onRetry={() => {
                void fixable.refetch();
                void kev.refetch();
              }}
            />
          ) : !ready ? (
            <SkeletonRows />
          ) : (
            <FindingList findings={list} onOpen={sel.open} empty={<TodoEmpty summary={summary.data} />} />
          )}
        </Card>
        {truncated && (
          <p className="mt-2 text-xs text-muted">
            List truncated to the first {int(list.length)} entries: narrow it down in “All vulnerabilities”.
          </p>
        )}
      </section>

      <LiveFeed className="max-h-[70vh] lg:sticky lg:top-28 lg:h-[calc(100vh-8.75rem)] lg:max-h-none" />

      {sel.finding && <FindingDrawer finding={sel.finding} gone={sel.gone} onClose={sel.close} />}
    </div>
  );
}
