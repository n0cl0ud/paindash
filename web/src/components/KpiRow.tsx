import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { queries } from "../api/client";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { int } from "../lib/format";
import { Icon } from "./Icon";
import { useShowScans } from "./ScansDrawer";
import { Skeleton } from "./States";

/**
 * Counts how many times `value` changed within the same `scope` (env + scope),
 * plus the last delta. Used to flash a tile after a live update, not on env or
 * scope switch.
 */
function useChange(value: number, scope: string) {
  const prev = useRef({ scope, value });
  const [change, setChange] = useState({ n: 0, delta: 0 });
  useEffect(() => {
    const p = prev.current;
    if (p.scope === scope && p.value !== value) {
      setChange((c) => ({ n: c.n + 1, delta: value - p.value }));
    } else if (p.scope !== scope) {
      setChange({ n: 0, delta: 0 });
    }
    prev.current = { scope, value };
  }, [scope, value]);
  return change;
}

function Tile({
  label,
  value,
  total,
  upIsBad = true,
  alert = false,
  children,
}: {
  label: string;
  value: number;
  total?: number;
  upIsBad?: boolean;
  alert?: boolean;
  children?: ReactNode;
}) {
  const { viewKey } = useEnv();
  const { n, delta } = useChange(value, viewKey);
  const deltaTone =
    delta > 0 === upIsBad ? "bg-bad/10 text-bad-text" : "bg-good/10 text-good-text";
  return (
    <section className="relative overflow-hidden rounded-xl border border-line bg-surface px-4 py-3.5">
      {n > 0 && <span key={n} className="pointer-events-none absolute inset-0 animate-flash" aria-hidden="true" />}
      {alert && <span className="absolute inset-y-0 left-0 w-1 bg-bad" aria-hidden="true" />}
      <h3 className="flex items-center gap-1.5 text-sm text-ink-2">
        {alert && <Icon name="alert" className="size-3.5 text-bad-text" />}
        {label}
      </h3>
      <div className="relative mt-1 flex items-baseline gap-1.5">
        <span className="text-3xl font-semibold tracking-tight text-ink">{int(value)}</span>
        {total !== undefined && <span className="text-sm text-muted">/ {int(total)}</span>}
        {n > 0 && delta !== 0 && (
          <span
            key={n}
            className={cx("ml-1 animate-fade-delta rounded px-1.5 text-xs font-semibold tabular-nums", deltaTone)}
          >
            {delta > 0 ? `+${delta}` : `−${-delta}`}
          </span>
        )}
      </div>
      <div className="relative mt-1 text-xs text-muted">{children}</div>
    </section>
  );
}

function Meter({ value, max }: { value: number; max: number }) {
  const ratio = max > 0 ? Math.min(1, value / max) : 0;
  return (
    <span
      className="mt-2 block h-1.5 overflow-hidden rounded-full bg-accent-track"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
      aria-label="Images scanned"
    >
      <span className="block h-full rounded-full bg-accent-fill transition-[width] duration-700" style={{ width: `${ratio * 100}%` }} />
    </span>
  );
}

export function KpiRow() {
  const { env, scope, exposureAvailable } = useEnv();
  const { data, isError } = useQuery(queries.summary(env, scope));
  const showScans = useShowScans();

  if (!data) {
    if (isError) {
      return (
        <p className="rounded-xl border border-line bg-surface px-4 py-3 text-sm text-muted">
          Metrics unavailable right now.
        </p>
      );
    }
    return (
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" role="status" aria-label="Loading…">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="rounded-xl border border-line bg-surface px-4 py-3.5">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="mt-2.5 h-8 w-16" />
            <Skeleton className="mt-2 h-3 w-40" />
          </div>
        ))}
      </div>
    );
  }

  const { images } = data;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Tile label="Exploited (KEV)" value={data.kev} alert={data.kev > 0}>
        Actively exploited (CISA KEV)
      </Tile>
      <Tile label="Critical with fix" value={data.criticalFixable} alert={data.criticalFixable > 0}>
        Fix available, ready to deploy
      </Tile>
      <Tile label="Affected workloads" value={data.workloadsAffected} total={data.workloadsTotal}>
        At least one critical or high
        {exposureAvailable && (
          <span
            className={cx(
              "mt-0.5 flex items-center gap-1",
              data.internetAffected > 0 ? "font-medium text-accent" : "text-muted",
            )}
          >
            <Icon name="globe" className="size-3" />
            of which {int(data.internetAffected)} internet-facing
          </span>
        )}
      </Tile>
      <Tile label="Images scanned" value={images.scanned} total={images.total} upIsBad={false}>
        <span className="flex flex-wrap gap-x-3">
          {images.pending > 0 && (
            <button
              type="button"
              onClick={() => showScans("pending")}
              title="Show pending scans"
              className="inline-flex items-center gap-1.5 text-ink-2 hover:text-ink hover:underline"
            >
              <span className="size-1.5 animate-pulse rounded-full bg-accent-fill" aria-hidden="true" />
              {int(images.pending)} pending
            </button>
          )}
          {images.failed > 0 && (
            <button
              type="button"
              onClick={() => showScans("failed")}
              title="Show failed scans"
              className="inline-flex items-center gap-1 font-medium text-warn-text hover:underline"
            >
              <Icon name="alert" className="size-3" /> {int(images.failed)} failed
            </button>
          )}
          {images.pending === 0 && images.failed === 0 && (
            <span>{images.total > 0 ? "All up to date" : "No images inventoried"}</span>
          )}
        </span>
        <Meter value={images.scanned} max={images.total} />
      </Tile>
    </div>
  );
}
