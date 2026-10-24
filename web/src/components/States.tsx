import type { ReactNode } from "react";
import { ApiError } from "../api/client";
import { cx } from "../lib/cx";
import { Icon, type IconName } from "./Icon";

export function Skeleton({ className }: { className?: string }) {
  return <span className={cx("block animate-pulse rounded bg-surface-2", className)} aria-hidden="true" />;
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading…">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="space-y-2 border-b border-line px-4 py-3.5 last:border-0">
          <div className="flex gap-3">
            <Skeleton className="h-4 w-36" />
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-20" />
          </div>
          <Skeleton className="h-3.5 w-64" />
          <Skeleton className="h-3.5 w-48" />
        </div>
      ))}
    </div>
  );
}

export function EmptyState({
  icon = "check",
  tone = "muted",
  title,
  children,
}: {
  icon?: IconName;
  tone?: "muted" | "good" | "accent";
  title: string;
  children?: ReactNode;
}) {
  const toneCls = {
    muted: "bg-surface-2 text-muted",
    good: "bg-good/15 text-good-text",
    accent: "bg-accent-fill/15 text-accent",
  }[tone];
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <span className={cx("mb-4 grid size-11 place-items-center rounded-full", toneCls)}>
        <Icon name={icon} className="size-5" />
      </span>
      <h3 className="text-base font-semibold text-ink">{title}</h3>
      {children && <div className="mt-1.5 max-w-md text-sm text-ink-2">{children}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg =
    error instanceof ApiError
      ? `The server responded with ${error.message}.`
      : "The server cannot be reached right now.";
  return (
    <EmptyState icon="alert" title="Couldn’t load the data">
      <p>{msg}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-1.5 rounded-md border border-line-strong px-3 py-1.5 text-sm font-medium text-ink hover:bg-surface-2"
        >
          <Icon name="refresh" className="size-3.5" /> Retry
        </button>
      )}
    </EmptyState>
  );
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cx("overflow-hidden rounded-xl border border-line bg-surface", className)}>{children}</div>;
}
