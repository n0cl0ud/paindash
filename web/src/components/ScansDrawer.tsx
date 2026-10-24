import { useQuery } from "@tanstack/react-query";
import { createContext, use, useCallback, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { queries, type ScanFilter } from "../api/client";
import type { ImageScan } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { workloadPath } from "../lib/findings";
import { plural, shortDigest } from "../lib/format";
import { ExposureBadge } from "./Badges";
import { Drawer } from "./Drawer";
import { ScopeHint } from "./ScopeBar";
import { EmptyState, ErrorState, SkeletonRows } from "./States";

const ScansContext = createContext<(status: ScanFilter) => void>(() => {});

/** Opens the scans drawer on failed images, or on pending (and running) ones. */
export const useShowScans = () => use(ScansContext);

/** Renders the scans drawer above `children`, which can open it from anywhere (KPI tile, live feed). */
export function ScansProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<ScanFilter | null>(null);
  const close = useCallback(() => setStatus(null), []);
  return (
    <ScansContext value={setStatus}>
      {children}
      {status && <ScansDrawer status={status} onClose={close} />}
    </ScansContext>
  );
}

const STATUS: Record<ImageScan["status"], { label: string; cls: string }> = {
  failed: { label: "Failed", cls: "border-bad/40 bg-bad/10 text-bad-text" },
  pending: { label: "Pending", cls: "border-line bg-surface-2 text-ink-2" },
  scanning: { label: "Scanning", cls: "border-accent/40 bg-accent-fill/10 text-accent" },
  scanned: { label: "Scanned", cls: "border-good/40 bg-good/10 text-good-text" },
};

function attempts(i: ImageScan): string {
  switch (i.status) {
    case "failed":
      return `Retried automatically, given up after ${plural(i.attempts, "attempt")}.`;
    case "scanning":
      return i.attempts > 1 ? `Scanning now (attempt ${i.attempts}).` : "Scanning now.";
    default:
      return i.attempts > 0
        ? `${plural(i.attempts, "failed attempt")}, will retry automatically.`
        : "Waiting for the scanner.";
  }
}

function ImageItem({ img, onClose }: { img: ImageScan; onClose: () => void }) {
  const { href } = useEnv();
  const s = STATUS[img.status] ?? STATUS.pending;
  return (
    <li className="overflow-hidden rounded-lg border border-line">
      <div className="space-y-1.5 px-3 py-2.5">
        <div className="flex items-start gap-2">
          <span className="min-w-0 flex-1 font-mono text-sm break-all text-ink">{img.image}</span>
          <span className={cx("shrink-0 rounded border px-1.5 py-px text-[11px] font-semibold", s.cls)}>{s.label}</span>
        </div>
        <div className="font-mono text-xs text-muted" title={img.digest}>
          {shortDigest(img.digest)}
        </div>
        <p className="text-xs text-ink-2">{attempts(img)}</p>
        {/* The scanner's stderr tail, redacted server-side: shown verbatim. */}
        {img.error && (
          <pre className="max-h-48 overflow-auto rounded-md border border-line bg-page px-2.5 py-2 font-mono text-xs leading-relaxed whitespace-pre-wrap wrap-anywhere text-ink-2">
            {img.error}
          </pre>
        )}
      </div>
      {img.workloads.length > 0 && (
        <ul className="divide-y divide-line border-t border-line bg-page/50">
          {img.workloads.map((w) => (
            <li
              key={`${w.cluster}/${w.namespace}/${w.kind}/${w.name}/${w.container}`}
              className="flex flex-wrap items-baseline gap-x-2 px-3 py-2 text-sm"
            >
              <Link to={href(workloadPath(w))} onClick={onClose} className="font-medium text-ink hover:underline">
                {w.namespace}/{w.name}
              </Link>
              <ExposureBadge exposure={w.exposure} className="self-center" />
              <span className="text-xs text-muted">
                {w.kind} · {w.cluster} · container {w.container}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function ScansDrawer({ status, onClose }: { status: ScanFilter; onClose: () => void }) {
  const { env, scope } = useEnv();
  const { data, error, refetch } = useQuery(queries.images(env, status, scope));
  const failed = status === "failed";

  return (
    <Drawer
      titleId="scans-title"
      onClose={onClose}
      header={
        <>
          <h2 id="scans-title" className="text-lg font-semibold text-ink">
            {failed ? "Failed scans" : "Pending scans"} <span className="font-normal text-muted">in {env}</span>
            <ScopeHint />
          </h2>
          {data && (
            <p className="mt-0.5 text-sm text-muted">
              {plural(data.items.length, "image")}
              {!failed && " · queued or being scanned"}
            </p>
          )}
        </>
      }
    >
      {!data && error ? (
        <ErrorState error={error} onRetry={() => void refetch()} />
      ) : !data ? (
        <SkeletonRows rows={3} />
      ) : data.items.length === 0 ? (
        <EmptyState icon="check" tone="good" title={failed ? "No failed scans" : "No pending scans"}>
          {failed
            ? "A failed scan is retried automatically, and listed here once it gives up."
            : "All images are scanned."}
        </EmptyState>
      ) : (
        <ul className="space-y-3">
          {data.items.map((img) => (
            <ImageItem key={img.digest} img={img} onClose={onClose} />
          ))}
        </ul>
      )}
    </Drawer>
  );
}
