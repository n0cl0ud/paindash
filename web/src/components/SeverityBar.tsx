import type { Severity } from "../api/types";
import { cx } from "../lib/cx";
import { int, SEV_BG, SEV_LABEL } from "../lib/format";

const BAR_SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

function describe(counts: Record<Severity, number>) {
  const parts = BAR_SEVERITIES.filter((s) => counts[s] > 0).map(
    (s) => `${int(counts[s])} ${SEV_LABEL[s].toLowerCase()}`,
  );
  return parts.length ? parts.join(", ") : "no vulnerabilities";
}

/**
 * Mini stacked bar of Critical/High/Medium/Low counts. Length is scaled to
 * `max` (the largest total in the table) so rows compare at a glance; the
 * exact counts sit next to it, keyed by the same swatches as the legend.
 */
export function SeverityBar({
  counts,
  max,
  width = 96,
}: {
  counts: Record<Severity, number>;
  max: number;
  width?: number;
}) {
  const present = BAR_SEVERITIES.filter((s) => counts[s] > 0);
  const total = present.reduce((n, s) => n + counts[s], 0);
  if (total === 0) return <span className="text-xs text-muted">none</span>;
  const barWidth = Math.max(present.length * 5, Math.round((total / Math.max(max, total)) * width));
  return (
    <div className="flex items-center gap-3" title={describe(counts)}>
      <div className="flex shrink-0" style={{ width }}>
        <div
          className="flex h-2.5 gap-[2px]"
          style={{ width: barWidth }}
          role="img"
          aria-label={describe(counts)}
        >
          {present.map((s, i) => (
            <span
              key={s}
              className={cx(SEV_BG[s], "h-full min-w-[3px]", i === present.length - 1 && "rounded-r")}
              style={{ flex: `${counts[s]} 1 0` }}
            />
          ))}
        </div>
      </div>
      <span className="flex gap-2.5 text-xs tabular-nums text-ink-2">
        {present.map((s) => (
          <span key={s} className="inline-flex items-center gap-1">
            <span className={cx("size-2 rounded-[2px]", SEV_BG[s])} aria-hidden="true" />
            {int(counts[s])}
          </span>
        ))}
      </span>
    </div>
  );
}

export function SeverityLegend({ className }: { className?: string }) {
  return (
    <div className={cx("flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted", className)}>
      {BAR_SEVERITIES.map((s) => (
        <span key={s} className="inline-flex items-center gap-1.5">
          <span className={cx("size-2.5 rounded-[3px]", SEV_BG[s])} aria-hidden="true" />
          {SEV_LABEL[s]}
        </span>
      ))}
    </div>
  );
}
