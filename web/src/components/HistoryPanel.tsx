import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { queries } from "../api/client";
import type { HistoryChange, HistoryPoint } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { absDate, day, int } from "../lib/format";
import { isScoped } from "../lib/scope";
import { Delta } from "./Badges";
import { Icon } from "./Icon";
import { EVENT_FALLBACK, EVENT_TYPES } from "./LiveFeed";
import { Skeleton } from "./States";

type SeriesKey = "kev" | "criticalFixable" | "highFixableInternet" | "excepted";

interface Series {
  key: SeriesKey;
  label: string;
  short: string;
  color: string;
  hint: string;
}

// Same counts and names as the tiles: the last point of each line is the tile.
const SERIES: Series[] = [
  { key: "kev", label: "Exploited (KEV)", short: "KEV", color: "var(--kev)", hint: "Distinct vulnerabilities listed in CISA KEV" },
  { key: "criticalFixable", label: "Critical with fix", short: "Critical fix", color: "var(--sev-critical)", hint: "Distinct critical vulnerabilities with a fix available" },
  { key: "highFixableInternet", label: "High with fix, internet", short: "High fix, internet", color: "var(--sev-high)", hint: "Distinct high vulnerabilities with a fix, on internet-facing workloads" },
  { key: "excepted", label: "Excepted", short: "Excepted", color: "var(--muted)", hint: "Findings hidden by an active exception" },
];

const RANGES = [
  { days: 7, label: "7d" },
  { days: 30, label: "30d" },
  { days: 90, label: "90d" },
  { days: 0, label: "All" },
];

const ROW_H = 56; // plot height of each small multiple
const PAD = 6; // vertical breathing room inside a plot
const TOOLTIP_W = 288; // hover card width, narrowed to the chart on phones

// Per-viewer conveniences only: storage may be unavailable.
function load(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}
function save(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* not persisted */
  }
}

/** Smallest "nice" integer ceiling: 5, 10, 15, 20, 30, 40, 50, 60, 80, 100… */
function niceMax(m: number): number {
  if (m <= 5) return 5;
  const p = 10 ** Math.floor(Math.log10(m));
  return [1, 1.5, 2, 3, 4, 5, 6, 8, 10].map((f) => f * p).find((v) => v >= m && Number.isInteger(v)) ?? 10 * p;
}

type Kind = "deploy" | "db" | "exception";

/** What moved a point, for its marker on the time axis. */
function kindOf(cs: HistoryChange[]): Kind | null {
  if (cs.some((c) => c.type === "scan_completed" || c.type === "deployed" || c.type === "removed")) return "deploy";
  if (cs.some((c) => c.type === "vulns_new" || c.type === "vulns_fixed" || c.type === "kev_added")) return "db";
  if (cs.some((c) => c.type.startsWith("exception"))) return "exception";
  return null;
}

const tickFmt = {
  day: new Intl.DateTimeFormat("en", { weekday: "short", day: "numeric" }),
  date: new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }),
  month: new Intl.DateTimeFormat("en", { month: "short", year: "2-digit" }),
};

/** About five ticks on day boundaries, labelled for the span, at least 56 px apart. */
function timeTicks(t0: number, t1: number, width: number): { t: number; label: string }[] {
  const DAY = 86_400_000;
  const spanDays = (t1 - t0) / DAY;
  const step = spanDays <= 10 ? 1 : spanDays <= 45 ? 7 : spanDays <= 120 ? 14 : 30;
  const fmt = spanDays <= 10 ? tickFmt.day : spanDays <= 120 ? tickFmt.date : tickFmt.month;
  const first = new Date(t0);
  first.setHours(0, 0, 0, 0);
  const out: { t: number; label: string }[] = [];
  for (let t = first.getTime() + DAY; t < t1; t += step * DAY) {
    if (t > t0) out.push({ t, label: fmt.format(t) });
  }
  const every = Math.max(1, Math.ceil((out.length * 56) / width));
  return out.filter((_, i) => i % every === 0);
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [box, setBox] = useState({ left: 0, width: 0 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => setBox({ left: el.offsetLeft, width: el.clientWidth });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, box] as const;
}

export function HistoryPanel() {
  const { env, scope, exposureAvailable } = useEnv();
  const [open, setOpen] = useState(() => load("paindash.history.open", "1") === "1");
  const [days, setDays] = useState(() => {
    const d = Number(load("paindash.history.days", "30"));
    return RANGES.some((r) => r.days === d) ? d : 30;
  });
  const [compare, setCompare] = useState(false);
  const [table, setTable] = useState(false);
  const { data, isError, isPlaceholderData } = useQuery({
    ...queries.history(days),
    placeholderData: (prev) => prev,
  });

  const series = SERIES.filter((s) => exposureAvailable || s.key !== "highFixableInternet");
  const points = data?.envs[env] ?? [];
  const recorded = points.length - 1; // the last one is the live value
  // The end of the promotion chain (prod), where fixes have to land, compared
  // with the earlier envs of the chain only: what they fixed is not promoted yet.
  const promotion = useQuery(queries.meta()).data?.promotion ?? [];
  const compareEnv = promotion.at(-1) ?? "prod";
  const canCompare = promotion.slice(0, -1).includes(env) && (data?.envs[compareEnv]?.length ?? 0) > 1;
  const comparePoints = compare && canCompare ? data?.envs[compareEnv] : undefined;

  const toggleOpen = () => {
    setOpen((o) => {
      save("paindash.history.open", o ? "0" : "1");
      return !o;
    });
  };
  const pickRange = (d: number) => {
    setDays(d);
    save("paindash.history.days", String(d));
  };

  return (
    <section className="rounded-xl border border-line bg-surface" aria-label="History">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
        <button
          type="button"
          onClick={toggleOpen}
          aria-expanded={open}
          className="inline-flex items-center gap-1.5 text-sm font-semibold text-ink"
        >
          <Icon name="clock" className="size-4 text-muted" />
          History
          <span className={cx("text-muted transition-transform", open ? "rotate-90" : "")} aria-hidden="true">
            ›
          </span>
        </button>
        {!open && recorded > 0 && data && (
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            {series.map((s) => (
              <Sparkline key={s.key} s={s} points={points} since={data.since} now={data.now} />
            ))}
          </span>
        )}
        {open && isScoped(scope) && (
          <span
            className="rounded bg-surface-2 px-1.5 py-0.5 text-xs text-muted"
            title="The history covers the whole environment: the namespace, component and exposure filters do not apply to it."
          >
            Env-wide, filters don't apply
          </span>
        )}
        {open && (
          <span className="ml-auto flex flex-wrap items-center gap-2">
            {canCompare && (
              <button
                type="button"
                aria-pressed={compare}
                onClick={() => setCompare((c) => !c)}
                title={`Overlay ${compareEnv} as a dotted line: the gap is what has not been promoted yet`}
                className={cx(
                  "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-sm font-medium",
                  compare ? "border-ink bg-ink text-page" : "border-line bg-surface text-ink-2 hover:border-line-strong hover:text-ink",
                )}
              >
                <svg width="16" height="6" aria-hidden="true">
                  <line x1="0" y1="3" x2="16" y2="3" stroke="currentColor" strokeWidth="1.5" strokeDasharray="2 3" />
                </svg>
                Compare with {compareEnv}
              </button>
            )}
            <button
              type="button"
              aria-pressed={table}
              onClick={() => setTable((t) => !t)}
              className="rounded-lg px-2 py-1 text-sm font-medium text-ink-2 hover:bg-surface-2 hover:text-ink"
            >
              {table ? "Chart" : "Table"}
            </button>
            <span className="inline-flex rounded-lg border border-line p-0.5" role="group" aria-label="Time range">
              {RANGES.map((r) => (
                <button
                  key={r.days}
                  type="button"
                  aria-pressed={days === r.days}
                  onClick={() => pickRange(r.days)}
                  className={cx(
                    "rounded-md px-2 py-0.5 text-sm tabular-nums",
                    days === r.days ? "bg-ink font-medium text-page" : "text-ink-2 hover:text-ink",
                  )}
                >
                  {r.label}
                </button>
              ))}
            </span>
          </span>
        )}
      </header>

      {open && (
        <div className={cx("border-t border-line px-4 pt-3 pb-3 transition-opacity", isPlaceholderData && "opacity-60")}>
          {!data ? (
            isError ? (
              <p className="py-6 text-center text-sm text-muted">History unavailable right now.</p>
            ) : (
              <Skeleton className="h-56 w-full" />
            )
          ) : recorded < 1 ? (
            <p className="py-6 text-center text-sm text-muted">
              History starts {data.start ? day(data.start) : "now"}: a point is recorded whenever these numbers move,
              and once a day.
            </p>
          ) : table ? (
            <HistoryTable points={points} series={series} since={data.since} />
          ) : (
            <HistoryChart
              points={points}
              compare={comparePoints}
              compareEnv={compareEnv}
              series={series}
              since={data.since}
              now={data.now}
              start={data.start}
              days={days}
            />
          )}
        </div>
      )}
    </section>
  );
}

function Sparkline({ s, points, since, now }: { s: Series; points: HistoryPoint[]; since: string; now: string }) {
  const W = 56;
  const H = 16;
  const t0 = Date.parse(since);
  const t1 = Math.max(Date.parse(now), t0 + 1);
  const max = Math.max(1, ...points.map((p) => p[s.key]));
  const x = (t: string) => Math.max(0, Math.min(W, ((Date.parse(t) - t0) / (t1 - t0)) * W));
  const y = (v: number) => 1 + (1 - v / max) * (H - 2);
  const last = points[points.length - 1]?.[s.key] ?? 0;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-ink-2" title={s.hint}>
      {s.short}
      <svg width={W} height={H} aria-hidden="true" className="overflow-visible">
        <path d={stepPath(points, s.key, x, y)} fill="none" stroke={s.color} strokeWidth="1.5" strokeLinejoin="round" />
      </svg>
      <span className="font-semibold tabular-nums text-ink">{int(last)}</span>
    </span>
  );
}

/** Step-after path: counts hold their value until the next point. */
function stepPath(ps: HistoryPoint[], key: SeriesKey, x: (t: string) => number, y: (v: number) => number): string {
  let d = "";
  ps.forEach((p, i) => {
    const px = x(p.t).toFixed(1);
    const py = y(p[key]).toFixed(1);
    d += i === 0 ? `M${px},${py}` : `H${px}V${py}`;
  });
  return d;
}

/** The step path with its corners rounded by up to r px. */
function roundedStepPath(
  ps: HistoryPoint[],
  key: SeriesKey,
  x: (t: string) => number,
  y: (v: number) => number,
  r = 3,
): string {
  // Corners of the step-after line, without zero-length segments.
  const v: [number, number][] = [];
  const push = (px: number, py: number) => {
    const prev = v[v.length - 1];
    if (!prev || prev[0] !== px || prev[1] !== py) v.push([px, py]);
  };
  ps.forEach((p, i) => {
    const px = x(p.t);
    if (i > 0) push(px, y(ps[i - 1][key]));
    push(px, y(p[key]));
  });
  if (v.length === 0) return "";
  const f = (n: number) => n.toFixed(1);
  let d = `M${f(v[0][0])},${f(v[0][1])}`;
  for (let i = 1; i < v.length - 1; i++) {
    const [ax, ay] = v[i - 1];
    const [bx, by] = v[i];
    const [cx, cy] = v[i + 1];
    const rin = Math.min(r, Math.hypot(bx - ax, by - ay) / 2);
    const rout = Math.min(r, Math.hypot(cx - bx, cy - by) / 2);
    const rr = Math.min(rin, rout);
    const ux = Math.sign(bx - ax), uy = Math.sign(by - ay);
    const wx = Math.sign(cx - bx), wy = Math.sign(cy - by);
    d += `L${f(bx - ux * rr)},${f(by - uy * rr)}Q${f(bx)},${f(by)} ${f(bx + wx * rr)},${f(by + wy * rr)}`;
  }
  const end = v[v.length - 1];
  return d + `L${f(end[0])},${f(end[1])}`;
}

/** The value at the start of the window (or the first point of a young history). */
function startValue(ps: HistoryPoint[], key: SeriesKey, t0: number): number {
  let v = ps[0][key];
  for (const p of ps) {
    if (Date.parse(p.t) > t0) break;
    v = p[key];
  }
  return v;
}

/** Change over the window: down is good for these counts, except "excepted" (neutral). */
function Trend({ delta, neutral, label }: { delta: number; neutral: boolean; label: string }) {
  if (delta === 0) {
    return <span className="text-xs text-muted">= {label}</span>;
  }
  const tone = neutral ? "bg-surface-2 text-ink-2" : delta < 0 ? "bg-good/10 text-good-text" : "bg-bad/10 text-bad-text";
  return (
    <span
      className={cx("rounded px-1 text-xs font-semibold tabular-nums", tone)}
      title={`${delta > 0 ? "+" : "−"}${int(Math.abs(delta))} over ${label}`}
    >
      {delta < 0 ? "▼" : "▲"} {int(Math.abs(delta))}
      <span className="ml-1 font-normal opacity-75">{label}</span>
    </span>
  );
}

function HistoryChart({
  points,
  compare,
  compareEnv,
  series,
  since,
  now,
  start,
  days,
}: {
  points: HistoryPoint[];
  compare?: HistoryPoint[];
  compareEnv: string;
  series: Series[];
  since: string;
  now: string;
  start: string | null;
  days: number;
}) {
  const uid = useId();
  const rangeLabel = RANGES.find((r) => r.days === days)?.label.toLowerCase() ?? "";
  const [plotRef, plot] = useWidth<HTMLDivElement>();
  const [boxRef, box] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [pinned, setPinned] = useState<number | null>(null);
  const W = Math.max(plot.width, 1);
  const t0 = Date.parse(since);
  const t1 = Math.max(Date.parse(now), t0 + 3_600_000);
  const x = (t: string) => Math.max(0, Math.min(W, ((Date.parse(t) - t0) / (t1 - t0)) * W));

  // Points the crosshair can land on: the ones inside the window.
  const targets = useMemo(
    () => points.map((p, i) => ({ i, t: Date.parse(p.t) })).filter((p) => p.t >= t0),
    [points, t0],
  );
  useEffect(() => setPinned(null), [since]);

  const yMax = useMemo(() => {
    const out = {} as Record<SeriesKey, number>;
    for (const s of series) {
      const vals = [...points, ...(compare ?? [])].map((p) => p[s.key]);
      out[s.key] = niceMax(Math.max(0, ...vals));
    }
    return out;
  }, [points, compare, series]);

  const nearest = (px: number) => {
    let best: number | null = null;
    let dist = Infinity;
    for (const c of targets) {
      const d = Math.abs(x(points[c.i].t) - px);
      if (d < dist) {
        dist = d;
        best = c.i;
      }
    }
    return best;
  };
  const onMove = (e: PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    setHover(nearest(e.clientX - r.left));
  };
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = targets.findIndex((c) => c.i === (hover ?? pinned));
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const next = idx < 0 ? targets.length - 1 : Math.max(0, Math.min(targets.length - 1, idx + (e.key === "ArrowLeft" ? -1 : 1)));
      setHover(targets[next]?.i ?? null);
    } else if (e.key === "Enter" && hover !== null) {
      setPinned(hover);
    } else if (e.key === "Escape") {
      setPinned(null);
      setHover(null);
    }
  };

  const active = hover ?? pinned;
  const activePoint = active !== null ? points[active] : null;
  const isLive = active === points.length - 1;
  const comparedAt = (t: string) => {
    if (!compare) return null;
    const at = Date.parse(t);
    let v: HistoryPoint | null = null;
    for (const p of compare) {
      if (Date.parse(p.t) <= at) v = p;
    }
    return v;
  };
  const markers = points
    .slice(0, -1)
    .map((p, i) => ({ i, p, kind: kindOf(p.changes) }))
    .filter((m) => m.kind && Date.parse(m.p.t) >= t0);
  const young = start !== null && Date.parse(start) > t0;
  const ticks = timeTicks(t0, t1, W);
  const cx0 = activePoint ? x(activePoint.t) : 0;
  const pinnedPoint = pinned !== null ? points[pinned] : null;

  return (
    <div>
      <div ref={boxRef} className="relative" onPointerLeave={() => setHover(null)}>
        {series.map((s, si) => {
          const y = (v: number) => PAD + (1 - v / yMax[s.key]) * (ROW_H - 2 * PAD);
          const last = points[points.length - 1][s.key];
          const lastCompare = compare?.[compare.length - 1]?.[s.key];
          const line = roundedStepPath(points, s.key, x, y);
          const xs = [x(points[0].t), W];
          const gid = `${uid}-${s.key}`;
          // Phones: the name and the value above a full-width plot.
          return (
            <div
              key={s.key}
              className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 py-1 sm:grid-cols-[9.5rem_1fr_6.5rem] sm:items-stretch"
            >
              <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 sm:flex-col sm:flex-nowrap sm:items-stretch sm:justify-between sm:py-1 sm:text-right">
                <span className="inline-flex items-center justify-end gap-1.5 text-xs font-medium text-ink-2" title={s.hint}>
                  <span className="size-2 rounded-full" style={{ background: s.color }} aria-hidden="true" />
                  {s.label}
                </span>
                <span className="text-[10px] leading-none text-muted tabular-nums">0–{int(yMax[s.key])}</span>
              </div>
              <div
                ref={si === 0 ? plotRef : undefined}
                className="relative order-last col-span-2 sm:order-none sm:col-span-1"
                style={{ height: ROW_H }}
              >
                <svg key={days} width={W} height={ROW_H} className="block overflow-visible" aria-hidden="true">
                  <defs>
                    <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" style={{ stopColor: s.color, stopOpacity: 0.28 }} />
                      <stop offset="100%" style={{ stopColor: s.color, stopOpacity: 0.02 }} />
                    </linearGradient>
                  </defs>
                  <line x1="0" x2={W} y1={y(0)} y2={y(0)} stroke="var(--line-strong)" strokeWidth="1" />
                  <line x1="0" x2={W} y1={y(yMax[s.key])} y2={y(yMax[s.key])} stroke="var(--line)" strokeWidth="1" />
                  <path
                    d={`${line}L${xs[1].toFixed(1)},${y(0).toFixed(1)}L${xs[0].toFixed(1)},${y(0).toFixed(1)}Z`}
                    fill={`url(#${gid})`}
                    className="animate-fade-in"
                  />
                  {compare && (
                    <path
                      d={roundedStepPath(compare, s.key, x, y)}
                      fill="none"
                      stroke={s.color}
                      strokeWidth="1.5"
                      strokeDasharray="2 3"
                      opacity="0.75"
                    />
                  )}
                  <path
                    d={line}
                    pathLength={1}
                    strokeDasharray="1 1"
                    fill="none"
                    stroke={s.color}
                    strokeWidth="2"
                    strokeLinejoin="round"
                    strokeLinecap="round"
                    className="animate-draw"
                  />
                  {/* Live end of the line: the tile's value. */}
                  <circle
                    cx={W}
                    cy={y(last)}
                    r="4"
                    fill={s.color}
                    className="origin-center animate-live-ping [transform-box:fill-box]"
                  />
                  <circle cx={W} cy={y(last)} r="4" fill={s.color} stroke="var(--surface)" strokeWidth="2" />
                  {activePoint && (
                    <circle
                      cx={cx0}
                      cy={y(activePoint[s.key])}
                      r="4.5"
                      fill={s.color}
                      stroke="var(--surface)"
                      strokeWidth="2"
                    />
                  )}
                </svg>
              </div>
              <div className="flex flex-col items-end justify-center gap-0.5 sm:items-stretch">
                <span className="flex items-baseline gap-2">
                  <span className="text-xl leading-none font-semibold text-ink">{int(last)}</span>
                  <Trend delta={last - startValue(points, s.key, t0)} neutral={s.key === "excepted"} label={rangeLabel} />
                </span>
                {lastCompare !== undefined && (
                  <span className="text-xs text-muted tabular-nums">{compareEnv} {int(lastCompare)}</span>
                )}
              </div>
            </div>
          );
        })}

        {/* Time axis: change markers, then dates. */}
        <div className="grid gap-x-3 sm:grid-cols-[9.5rem_1fr_5rem]">
          <span
            className={cx(
              "order-last pt-1 text-[10px] text-muted sm:order-none sm:block sm:text-right",
              !(young && start) && "hidden",
            )}
          >
            {young && start ? `since ${day(start)}` : ""}
          </span>
          <svg width={W} height={30} className="block overflow-visible" aria-hidden="true">
            {markers.map((m) => (
              <Marker key={m.i} kind={m.kind as Kind} x={x(m.p.t)} />
            ))}
            {ticks.map((tk) => {
              const tx = ((tk.t - t0) / (t1 - t0)) * W;
              return (
                <g key={tk.t}>
                  <line x1={tx} x2={tx} y1="12" y2="15" stroke="var(--line-strong)" />
                  <text x={tx} y="27" textAnchor="middle" fontSize="10" fill="var(--muted)" className="tabular-nums">
                    {tk.label}
                  </text>
                </g>
              );
            })}
          </svg>
          <span className="hidden pt-1 text-[10px] text-muted sm:block">now</span>
        </div>

        {/* Hover layer over the plots and the axis. */}
        <div
          role="slider"
          tabIndex={0}
          aria-label="History: arrow keys move between points, Enter pins the changes"
          aria-valuemin={0}
          aria-valuemax={Math.max(0, targets.length - 1)}
          aria-valuenow={Math.max(0, targets.findIndex((c) => c.i === active))}
          aria-valuetext={activePoint ? absDate(activePoint.t) : "none"}
          className="absolute top-0 bottom-0 cursor-crosshair rounded focus-visible:outline-2 focus-visible:outline-accent-fill"
          style={{ left: plot.left, width: plot.width }}
          onPointerMove={onMove}
          onClick={() => hover !== null && setPinned(hover === pinned ? null : hover)}
          onKeyDown={onKey}
          onBlur={() => setHover(null)}
        >
          {activePoint && (
            <>
              <div className="pointer-events-none absolute top-0 bottom-7 w-px bg-line-strong" style={{ left: cx0 }} />
              {hover !== null && (
                <Tooltip
                  point={activePoint}
                  live={isLive}
                  series={series}
                  compare={comparedAt(activePoint.t)}
                  compareEnv={compareEnv}
                  left={cx0}
                  width={plot.width}
                  plotLeft={plot.left}
                  boxWidth={box.width}
                />
              )}
            </>
          )}
        </div>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted sm:pl-[calc(9.5rem+0.75rem)]">
        <span className="inline-flex items-center gap-1.5">
          <svg width="10" height="10" aria-hidden="true">
            <Marker kind="deploy" x={5} y={0} />
          </svg>
          Deployment
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="10" height="10" aria-hidden="true">
            <Marker kind="db" x={5} y={0} />
          </svg>
          New CVEs published
        </span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="10" height="10" aria-hidden="true">
            <Marker kind="exception" x={5} y={0} />
          </svg>
          Exception
        </span>
        <span className="ml-auto">Hover for details, click to pin what changed</span>
      </div>

      {pinnedPoint && (
        <div className="mt-3 rounded-lg border border-line bg-page px-3 py-2.5">
          <div className="mb-1.5 flex items-center gap-2 text-sm">
            <span className="font-medium text-ink">What changed by {absDate(pinnedPoint.t)}</span>
            <button type="button" onClick={() => setPinned(null)} className="ml-auto text-muted hover:text-ink" aria-label="Close">
              <Icon name="close" className="size-4" />
            </button>
          </div>
          <ChangeList changes={pinnedPoint.changes} />
        </div>
      )}
    </div>
  );
}

function Marker({ kind, x, y = 2 }: { kind: Kind; x: number; y?: number }) {
  switch (kind) {
    case "deploy":
      return <rect x={x - 1} y={y} width="2" height="8" rx="1" fill="var(--ink-2)" />;
    case "db":
      return <circle cx={x} cy={y + 4} r="3" fill="var(--surface)" stroke="var(--accent)" strokeWidth="1.5" />;
    case "exception":
      return <rect x={x - 3} y={y + 1} width="6" height="6" rx="1" fill="var(--surface)" stroke="var(--muted)" strokeWidth="1.5" />;
  }
}

function Tooltip({
  point,
  live,
  series,
  compare,
  compareEnv,
  left,
  width,
  plotLeft,
  boxWidth,
}: {
  point: HistoryPoint;
  live: boolean;
  series: Series[];
  compare: HistoryPoint | null;
  compareEnv: string;
  left: number;
  width: number;
  plotLeft: number;
  boxWidth: number;
}) {
  // Beside the crosshair, on the side with more room, and inside the chart.
  const w = Math.min(TOOLTIP_W, boxWidth);
  const beside = left > width * 0.55 ? left - 12 - w : left + 12;
  const x = Math.max(-plotLeft, Math.min(beside, boxWidth - plotLeft - w));
  const shown = point.changes.slice(-3);
  return (
    <div
      className="pointer-events-none absolute top-2 z-10 rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-lg"
      style={{ left: x, width: w }}
    >
      <div className="mb-1.5 font-medium text-ink-2">{live ? "Now" : absDate(point.t)}</div>
      <ul className="space-y-0.5">
        {series.map((s) => (
          <li key={s.key} className="flex items-center gap-2">
            <svg width="12" height="4" aria-hidden="true">
              <line x1="0" y1="2" x2="12" y2="2" stroke={s.color} strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span className="w-8 text-right text-sm font-semibold text-ink tabular-nums">{int(point[s.key])}</span>
            <span className="text-ink-2">{s.label}</span>
            {compare && <span className="ml-auto text-muted tabular-nums">{compareEnv} {int(compare[s.key])}</span>}
          </li>
        ))}
      </ul>
      {shown.length > 0 && (
        <div className="mt-2 border-t border-line pt-1.5">
          <div className="mb-1 text-muted">What changed</div>
          <ChangeList changes={shown} compact />
          {point.changes.length > shown.length && (
            <div className="mt-1 text-muted">+{point.changes.length - shown.length} more, click to see all</div>
          )}
        </div>
      )}
    </div>
  );
}

function ChangeList({ changes, compact = false }: { changes: HistoryChange[]; compact?: boolean }) {
  if (changes.length === 0) {
    return <p className="text-xs text-muted">No event recorded: the daily point.</p>;
  }
  return (
    <ul className={cx(compact ? "space-y-1" : "space-y-1.5")}>
      {changes.map((c, i) => {
        const t = EVENT_TYPES[c.type] ?? EVENT_FALLBACK;
        return (
          <li key={i} className="flex items-start gap-2">
            <span className={cx("mt-px grid size-5 shrink-0 place-items-center rounded-full", t.tone)} title={t.label}>
              <Icon name={t.icon} className="size-3" />
            </span>
            <span className={cx("min-w-0 flex-1 leading-snug text-ink", compact ? "text-xs" : "text-sm")}>
              {c.title}
              {c.delta && (
                <span className="ml-1.5 inline-flex gap-1 text-xs">
                  <Delta {...c.delta} />
                </span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function HistoryTable({ points, series, since }: { points: HistoryPoint[]; series: Series[]; since: string }) {
  const t0 = Date.parse(since);
  const rows = points.filter((p) => Date.parse(p.t) >= t0).reverse();
  return (
    <div className="max-h-80 overflow-auto">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-surface text-left text-xs text-muted">
          <tr>
            <th scope="col" className="py-1.5 pr-3 font-medium">When</th>
            {series.map((s) => (
              <th key={s.key} scope="col" className="py-1.5 pr-3 text-right font-medium">
                {s.label}
              </th>
            ))}
            <th scope="col" className="py-1.5 font-medium">What changed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p, i) => (
            <tr key={p.t} className="border-t border-line align-top">
              <td className="py-1.5 pr-3 whitespace-nowrap text-ink-2 tabular-nums">{i === 0 ? "Now" : absDate(p.t)}</td>
              {series.map((s) => (
                <td key={s.key} className="py-1.5 pr-3 text-right text-ink tabular-nums">
                  {int(p[s.key])}
                </td>
              ))}
              <td className="py-1.5 text-xs text-ink-2">
                {p.changes.length === 0 ? "—" : p.changes.map((c) => c.title).join(" · ")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
