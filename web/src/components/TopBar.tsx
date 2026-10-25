import { useQuery } from "@tanstack/react-query";
import { Link, NavLink } from "react-router";
import { queries, TODO_FIXABLE, TODO_KEV } from "../api/client";
import type { LiveStatus } from "../api/stream";
import type { Meta } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { todoFindings } from "../lib/findings";
import { absDate, ageMs, plural, relTime, useNow } from "../lib/format";
import { Icon } from "./Icon";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function EnvSwitcher({ onChange, onHover }: { onChange: (env: string) => void; onHover: (env: string) => void }) {
  const { env, envs } = useEnv();
  const clusters = envs.find((e) => e.name === env)?.clusters ?? [];
  return (
    <div className="flex max-w-full min-w-0 items-center gap-3">
      {/* More envs than the width holds (a phone): they wrap, all in sight. */}
      <div
        role="group"
        aria-label="Environment"
        className="inline-flex min-w-0 flex-wrap rounded-lg border border-line bg-page p-0.5"
      >
        {envs.map((e, i) => {
          const active = e.name === env;
          return (
            <button
              key={e.name}
              type="button"
              aria-pressed={active}
              onClick={() => onChange(e.name)}
              onPointerEnter={() => onHover(e.name)}
              onFocus={() => onHover(e.name)}
              title={i < 9 ? `${e.name} (key ${i + 1})` : e.name}
              className={cx(
                "shrink-0 rounded-md px-3.5 py-1 text-sm font-semibold whitespace-nowrap transition-colors",
                active ? "bg-ink text-page shadow-sm" : "text-ink-2 hover:bg-surface-2 hover:text-ink",
              )}
            >
              {e.name}
            </button>
          );
        })}
      </div>
      {clusters.length > 0 && (
        <span className="hidden truncate text-xs text-muted md:block" title={clusters.join(", ")}>
          {clusters.join(" · ")}
        </span>
      )}
    </div>
  );
}

const LIVE: Record<LiveStatus, { label: string; cls: string; dot: string }> = {
  open: { label: "Live", cls: "border-good/40 bg-good/10 text-good-text", dot: "bg-good animate-pulse-dot" },
  connecting: { label: "Connecting…", cls: "border-warn/50 bg-warn/15 text-warn-text", dot: "bg-warn" },
  reconnecting: { label: "Reconnecting…", cls: "border-warn/50 bg-warn/15 text-warn-text", dot: "bg-warn" },
  offline: { label: "Offline", cls: "border-bad/40 bg-bad/10 text-bad-text", dot: "bg-bad" },
};

function LivePill({ status }: { status: LiveStatus }) {
  const s = LIVE[status];
  return (
    <span
      role="status"
      className={cx("inline-flex items-center gap-2 rounded-full border px-2.5 py-0.5 text-xs font-semibold", s.cls)}
    >
      <span className={cx("size-2 rounded-full", s.dot)} aria-hidden="true" />
      {s.label}
    </span>
  );
}

function DbFreshness({ vulnDb }: { vulnDb: Meta["vulnDb"] }) {
  const now = useNow(60_000);
  // Anchore publishes a DB a day, sometimes hours late: only two days without
  // one is a problem. paindash checks every hour: three hours without a check
  // means it is stuck.
  const old = ageMs(vulnDb.builtAt, now) > 2 * DAY;
  const unchecked = vulnDb.checkedAt != null && ageMs(vulnDb.checkedAt, now) > 3 * HOUR;
  const stale = old || unchecked;
  const title = [
    vulnDb.builtAt && `DB built ${absDate(vulnDb.builtAt)}`,
    vulnDb.checkedAt && `checked ${relTime(vulnDb.checkedAt, now)}`,
    old && "no new DB for 2 days: is the feed still published?",
    unchecked && "no check for 3 hours: is the scanner stuck?",
  ]
    .filter(Boolean)
    .join(", ");
  return (
    <span
      title={title || "DB date unknown"}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs",
        stale ? "border border-warn/50 bg-warn/15 font-medium text-warn-text" : "text-muted",
      )}
    >
      {stale ? <Icon name="alert" className="size-3" /> : <Icon name="database" className="size-3" />}
      CVE DB: {vulnDb.builtAt ? relTime(vulnDb.builtAt, now) : "unknown"}
    </span>
  );
}

/** Exceptions (all envs) close to expiry: someone has to renew or let them go. */
function ExpiringExceptions() {
  const { env, scope, href } = useEnv();
  const n = useQuery(queries.summary(env, scope)).data?.exceptionsExpiring ?? 0;
  if (n === 0) return null;
  return (
    <Link
      to={href("/exceptions")}
      className="inline-flex items-center gap-1.5 rounded-full border border-warn/50 bg-warn/15 px-2 py-0.5 text-xs font-medium text-warn-text hover:underline"
    >
      <Icon name="clock" className="size-3" />
      {plural(n, "exception")} expiring soon
    </Link>
  );
}

function TodoCount() {
  const { env, scope } = useEnv();
  const fixable = useQuery(queries.findings(env, TODO_FIXABLE, scope));
  const kev = useQuery(queries.findings(env, TODO_KEV, scope));
  if (!fixable.data || !kev.data) return null;
  const n = todoFindings(fixable.data.items, kev.data.items).length;
  if (n === 0) return null;
  return (
    <span className="ml-1.5 rounded-full bg-surface-2 px-1.5 text-xs font-semibold tabular-nums text-ink-2">{n}</span>
  );
}

export function TopBar({
  meta,
  live,
  onEnvChange,
  onEnvHover,
}: {
  meta: Meta;
  live: LiveStatus;
  onEnvChange: (env: string) => void;
  onEnvHover: (env: string) => void;
}) {
  const { href } = useEnv();
  const tab = ({ isActive }: { isActive: boolean }) =>
    cx(
      "-mb-px inline-flex items-center border-b-2 px-1 pb-2.5 text-sm font-medium whitespace-nowrap",
      isActive ? "border-ink text-ink" : "border-transparent text-ink-2 hover:text-ink",
    );

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-surface/95 backdrop-blur">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-5 gap-y-2 px-4 pt-3 pb-2.5 sm:px-6">
        <Link to={href("/")} className="flex items-center gap-2 text-lg font-bold tracking-tight text-ink">
          <svg viewBox="0 0 32 32" className="size-6" aria-hidden="true">
            <rect width="32" height="32" rx="7" className="fill-ink" />
            <rect x="7" y="18" width="4" height="7" rx="1.5" className="fill-sev-low" />
            <rect x="14" y="12" width="4" height="13" rx="1.5" className="fill-sev-high" />
            <rect x="21" y="7" width="4" height="18" rx="1.5" className="fill-sev-critical" />
          </svg>
          paindash
        </Link>
        <EnvSwitcher onChange={onEnvChange} onHover={onEnvHover} />
        <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1.5">
          {meta.demo && (
            <span
              className="rounded border border-accent/50 bg-accent-fill/15 px-1.5 py-0.5 text-xs font-bold tracking-wider text-accent"
              title="Demo mode: simulated data"
            >
              DEMO
            </span>
          )}
          {meta.authDisabled && !meta.demo && (
            <span
              className="inline-flex items-center gap-1 rounded border border-warn/50 bg-warn/15 px-1.5 py-0.5 text-xs font-semibold text-warn-text"
              title="Authentication is disabled: anyone who can reach paindash sees everything and can record exceptions"
            >
              <Icon name="alert" className="size-3" /> No auth
            </span>
          )}
          <ExpiringExceptions />
          <LivePill status={live} />
          <DbFreshness vulnDb={meta.vulnDb} />
          {meta.user?.email && (
            <span className="hidden text-xs text-muted lg:inline" title={meta.user.groups.join(", ")}>
              {meta.user.email}
            </span>
          )}
          {meta.user && !meta.user.canEdit && (
            <span
              className="rounded border border-line px-1.5 py-0.5 text-xs text-muted"
              title="You can read everything, but recording and revoking exceptions is left to editors"
            >
              Read-only
            </span>
          )}
          {meta.signOut && (
            // A plain form: the session cookie is HttpOnly, the server ends it.
            <form method="post" action="/auth/logout">
              <button type="submit" className="text-xs font-medium text-ink-2 hover:text-ink">
                Sign out
              </button>
            </form>
          )}
        </div>
      </div>
      {/* pb-px holds the tabs' -mb-px inside the scroll box (else it scrolls
          vertically by 1px); -mb-px lays the active tab over the header border. */}
      <nav className="mx-auto -mb-px flex max-w-[1600px] gap-5 overflow-x-auto overflow-y-hidden px-4 pb-px sm:px-6" aria-label="Views">
        <NavLink to={href("/")} end className={tab}>
          To fix
          <TodoCount />
        </NavLink>
        <NavLink to={href("/workloads")} className={tab}>
          Workloads
        </NavLink>
        <NavLink to={href("/vulns")} className={tab}>
          All vulnerabilities
        </NavLink>
        <NavLink to={href("/exceptions")} className={tab}>
          Exceptions
        </NavLink>
      </nav>
    </header>
  );
}
