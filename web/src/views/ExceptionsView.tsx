import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router";
import { api, ApiError, invalidateExceptionViews, OPENVEX_URL, queries } from "../api/client";
import type { Exception } from "../api/types";
import { Icon } from "../components/Icon";
import { Card, EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { daysLeft, exceptionScope, JUSTIFICATION_LABEL } from "../lib/exceptions";
import { absDate, day, int, plural, relTime, useNow } from "../lib/format";

// Expiring first (they need a decision), then active, then the history.
const STATE_RANK: Record<Exception["state"], number> = { expiring: 0, active: 1, expired: 2, revoked: 3 };

function StateBadge({ e, now }: { e: Exception; now: number }) {
  const base = "inline-flex items-center gap-1 rounded border px-1.5 py-px text-[11px] font-semibold whitespace-nowrap";
  switch (e.state) {
    case "expiring": {
      const n = daysLeft(e.expiresAt, now);
      return (
        <span className={cx(base, "border-warn/50 bg-warn/15 text-warn-text")}>
          <Icon name="clock" className="size-3" />
          {n === 0 ? "expires today" : `expiring in ${plural(n, "day")}`}
        </span>
      );
    }
    case "active":
      return <span className={cx(base, "border-good/40 bg-good/10 text-good-text")}>active</span>;
    case "expired":
      return <span className={cx(base, "border-line bg-surface-2 text-muted")}>expired</span>;
    case "revoked":
      return (
        <span
          className={cx(base, "border-line bg-surface-2 text-muted")}
          title={e.revokedAt ? `Revoked by ${e.revokedBy ?? "unknown"}, ${absDate(e.revokedAt)}` : undefined}
        >
          revoked
        </span>
      );
  }
}

/** "Revoke", then an explicit confirm step (Escape or Cancel backs out). */
function Revoke({ e }: { e: Exception }) {
  const { canEdit } = useEnv();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const revokeRef = useRef<HTMLButtonElement>(null);
  const backOut = useRef(false);
  const revoke = useMutation({
    mutationFn: () => api.revokeException(e.id),
    onSuccess: () => invalidateExceptionViews(qc),
  });

  // Give focus back to "Revoke" after backing out of the confirm step.
  useEffect(() => {
    if (!confirming && backOut.current) revokeRef.current?.focus();
    backOut.current = false;
  }, [confirming]);

  if (e.state === "expired" || e.state === "revoked" || !canEdit) return null;
  if (!confirming) {
    return (
      <button
        ref={revokeRef}
        type="button"
        onClick={() => setConfirming(true)}
        className="text-sm font-medium text-bad-text hover:underline"
      >
        Revoke
      </button>
    );
  }
  const cancel = () => {
    backOut.current = true;
    setConfirming(false);
    revoke.reset();
  };
  const error = revoke.error instanceof ApiError ? revoke.error.detail || revoke.error.message : revoke.error && "Failed";
  return (
    <span
      className="inline-flex flex-wrap items-center gap-2"
      onKeyDown={(ev) => {
        if (ev.key === "Escape") cancel();
      }}
    >
      <button
        type="button"
        autoFocus
        disabled={revoke.isPending}
        onClick={() => revoke.mutate()}
        title="The finding comes back in the lists"
        className="rounded-md bg-bad px-2 py-0.5 text-xs font-semibold whitespace-nowrap text-white hover:opacity-90 disabled:opacity-50"
      >
        {revoke.isPending ? "Revoking…" : "Confirm revoke"}
      </button>
      <button type="button" onClick={cancel} className="text-xs text-ink-2 hover:text-ink">
        Cancel
      </button>
      {error && (
        <span role="alert" className="text-xs text-bad-text">
          {error}
        </span>
      )}
    </span>
  );
}

function Row({ e, now }: { e: Exception; now: number }) {
  const { href } = useEnv();
  const inactive = e.state === "expired" || e.state === "revoked";
  return (
    <tr className={cx("border-b border-line align-top last:border-0", e.state === "expiring" && "bg-warn/10")}>
      <td
        className={cx(
          "border-l-[3px] px-4 py-2.5",
          e.state === "expiring" ? "border-l-warn" : "border-l-transparent",
          inactive && "opacity-60",
        )}
      >
        <Link
          to={href(`/vulns?q=${encodeURIComponent(e.vulnId)}&excepted=1`)}
          className="font-mono font-semibold whitespace-nowrap text-ink hover:underline"
        >
          {e.vulnId}
        </Link>
      </td>
      <td className={cx("px-4 py-2.5 font-mono text-[13px] text-ink", inactive && "opacity-60")}>{e.package}</td>
      <td className={cx("px-4 py-2.5", inactive && "opacity-60")}>
        {e.namespace ? (
          <span className="font-mono text-xs text-ink-2">{exceptionScope(e)}</span>
        ) : (
          <span className="text-ink-2">All workloads</span>
        )}
      </td>
      <td className={cx("min-w-40 px-4 py-2.5 text-ink-2", inactive && "opacity-60")}>
        {JUSTIFICATION_LABEL[e.justification] ?? e.justification}
      </td>
      <td className={cx("px-4 py-2.5 text-ink-2", inactive && "opacity-60")}>
        <p className="line-clamp-2 max-w-xs min-w-48" title={e.statement}>
          {e.statement}
        </p>
      </td>
      <td className={cx("px-4 py-2.5 whitespace-nowrap text-ink-2", inactive && "opacity-60")}>{e.author}</td>
      <td className={cx("px-4 py-2.5 whitespace-nowrap text-ink-2", inactive && "opacity-60")} title={absDate(e.createdAt)}>
        {relTime(e.createdAt, now)}
      </td>
      <td className={cx("px-4 py-2.5 whitespace-nowrap", inactive && "opacity-60")} title={absDate(e.expiresAt)}>
        <span className="text-ink">{relTime(e.expiresAt, now)}</span>
        <span className="block text-xs text-muted">{day(e.expiresAt)}</span>
      </td>
      <td className="px-4 py-2.5">
        <StateBadge e={e} now={now} />
      </td>
      <td className="px-4 py-2.5 text-right">
        <Revoke e={e} />
      </td>
    </tr>
  );
}

/** Every exception, all envs: what is hidden from the lists, by whom, until when. */
export function ExceptionsView() {
  const now = useNow(60_000);
  const { data, error, refetch } = useQuery(queries.exceptions());

  const rows = useMemo(
    () =>
      [...(data?.items ?? [])].sort(
        (a, b) =>
          STATE_RANK[a.state] - STATE_RANK[b.state] ||
          (a.state === "expiring" ? Date.parse(a.expiresAt) - Date.parse(b.expiresAt) : 0),
      ),
    [data],
  );
  const active = rows.filter((e) => e.state === "active" || e.state === "expiring").length;
  const expiring = rows.filter((e) => e.state === "expiring").length;

  return (
    <section aria-labelledby="exc-title">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h1 id="exc-title" className="text-xl font-semibold text-ink">
          Exceptions <span className="font-normal text-muted">all envs</span>
        </h1>
        {data && (
          <p className="text-sm text-muted">
            {int(active)} active
            {expiring > 0 && <span className="font-medium text-warn-text"> · {int(expiring)} expiring soon</span>}
          </p>
        )}
        <a
          href={OPENVEX_URL}
          download="paindash.openvex.json"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline sm:ml-auto"
        >
          <Icon name="download" className="size-3.5" /> Download OpenVEX
        </a>
      </div>
      <p className="mb-3 max-w-3xl text-sm text-ink-2">
        Findings marked as not affected. They stay out of the lists and counts until they expire or are revoked,
        then come back on their own.
      </p>

      <Card>
        {!data && error ? (
          <ErrorState error={error} onRetry={() => void refetch()} />
        ) : !data ? (
          <SkeletonRows rows={4} />
        ) : rows.length === 0 ? (
          <EmptyState icon="shieldOff" title="No exceptions">
            Open a finding and use “Mark as not affected” to record one.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-line bg-page text-left text-xs text-muted">
                <tr>
                  {["Vulnerability", "Package", "Scope", "Justification", "Statement", "Author", "Created", "Expires", "State"].map(
                    (h) => (
                      <th key={h} scope="col" className="px-4 py-2 font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ),
                  )}
                  {/* relative: keeps the sr-only label inside the scrolling table */}
                  <th scope="col" className="relative px-4 py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <Row key={e.id} e={e} now={now} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </section>
  );
}
