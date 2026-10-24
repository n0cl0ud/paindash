import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError, holdReload, invalidateExceptionViews, queries } from "../api/client";
import { VEX_JUSTIFICATIONS, type Exception, type Finding, type VexJustification } from "../api/types";
import { dateInput, JUSTIFICATION_LABEL } from "../lib/exceptions";
import { uniqueWorkloads } from "../lib/findings";
import { day } from "../lib/format";
import { componentId, namespaceOf } from "../lib/scope";
import { Icon } from "./Icon";

type Reach = "all" | "namespace" | "workload";

const DAY = 86_400_000;
const MIN_STATEMENT = 10;
const DEFAULT_DAYS = 90;
const MAX_DAYS = 180;

const FIELD =
  "rounded-lg border border-line bg-page px-2.5 py-1.5 text-sm text-ink placeholder:text-muted focus:border-accent-fill focus:outline-none disabled:opacity-50";

function Choice({
  checked,
  onSelect,
  label,
  children,
}: {
  checked: boolean;
  onSelect: () => void;
  label: string;
  children?: ReactNode;
}) {
  return (
    <label className="flex min-h-8 flex-wrap items-center gap-x-2 gap-y-1 text-sm text-ink">
      <input type="radio" name="reach" checked={checked} onChange={onSelect} className="size-3.5 accent-accent-fill" />
      {label}
      {children}
    </label>
  );
}

/**
 * Records an OpenVEX "not_affected" statement for this vuln + package, in all
 * workloads, one namespace or one workload (across every env). The server
 * takes the author from the login; every exception expires.
 */
export function ExceptionForm({
  f,
  onDone,
  onCancel,
}: {
  f: Finding;
  onDone: (e: Exception) => void;
  onCancel: () => void;
}) {
  const qc = useQueryClient();
  const user = useQuery(queries.meta()).data?.user;
  const id = useId();
  useEffect(holdReload, []); // an expired session must not wipe what is being typed

  // Only the namespaces and workloads this finding actually has.
  const workloads = useMemo(() => [...new Set(uniqueWorkloads(f).map(componentId))].sort(), [f]);
  const namespaces = useMemo(() => [...new Set(workloads.map(namespaceOf))], [workloads]);

  // Default: the narrowest rule that still covers every affected workload.
  const [reach, setReach] = useState<Reach>(
    workloads.length === 1 ? "workload" : namespaces.length === 1 ? "namespace" : "all",
  );
  const [ns, setNs] = useState(namespaces[0] ?? "");
  const [wl, setWl] = useState(workloads[0] ?? "");
  const [justification, setJustification] = useState<VexJustification | "">("");
  const [statement, setStatement] = useState("");
  const [expires, setExpires] = useState(() => dateInput(DEFAULT_DAYS));

  const create = useMutation({
    mutationFn: api.createException,
    onSuccess: (e) => {
      invalidateExceptionViews(qc);
      onDone(e);
    },
  });

  const min = dateInput(1);
  const max = dateInput(MAX_DAYS);
  const valid =
    justification !== "" &&
    statement.trim().length >= MIN_STATEMENT &&
    expires >= min &&
    expires <= max &&
    (reach !== "namespace" || ns !== "") &&
    (reach !== "workload" || wl !== "");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!valid || create.isPending) return;
    const wlNs = namespaceOf(wl);
    create.mutate({
      vulnId: f.vulnId,
      package: f.package.name,
      namespace: reach === "namespace" ? ns : reach === "workload" ? wlNs : undefined,
      workload: reach === "workload" ? wl.slice(wlNs.length + 1) : undefined, // the name, as in namespace/name
      justification: justification as VexJustification,
      statement: statement.trim(),
      // End of the chosen day (local), never past the server's 180-day limit.
      expiresAt: new Date(
        Math.min(Date.parse(`${expires}T23:59:59`), Date.now() + MAX_DAYS * DAY - 60_000),
      ).toISOString(),
    });
  };

  const error = create.error;
  const errorText =
    error instanceof ApiError ? error.detail || error.message : error ? "The server cannot be reached right now." : "";

  return (
    <form
      onSubmit={submit}
      aria-labelledby={`${id}-title`}
      className="space-y-4 rounded-lg border border-line-strong bg-page/50 p-4"
    >
      <div>
        <h3 id={`${id}-title`} className="flex items-center gap-2 text-sm font-semibold text-ink">
          <Icon name="shieldOff" className="size-4" /> Mark as not affected
        </h3>
        <p className="mt-0.5 text-xs text-muted">
          <span className="font-mono">{f.vulnId}</span> in <span className="font-mono">{f.package.name}</span>, in
          every env.
        </p>
      </div>

      <fieldset className="space-y-1">
        <legend className="mb-1 text-xs font-semibold tracking-wide text-muted uppercase">Applies to</legend>
        <Choice checked={reach === "all"} onSelect={() => setReach("all")} label="All workloads" />
        {namespaces.length > 0 && (
          <Choice checked={reach === "namespace"} onSelect={() => setReach("namespace")} label="Only in namespace">
            {namespaces.length > 1 ? (
              <select
                aria-label="Namespace"
                value={ns}
                onChange={(e) => {
                  setNs(e.target.value);
                  setReach("namespace");
                }}
                className={`${FIELD} py-1 font-mono`}
              >
                {namespaces.map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
            ) : (
              <span className="font-mono">{ns}</span>
            )}
          </Choice>
        )}
        {workloads.length > 0 && (
          <Choice checked={reach === "workload"} onSelect={() => setReach("workload")} label="Only in this workload">
            {workloads.length > 1 ? (
              <select
                aria-label="Workload"
                value={wl}
                onChange={(e) => {
                  setWl(e.target.value);
                  setReach("workload");
                }}
                className={`${FIELD} max-w-full py-1 font-mono`}
              >
                {workloads.map((w) => (
                  <option key={w}>{w}</option>
                ))}
              </select>
            ) : (
              <span className="font-mono">{wl}</span>
            )}
          </Choice>
        )}
      </fieldset>

      <label className="block space-y-1">
        <span className="text-xs font-semibold tracking-wide text-muted uppercase">Justification</span>
        <select
          required
          value={justification}
          onChange={(e) => setJustification(e.target.value as VexJustification)}
          className={`${FIELD} block w-full`}
        >
          <option value="" disabled>
            Choose a justification…
          </option>
          {VEX_JUSTIFICATIONS.map((j) => (
            <option key={j} value={j}>
              {JUSTIFICATION_LABEL[j]}
            </option>
          ))}
        </select>
      </label>

      <label className="block space-y-1">
        <span className="flex items-baseline justify-between text-xs">
          <span className="font-semibold tracking-wide text-muted uppercase">Statement</span>
          <span className="text-muted tabular-nums">
            {statement.trim().length < MIN_STATEMENT ? `at least ${MIN_STATEMENT} characters` : ""}
          </span>
        </span>
        <textarea
          required
          minLength={MIN_STATEMENT}
          rows={3}
          value={statement}
          onChange={(e) => setStatement(e.target.value)}
          placeholder="Why this image is not affected, e.g. the vulnerable function is never called."
          className={`${FIELD} block w-full resize-y`}
        />
      </label>

      <label className="block space-y-1">
        <span className="text-xs font-semibold tracking-wide text-muted uppercase">Expires on</span>
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <input
            type="date"
            required
            min={min}
            max={max}
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            className={FIELD}
          />
          <span className="text-xs text-muted">{MAX_DAYS} days at most</span>
        </span>
      </label>

      <p className="flex gap-2 rounded-md bg-surface-2 px-3 py-2 text-xs text-ink-2">
        <Icon name="alert" className="mt-px size-3.5 shrink-0" />
        <span>
          Recorded with your name{user?.email ? ` (${user.email})` : ""} and listed under Exceptions. It expires at
          the end of {expires ? day(`${expires}T00:00:00`) : "the chosen day"}: the finding then comes back in the
          lists.
        </span>
      </p>

      {errorText && (
        <p role="alert" className="rounded-md border border-bad/40 bg-bad/10 px-3 py-2 text-sm text-bad-text">
          {errorText}
        </p>
      )}

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={!valid || create.isPending}
          className="rounded-lg bg-ink px-3 py-1.5 text-sm font-semibold text-page hover:opacity-90 disabled:opacity-40"
        >
          {create.isPending ? "Recording…" : "Record exception"}
        </button>
        <button type="button" onClick={onCancel} className="text-sm font-medium text-ink-2 hover:text-ink">
          Cancel
        </button>
      </div>
    </form>
  );
}
