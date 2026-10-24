import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState, type FocusEvent, type KeyboardEvent } from "react";
import { queries } from "../api/client";
import type { Exposure } from "../api/types";
import { cx } from "../lib/cx";
import { useEnv } from "../lib/env";
import { EXPOSURE_LABEL, EXPOSURE_RANK, EXPOSURES, plural } from "../lib/format";
import { componentId, isScoped, namespaceOf, NO_SCOPE, scopeLabel, scopeTitle } from "../lib/scope";
import { Icon, type IconName } from "./Icon";
import { EmptyState } from "./States";

interface Option {
  id: string; // value stored in the scope
  prefix?: string; // muted start of the label, e.g. "checkout/"
  name: string;
  hint: string;
  icon?: IconName;
}

const toggled = <T extends string>(list: T[], id: T) => (list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);

export const EXPOSURE_MISSING = "Exposure not configured: no Ingress, Traefik IngressRoute or LoadBalancer metrics found";

/**
 * Button + popover with a search box (unless `searchable` is false) and a
 * checkbox list. Keyboard: the search box (or the first checkbox) gets focus
 * on open (ArrowDown on the button opens too), arrows move through the list,
 * Enter in the search box toggles the first match, Escape closes and gives
 * focus back to the button, tabbing out closes. Below `sm` the popover spans
 * the whole scope bar instead of hanging under its button, so that it fits a
 * phone screen. `disabled` (the reason) keeps the button focusable so that
 * its tooltip can be read.
 */
function MultiSelect({
  label,
  options,
  selected,
  onToggle,
  empty,
  searchable = true,
  disabled,
}: {
  label: string;
  options: Option[];
  selected: string[];
  onToggle: (id: string) => void;
  empty: string;
  searchable?: boolean;
  disabled?: string;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  const close = (refocus: boolean) => {
    setOpen(false);
    setQ("");
    if (refocus) button.current?.focus();
  };

  // A click anywhere else closes the popover.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) {
        setOpen(false);
        setQ("");
      }
    };
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [open]);

  const needle = q.trim().toLowerCase();
  const shown = needle ? options.filter((o) => `${o.prefix ?? ""}${o.name}`.toLowerCase().includes(needle)) : options;

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!open) {
      if (e.key === "ArrowDown" && e.target === button.current) {
        e.preventDefault();
        setOpen(true);
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close(true);
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const items = [...(root.current?.querySelectorAll<HTMLElement>("[data-nav]") ?? [])];
      const i = items.indexOf(document.activeElement as HTMLElement);
      const next = items[e.key === "ArrowDown" ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1)];
      if (next) {
        e.preventDefault();
        next.focus();
      }
    }
  };

  // Only focus moving elsewhere (Tab) closes here: clicks are handled above,
  // and Safari does not focus buttons on click (relatedTarget is null).
  const onBlur = (e: FocusEvent<HTMLDivElement>) => {
    if (open && e.relatedTarget && !root.current?.contains(e.relatedTarget)) close(false);
  };

  return (
    <div ref={root} className="sm:relative" onKeyDown={disabled ? undefined : onKeyDown} onBlur={onBlur}>
      <button
        ref={button}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        aria-disabled={disabled ? true : undefined}
        title={disabled}
        onClick={() => {
          if (disabled) return;
          if (open) close(false);
          else setOpen(true);
        }}
        className={cx(
          "inline-flex items-center gap-1.5 rounded-lg border bg-surface px-2.5 py-1 text-sm font-medium",
          disabled
            ? "cursor-not-allowed border-line text-muted opacity-60"
            : open || selected.length > 0
              ? "border-line-strong text-ink"
              : "border-line text-ink-2 hover:border-line-strong hover:text-ink",
        )}
      >
        {label}
        {selected.length > 0 && (
          <span className="rounded-full bg-ink px-1.5 text-xs font-semibold tabular-nums text-page">
            {selected.length}
            <span className="sr-only"> selected</span>
          </span>
        )}
        <Icon name="chevronDown" className={cx("size-3.5 text-muted transition-transform", open && "rotate-180")} />
      </button>
      {open && (
        <div
          id={id}
          role="dialog"
          aria-label={label}
          tabIndex={-1}
          className="absolute inset-x-0 top-full z-20 mt-1.5 overflow-hidden rounded-xl border border-line bg-surface shadow-lg outline-none sm:right-auto sm:w-96"
        >
          {searchable && (
          <div className="border-b border-line p-2">
            <label className="relative block">
              <span className="sr-only">Search {label.toLowerCase()}</span>
              <Icon
                name="search"
                className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted"
              />
              <input
                type="search"
                data-nav
                autoFocus
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && shown[0]) {
                    e.preventDefault();
                    onToggle(shown[0].id);
                  }
                }}
                placeholder={`Search ${label.toLowerCase()}`}
                className="w-full rounded-lg border border-line bg-page py-1.5 pr-3 pl-8 text-sm text-ink placeholder:text-muted focus:border-accent-fill focus:outline-none"
              />
            </label>
          </div>
          )}
          {shown.length === 0 ? (
            <p className="px-3 py-4 text-center text-sm text-muted">{options.length > 0 ? "No match" : empty}</p>
          ) : (
            <ul className="max-h-72 overflow-y-auto py-1" aria-label={label}>
              {shown.map((o, i) => (
                <li key={o.id}>
                  <label className="flex cursor-pointer items-start gap-2.5 px-3 py-1.5 text-sm hover:bg-surface-2">
                    <input
                      type="checkbox"
                      data-nav
                      autoFocus={!searchable && i === 0}
                      checked={selected.includes(o.id)}
                      onChange={() => onToggle(o.id)}
                      className="mt-[3px] size-3.5 shrink-0 accent-accent-fill"
                    />
                    {/* Long names wrap instead of being cut. */}
                    <span className="min-w-0 flex-1 text-ink [overflow-wrap:anywhere]">
                      {o.icon && <Icon name={o.icon} className="mr-1.5 inline-block size-3.5 align-[-2px] text-accent" />}
                      {o.prefix && <span className="text-muted">{o.prefix}</span>}
                      {o.name}
                    </span>
                    <span className="mt-px shrink-0 text-xs text-muted">{o.hint}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Restricts every view to some namespaces, components and/or exposures (see
 * lib/scope.ts). The options list the whole env; selections missing from it
 * (kept when switching env) stay listed so they can be removed.
 */
export function ScopeBar() {
  const { env, scope, setScope, exposureAvailable } = useEnv();
  const { data } = useQuery(queries.workloads(env, NO_SCOPE));
  const bar = useRef<HTMLDivElement>(null);
  // Index of the chip to focus once a removal has re-rendered the bar.
  const refocus = useRef<number | null>(null);

  useEffect(() => {
    if (refocus.current === null) return;
    const chips = bar.current?.querySelectorAll<HTMLElement>("[data-chip]");
    const target = chips?.length
      ? chips[Math.min(refocus.current, chips.length - 1)]
      : bar.current?.querySelector<HTMLElement>("button");
    target?.focus();
    refocus.current = null;
  });

  // Distinct components (namespace/name, possibly on several clusters or
  // kinds, with their widest exposure) and per-namespace / per-exposure counts.
  const { components, perNamespace, perExposure } = useMemo(() => {
    const components = new Map<string, { kinds: Set<string>; exposure: Exposure }>();
    for (const w of data?.items ?? []) {
      const id = componentId(w);
      const c = components.get(id) ?? { kinds: new Set<string>(), exposure: w.exposure };
      c.kinds.add(w.kind);
      if (EXPOSURE_RANK[w.exposure] < EXPOSURE_RANK[c.exposure]) c.exposure = w.exposure;
      components.set(id, c);
    }
    const perNamespace = new Map<string, number>();
    const perExposure = new Map<Exposure, number>();
    for (const [id, c] of components) {
      perNamespace.set(namespaceOf(id), (perNamespace.get(namespaceOf(id)) ?? 0) + 1);
      perExposure.set(c.exposure, (perExposure.get(c.exposure) ?? 0) + 1);
    }
    return { components, perNamespace, perExposure };
  }, [data]);

  const missing = data ? `not in ${env}` : "";
  const nsOptions: Option[] = [...new Set([...perNamespace.keys(), ...scope.ns])].sort().map((ns) => {
    const n = perNamespace.get(ns);
    return { id: ns, name: ns, hint: n === undefined ? missing : plural(n, "component") };
  });
  // Limited to the selected namespaces and exposures, if any (selected ones stay).
  const wlOptions: Option[] = [...new Set([...components.keys(), ...scope.wl])]
    .filter((id) => {
      const exposure = components.get(id)?.exposure;
      return (
        scope.wl.includes(id) ||
        ((scope.ns.length === 0 || scope.ns.includes(namespaceOf(id))) &&
          (scope.exp.length === 0 || (exposure !== undefined && scope.exp.includes(exposure))))
      );
    })
    .sort()
    .map((id) => {
      const ns = namespaceOf(id);
      const c = components.get(id);
      return {
        id,
        prefix: `${ns}/`,
        name: id.slice(ns.length + 1),
        hint: c ? [...c.kinds].join(", ") : missing,
        icon: exposureAvailable && c?.exposure === "internet" ? "globe" : undefined,
      };
    });
  const expOptions: Option[] = EXPOSURES.map((e) => ({
    id: e,
    name: EXPOSURE_LABEL[e],
    hint: data ? plural(perExposure.get(e) ?? 0, "component") : "",
    icon: e === "internet" ? "globe" : undefined,
  }));

  const toggleNs = (ns: string) => {
    const next = toggled(scope.ns, ns);
    // Components narrow the namespaces down (AND): drop those outside them.
    setScope({ ...scope, ns: next, wl: scope.wl.filter((id) => next.includes(namespaceOf(id))) });
  };
  const toggleWl = (id: string) => setScope({ ...scope, wl: toggled(scope.wl, id) });
  const toggleExp = (e: Exposure) => setScope({ ...scope, exp: toggled(scope.exp, e) });

  const chips = [
    ...scope.ns.map((ns) => ({ key: `ns:${ns}`, what: "namespace", prefix: "", name: ns, remove: () => toggleNs(ns) })),
    ...scope.wl.map((id) => {
      const ns = namespaceOf(id);
      return { key: `wl:${id}`, what: "component", prefix: `${ns}/`, name: id.slice(ns.length + 1), remove: () => toggleWl(id) };
    }),
    ...scope.exp.map((e) => ({
      key: `exp:${e}`,
      what: "exposure",
      prefix: "",
      name: EXPOSURE_LABEL[e],
      remove: () => toggleExp(e),
    })),
  ];
  const loading = data ? "" : "Loading…";

  return (
    <div ref={bar} role="group" aria-label="Scope" className="relative flex flex-wrap items-center gap-2">
      <MultiSelect
        label="Namespaces"
        options={nsOptions}
        selected={scope.ns}
        onToggle={toggleNs}
        empty={loading || `No workloads in ${env}`}
      />
      <MultiSelect
        label="Components"
        options={wlOptions}
        selected={scope.wl}
        onToggle={toggleWl}
        empty={loading || (scope.ns.length || scope.exp.length ? "No components match" : `No workloads in ${env}`)}
      />
      <MultiSelect
        label="Exposure"
        options={expOptions}
        selected={scope.exp}
        onToggle={(e) => toggleExp(e as Exposure)}
        empty={loading}
        searchable={false}
        disabled={exposureAvailable ? undefined : EXPOSURE_MISSING}
      />
      {chips.length > 0 && <span className="mx-1 hidden h-5 w-px bg-line sm:block" aria-hidden="true" />}
      {chips.map((c, i) => (
        <span
          key={c.key}
          className={cx(
            "inline-flex max-w-full items-center gap-1 rounded-md border border-line bg-surface py-0.5 pr-0.5 pl-2 text-xs text-ink",
            c.what !== "exposure" && "font-mono",
          )}
        >
          {c.key === "exp:internet" && <Icon name="globe" className="size-3 shrink-0 text-accent" />}
          <span className="truncate" title={`${c.prefix ?? ""}${c.name}`}>
            {c.prefix && <span className="text-muted">{c.prefix}</span>}
            {c.name}
          </span>
          <button
            type="button"
            data-chip
            onClick={() => {
              refocus.current = i;
              c.remove();
            }}
            aria-label={`Remove ${c.what} ${c.prefix}${c.name}`}
            title="Remove"
            className="shrink-0 rounded p-0.5 text-muted hover:bg-surface-2 hover:text-ink"
          >
            <Icon name="close" className="size-3" />
          </button>
        </span>
      ))}
      {chips.length > 0 && (
        <button
          type="button"
          onClick={() => {
            refocus.current = 0;
            setScope(NO_SCOPE);
          }}
          className="px-1 text-sm font-medium text-accent hover:underline"
        >
          Clear
        </button>
      )}
    </div>
  );
}

/** " · 2 namespaces" after a view title, when a scope is active. */
export function ScopeHint() {
  const { scope } = useEnv();
  if (!isScoped(scope)) return null;
  return (
    <span className="font-normal text-muted" title={scopeTitle(scope)}>
      {" "}
      · {scopeLabel(scope)}
    </span>
  );
}

/** Empty state for a scope that matches no workload of the env. */
export function OutOfScope() {
  const { env, scope, setScope } = useEnv();
  return (
    <EmptyState icon="box" title="Nothing in this scope">
      <p>
        No workload in {env} matches this scope ({scopeLabel(scope)}).
      </p>
      <button
        type="button"
        onClick={() => setScope(NO_SCOPE)}
        className="mt-4 text-sm font-medium text-accent hover:underline"
      >
        Clear scope
      </button>
    </EmptyState>
  );
}
