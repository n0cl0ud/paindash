import { useQuery } from "@tanstack/react-query";
import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { queries } from "../api/client";
import type { Exception, Finding } from "../api/types";
import { useEnv } from "../lib/env";
import { exceptionScope, JUSTIFICATION_LABEL, SOURCE_LABEL } from "../lib/exceptions";
import { findingKey, workloadPath } from "../lib/findings";
import { cvePrompt, cveRepos } from "../lib/fixPrompt";
import { absDate, day, ordinal, pct, relTime, shortDigest } from "../lib/format";
import { ExperimentalBadge, ExposureBadge, IdentificationBadges, KevBadge, SeverityBadge, SUSPECT_HINT } from "./Badges";
import { Drawer } from "./Drawer";
import { COPY_BLOCKED, CopyButton, RepoChips, useCopy } from "./CopyButton";
import { ExceptionForm } from "./ExceptionForm";
import { FixVersion } from "./FindingRow";
import { Icon } from "./Icon";

/**
 * Keeps the opened finding in sync with live data: when the list refreshes the
 * drawer shows the fresh copy; when the finding disappears (fixed), the last
 * known copy stays visible with a "no longer detected" notice.
 */
export function useFindingSelection(list: Finding[] | undefined) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const key = selected ? findingKey(selected) : null;
  const current = key && list ? list.find((f) => findingKey(f) === key) : undefined;
  const close = useCallback(() => setSelected(null), []);
  return {
    finding: current ?? selected,
    gone: Boolean(selected && list && !current),
    open: setSelected,
    close,
  };
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">{title}</h3>
      {children}
    </section>
  );
}

/** An exception already hides this finding (shown with ?include=excepted). */
function ExceptionInfo({ e, onClose }: { e: Exception; onClose: () => void }) {
  const { href } = useEnv();
  return (
    <section className="rounded-lg border border-line-strong bg-page p-4 text-sm">
      <h3 className="flex items-center gap-2 font-semibold text-ink">
        <Icon name="shieldOff" className="size-4" />
        Not affected: excepted until {day(e.expiresAt)}
      </h3>
      <p className="mt-1 text-ink-2">
        {JUSTIFICATION_LABEL[e.justification] ?? e.justification} · {exceptionScope(e)}
      </p>
      <p className="mt-1 whitespace-pre-line text-ink-2">“{e.statement}”</p>
      <p className="mt-2 text-xs text-muted">
        By {e.author}, <span title={absDate(e.createdAt)}>{relTime(e.createdAt)}</span> ·{" "}
        <Link to={href("/exceptions")} onClick={onClose} className="font-medium text-accent hover:underline">
          Manage exceptions
        </Link>
      </p>
    </section>
  );
}

/** The fix prompt of this vulnerability: every image of the env that has it. */
function FixPrompt({ f }: { f: Finding }) {
  const { env, href } = useEnv();
  const meta = useQuery(queries.meta()).data;
  const gitopsRepo = meta?.gitopsRepo ?? "";
  const promotion = meta?.promotion;
  const origins = useQuery(queries.origins()).data;
  const [open, setOpen] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);
  const { state, copy } = useCopy(preRef);

  const text = useMemo(() => {
    if (!origins) return "";
    const page = new URL(href("/vulns"), window.location.origin);
    page.searchParams.set("q", f.vulnId);
    return cvePrompt({ finding: f, env, origins, gitopsRepo, promotion: promotion ?? [], pageUrl: page.toString(), date: new Date() });
  }, [f, env, origins, gitopsRepo, promotion, href]);
  const repos = useMemo(() => (origins ? cveRepos(f, origins, gitopsRepo) : []), [f, origins, gitopsRepo]);
  const images = new Set(f.workloads.map((w) => w.digest)).size;

  return (
    <section className="rounded-lg border border-line p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Icon name="terminal" className="size-4 text-accent" />
            Fix prompt
            <ExperimentalBadge />
          </h3>
          <p className="mt-0.5 text-xs text-muted">
            For Claude Code or any coding agent: fixes it in the {images === 1 ? "image" : `${images} images`} that{" "}
            {images === 1 ? "has" : "have"} it and opens the pull requests.
          </p>
        </div>
        <CopyButton state={state} onClick={() => text && void copy(text)} />
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <RepoChips repos={repos} />
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-ink"
        >
          {open ? "Hide" : "Show"} prompt
          <Icon name="chevronDown" className={`size-3.5 transition-transform ${open ? "rotate-180" : ""}`} />
        </button>
      </div>
      {state === "failed" && <p className="mt-3 text-sm text-ink-2">{COPY_BLOCKED}</p>}
      {(open || state === "failed") && (
        <pre
          ref={preRef}
          tabIndex={0}
          aria-label="Prompt"
          className="mt-3 max-h-80 overflow-auto rounded-lg border border-line bg-page p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap text-ink-2 [overflow-wrap:anywhere]"
        >
          {text}
        </pre>
      )}
    </section>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-page px-3 py-2">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5 text-sm font-semibold text-ink">{children}</dd>
    </div>
  );
}

export function FindingDrawer({
  finding: f,
  gone,
  onClose,
}: {
  finding: Finding;
  gone: boolean;
  onClose: () => void;
}) {
  const { href, canEdit } = useEnv();
  const aliases = f.aliases.filter((a) => a !== f.vulnId);
  const [form, setForm] = useState(false);
  // The exception just recorded from here (the list refresh may drop the finding).
  const [created, setCreated] = useState<Exception | null>(null);

  return (
    <Drawer
      titleId="drawer-title"
      onClose={onClose}
      header={
        <>
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 id="drawer-title" className="font-mono text-lg font-semibold break-all text-ink">
              {f.vulnId}
            </h2>
            {f.kev && <KevBadge addedAt={f.kevAddedAt} />}
            <SeverityBadge severity={f.severity} />
            <ExposureBadge exposure={f.exposure} />
            <IdentificationBadges f={f} />
          </div>
          <div className="mt-1">
            <FixVersion f={f} />
          </div>
        </>
      }
    >
      {gone && !created && (
        <p className="flex items-center gap-2 rounded-lg border border-good/40 bg-good/10 px-3 py-2 text-sm text-good-text">
          <Icon name="check" /> This vulnerability is no longer detected in this environment.
        </p>
      )}

      {f.suspect && (
        <p className="flex gap-2 rounded-lg border border-warn/50 bg-warn/15 px-3 py-2 text-sm text-warn-text">
          <Icon name="alert" className="mt-0.5 size-4 shrink-0" />
          <span>
            <span className="font-semibold">Suspect.</span> {SUSPECT_HINT}.
          </span>
        </p>
      )}

      {f.promotion.length > 0 && (
        <section className="rounded-lg border border-good/40 bg-good/10 p-4">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-good-text">
            <Icon name="check" />
            Already fixed elsewhere: promote the image
          </h3>
          <ul className="mt-3 space-y-2.5">
            {f.promotion.map((p) => (
              <li key={`${p.env}/${p.cluster}/${p.digest}`} className="text-sm">
                <span className="font-semibold text-ink">{p.env}</span>
                <span className="text-muted"> · {p.cluster}</span>
                <div className="mt-0.5 font-mono text-xs break-all text-ink-2">{p.image}</div>
                <div className="font-mono text-xs text-muted" title={p.digest}>
                  {shortDigest(p.digest)}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {!gone && !created && !f.exception && f.fixedIn.length > 0 && <FixPrompt f={f} />}

      {created ? (
        <p className="flex gap-2 rounded-lg border border-line-strong bg-page px-3 py-2 text-sm text-ink-2">
          <Icon name="shieldOff" className="mt-0.5 size-4 shrink-0" />
          <span>
            Exception recorded for{" "}
            {created.namespace ? <span className="font-mono">{exceptionScope(created)}</span> : "all workloads"} until{" "}
            {day(created.expiresAt)}.{" "}
            <Link to={href("/exceptions")} onClick={onClose} className="font-medium text-accent hover:underline">
              See exceptions
            </Link>
          </span>
        </p>
      ) : f.exception ? (
        <ExceptionInfo e={f.exception} onClose={onClose} />
      ) : !canEdit ? (
        <p className="text-sm text-muted">Read-only access: exceptions are recorded by editors.</p>
      ) : form ? (
        <ExceptionForm f={f} onDone={setCreated} onCancel={() => setForm(false)} />
      ) : (
        <button
          type="button"
          onClick={() => setForm(true)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1 text-sm font-medium text-ink-2 hover:border-line-strong hover:text-ink"
        >
          <Icon name="shieldOff" className="size-3.5" /> Mark as not affected…
        </button>
      )}

      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="CVSS">{f.cvss == null ? "—" : f.cvss.toFixed(1)}</Stat>
        <Stat label="EPSS">{pct(f.epss)}</Stat>
        <Stat label="EPSS percentile">
          {f.epssPercentile == null ? "—" : ordinal(Math.round(f.epssPercentile * 100))}
        </Stat>
        <Stat label="First seen">
          <span title={absDate(f.firstSeen)}>{relTime(f.firstSeen)}</span>
        </Stat>
      </dl>

      {f.description && (
        <Section title="Description">
          <p className="text-sm leading-relaxed whitespace-pre-line text-ink-2">{f.description}</p>
        </Section>
      )}

      <Section title="Package">
        <p className="text-sm text-ink-2">
          Identified from: <span className="font-medium text-ink">{SOURCE_LABEL[f.source] ?? f.source}</span>
        </p>
        {f.location && <p className="mt-1 font-mono text-xs break-all text-ink-2">{f.location}</p>}
        <p className="mt-1 font-mono text-xs break-all text-muted">
          {f.package.type} · {f.package.purl}
        </p>
      </Section>

      <Section title="References">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {f.url && (
            <a
              href={f.url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1.5 font-medium text-accent hover:underline"
            >
              View advisory <Icon name="external" className="size-3.5" />
            </a>
          )}
          {aliases.map((a) => (
            <span key={a} className="rounded border border-line px-1.5 py-0.5 font-mono text-xs text-ink-2">
              {a}
            </span>
          ))}
        </div>
      </Section>

      <Section title={`Affected containers (${f.workloads.length})`}>
        <ul className="divide-y divide-line rounded-lg border border-line">
          {f.workloads.map((w) => (
            <li key={`${w.cluster}/${w.namespace}/${w.kind}/${w.name}/${w.container}`} className="px-3 py-2.5">
              <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
                <Link to={href(workloadPath(w))} onClick={onClose} className="font-medium text-ink hover:underline">
                  {w.namespace}/{w.name}
                </Link>
                <ExposureBadge exposure={w.exposure} className="self-center" />
                <span className="text-xs text-muted">
                  {w.kind} · {w.cluster} · container {w.container}
                </span>
              </div>
              <div className="mt-0.5 font-mono text-xs break-all text-ink-2">{w.image}</div>
              <div className="font-mono text-xs text-muted" title={w.digest}>
                {shortDigest(w.digest)}
              </div>
            </li>
          ))}
        </ul>
      </Section>
    </Drawer>
  );
}
