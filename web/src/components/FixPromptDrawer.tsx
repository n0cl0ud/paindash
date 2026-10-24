import { useQuery } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import { queries } from "../api/client";
import type { WorkloadDetail } from "../api/types";
import { cx } from "../lib/cx";
import { FIX_SCOPES, fixPrompt, fixRepos, scoped, type FixScope } from "../lib/fixPrompt";
import { int } from "../lib/format";
import { COPY_BLOCKED, CopyButton, RepoChips, useCopy } from "./CopyButton";
import { Drawer } from "./Drawer";
import { ExperimentalBadge } from "./Badges";
import { Icon } from "./Icon";

/** The fix prompt of a workload, to paste into Claude Code or any coding agent. */
export function FixPromptDrawer({ detail, onClose }: { detail: WorkloadDetail; onClose: () => void }) {
  const meta = useQuery(queries.meta()).data;
  const gitopsRepo = meta?.gitopsRepo ?? "";
  const promotion = meta?.promotion;
  const todo = useMemo(() => scoped(detail.findings, "todo").work.length, [detail]);
  const fixable = useMemo(() => scoped(detail.findings, "fixable").work.length, [detail]);
  const [scope, setScope] = useState<FixScope>(todo > 0 ? "todo" : "fixable");
  const preRef = useRef<HTMLPreElement>(null);
  const { state, copy } = useCopy(preRef);

  const text = useMemo(
    () => fixPrompt({ detail, scope, gitopsRepo, promotion: promotion ?? [], pageUrl: window.location.href, date: new Date() }),
    [detail, scope, gitopsRepo, promotion],
  );
  const repos = useMemo(() => fixRepos(detail, scope, gitopsRepo), [detail, scope, gitopsRepo]);
  const guessed = detail.workload.containers.filter((c) => c.origin?.firstParty && c.origin.guessed);
  const w = detail.workload;

  return (
    <Drawer
      titleId="fix-prompt-title"
      onClose={onClose}
      header={
        <>
          <h2 id="fix-prompt-title" className="flex items-center gap-2 text-lg font-semibold text-ink">
            <Icon name="terminal" className="size-5 text-accent" />
            Fix prompt
            <ExperimentalBadge />
          </h2>
          <p className="mt-1 text-sm text-muted">
            Paste it into Claude Code or any coding agent with <span className="font-mono text-xs">git</span> and{" "}
            <span className="font-mono text-xs">gh</span> access: it fixes {w.namespace}/{w.name} and opens the pull
            requests, for you to review.
          </p>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="inline-flex rounded-lg border border-line bg-page p-0.5 text-sm" role="group" aria-label="Scope">
            {(["todo", "fixable"] as const).map((s) => {
              const n = s === "todo" ? todo : fixable;
              return (
                <button
                  key={s}
                  type="button"
                  disabled={n === 0}
                  aria-pressed={scope === s}
                  onClick={() => setScope(s)}
                  title={FIX_SCOPES[s].hint}
                  className={cx(
                    "rounded-md px-3 py-0.5 font-medium disabled:opacity-40",
                    scope === s ? "bg-ink text-page" : "text-ink-2 hover:text-ink",
                  )}
                >
                  {FIX_SCOPES[s].label} ({int(n)})
                </button>
              );
            })}
          </div>
          <CopyButton state={state} onClick={() => void copy(text)} className="ml-auto" />
        </div>

        <RepoChips repos={repos} />

        {guessed.length > 0 && (
          <p className="flex gap-2 rounded-lg border border-warn/50 bg-warn/15 px-3 py-2 text-sm text-warn-text">
            <Icon name="alert" className="mt-0.5 size-4 shrink-0" />
            <span>
              No source label on {guessed.map((c) => c.name).join(", ")}: the repo is guessed from the image name, the
              agent is told to check it.
            </span>
          </p>
        )}
        {state === "failed" && (
          <p className="rounded-lg border border-line-strong bg-page px-3 py-2 text-sm text-ink-2">{COPY_BLOCKED}</p>
        )}
      </div>

      <pre
        ref={preRef}
        tabIndex={0}
        aria-label="Prompt"
        className="max-h-[60vh] overflow-auto rounded-lg border border-line bg-page p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap text-ink-2 [overflow-wrap:anywhere]"
      >
        {text}
      </pre>
      <p className="-mt-4 text-xs text-muted">
        Scanner data only, advisory texts left out. {int(text.split("\n").length)} lines.
      </p>
    </Drawer>
  );
}
