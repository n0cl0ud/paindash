import { useEffect, useState, type RefObject } from "react";
import { cx } from "../lib/cx";
import { Icon } from "./Icon";

type CopyState = "ok" | "failed" | null;

/**
 * Copies text to the clipboard. When the browser blocks it (plain http,
 * permissions), `target` gets selected for a manual copy instead.
 */
export function useCopy(target: RefObject<HTMLElement | null>) {
  const [state, setState] = useState<CopyState>(null);
  useEffect(() => {
    if (state === "ok") {
      const t = setTimeout(() => setState(null), 1800);
      return () => clearTimeout(t);
    }
    const sel = window.getSelection();
    if (state === "failed" && target.current && sel) {
      const r = document.createRange();
      r.selectNodeContents(target.current);
      sel.removeAllRanges();
      sel.addRange(r);
    }
  }, [state, target]);
  const copy = (text: string) =>
    Promise.resolve()
      .then(() => navigator.clipboard.writeText(text))
      .then(
        () => setState("ok"),
        () => setState("failed"),
      );
  return { state, copy };
}

export const COPY_BLOCKED = "The browser blocked the clipboard: the prompt is selected, copy it with ⌘C / Ctrl+C.";

export function CopyButton({ state, onClick, className }: { state: CopyState; onClick: () => void; className?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(
        "inline-flex shrink-0 items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold transition-colors",
        state === "ok" ? "bg-good text-white" : "bg-ink text-page hover:opacity-90",
        className,
      )}
    >
      <Icon name={state === "ok" ? "check" : "copy"} className="size-4" />
      {state === "ok" ? "Copied" : "Copy prompt"}
    </button>
  );
}

/** The repos a prompt opens pull requests on. */
export function RepoChips({ repos }: { repos: string[] }) {
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
      <span>Pull requests on</span>
      {repos.map((r) => (
        <span key={r} className="inline-flex items-center gap-1 rounded border border-line px-1.5 py-px font-mono text-ink-2">
          <Icon name="github" className="size-3" />
          {r}
        </span>
      ))}
    </p>
  );
}
