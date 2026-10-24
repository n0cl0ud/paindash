import { useEffect, useRef, type ReactNode } from "react";
import { Icon } from "./Icon";

/**
 * Modal side panel: focus moves to the close button and back to where it was
 * on close; Escape and the backdrop close it. `onClose` must be stable.
 */
export function Drawer({
  titleId,
  header,
  onClose,
  children,
}: {
  titleId: string; // id of the heading inside `header`
  header: ReactNode;
  onClose: () => void;
  children: ReactNode;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-40" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden="true" />
      <aside className="absolute inset-y-0 right-0 flex w-full max-w-xl animate-drawer flex-col border-l border-line bg-surface shadow-2xl">
        <header className="flex items-start gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0 flex-1">{header}</div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1.5 text-muted hover:bg-surface-2 hover:text-ink"
          >
            <Icon name="close" className="size-5" />
          </button>
        </header>
        <div className="flex-1 space-y-6 overflow-y-auto px-5 py-5">{children}</div>
      </aside>
    </div>
  );
}
