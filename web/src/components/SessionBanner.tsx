import { useSyncExternalStore } from "react";
import { sessionStore } from "../api/client";
import { Icon } from "./Icon";

/** Shown when an API call came back as a login redirect / HTML page / 401 / 403. */
export function SessionBanner() {
  const expired = useSyncExternalStore(sessionStore.subscribe, sessionStore.get);
  if (!expired) return null;
  return (
    <div role="alert" className="sticky top-0 z-50 border-b border-warn/60 bg-warn px-4 py-2 text-[#0b0b0b]">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-center gap-x-4 gap-y-1 text-sm font-semibold">
        <span className="inline-flex items-center gap-2">
          <Icon name="alert" /> Session expired, reload the page
        </span>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="inline-flex items-center gap-1.5 rounded-md bg-[#0b0b0b] px-3 py-1 text-xs font-semibold text-white hover:bg-[#2c2c2a]"
        >
          <Icon name="refresh" className="size-3.5" /> Reload
        </button>
      </div>
    </div>
  );
}
