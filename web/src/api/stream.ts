import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, FEED_CAP, queries, sessionStore } from "./client";
import type { EventsResponse, InvalidateMessage, LiveEvent } from "./types";

export type LiveStatus = "connecting" | "open" | "reconnecting" | "offline";

// After this long without a working connection the pill turns "Offline".
const OFFLINE_AFTER_MS = 20_000;

function parse<T>(data: string): T | null {
  try {
    return JSON.parse(data) as T;
  } catch {
    return null;
  }
}

/**
 * Opens one EventSource on /api/stream?env=… for the selected env (re-opened
 * when env changes) and feeds the React Query cache:
 *  - "live": prepended to the ["events", env] feed (newest first, capped);
 *  - "invalidate": invalidateQueries for each scope of that env. These are
 *    query families; the keys match by prefix, so ["summary", env] also
 *    covers every namespace/component scope ["summary", env, scope].
 */
export function useLiveStream(env: string): LiveStatus {
  const qc = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");

  useEffect(() => {
    if (!env) return;
    let es: EventSource | null = null;
    let retryTimer: number | undefined;
    let offlineTimer: number | undefined;
    let attempts = 0;
    let hadConnection = false;
    let disposed = false;

    const startOfflineTimer = () => {
      if (offlineTimer === undefined) {
        offlineTimer = window.setTimeout(() => setStatus("offline"), OFFLINE_AFTER_MS);
      }
    };

    const onLive = (e: MessageEvent<string>) => {
      const ev = parse<LiveEvent>(e.data);
      if (!ev) return;
      qc.setQueryData<EventsResponse>(queries.events(env).queryKey, (old) =>
        old
          ? { items: [ev, ...old.items.filter((x) => x.id !== ev.id)].slice(0, FEED_CAP) }
          : old,
      );
      if (ev.type === "db_updated") void qc.invalidateQueries({ queryKey: ["meta"] });
    };

    const onInvalidate = (e: MessageEvent<string>) => {
      const scopes = parse<InvalidateMessage>(e.data)?.scopes ?? [];
      for (const scope of scopes) void qc.invalidateQueries({ queryKey: [scope, env] });
      // Scan states change the image counts of the summary: refresh the image lists too.
      if (scopes.includes("summary")) {
        void qc.invalidateQueries({ queryKey: ["images", env] });
        void qc.invalidateQueries({ queryKey: ["history"] });
      }
      // Exceptions (all envs) are added, revoked and expire along with findings.
      if (scopes.includes("findings")) void qc.invalidateQueries({ queryKey: ["exceptions"] });
      // A workload detail is made of both findings and workload data.
      if (scopes.includes("findings") || scopes.includes("workloads")) {
        void qc.invalidateQueries({ queryKey: ["workload", env] });
      }
    };

    const connect = () => {
      if (disposed || sessionStore.get()) return;
      es = new EventSource(`/api/stream?env=${encodeURIComponent(env)}`);
      es.onopen = () => {
        window.clearTimeout(offlineTimer);
        offlineTimer = undefined;
        attempts = 0;
        // Messages may have been missed while disconnected: resync everything.
        if (hadConnection) void qc.invalidateQueries();
        hadConnection = true;
        setStatus("open");
      };
      es.onerror = () => {
        if (disposed) return;
        setStatus((s) => (s === "offline" ? s : hadConnection ? "reconnecting" : "connecting"));
        startOfflineTimer();
        if (es?.readyState === EventSource.CLOSED) {
          // The browser gave up (HTTP error or non event-stream answer, which
          // is what an expired Pomerium session looks like). Probe with a
          // plain fetch so the session banner shows up, then retry.
          es.close();
          void api.meta().catch(() => undefined);
          attempts += 1;
          retryTimer = window.setTimeout(connect, Math.min(30_000, 1000 * 2 ** attempts));
        }
      };
      es.addEventListener("live", onLive);
      es.addEventListener("invalidate", onInvalidate);
    };

    const onOffline = () => setStatus("offline");
    const onOnline = () => {
      if (es?.readyState === EventSource.OPEN) return;
      es?.close();
      window.clearTimeout(retryTimer);
      attempts = 0;
      connect();
    };

    setStatus("connecting");
    connect();
    window.addEventListener("offline", onOffline);
    window.addEventListener("online", onOnline);
    return () => {
      disposed = true;
      es?.close();
      window.clearTimeout(retryTimer);
      window.clearTimeout(offlineTimer);
      window.removeEventListener("offline", onOffline);
      window.removeEventListener("online", onOnline);
    };
  }, [env, qc]);

  return status;
}
