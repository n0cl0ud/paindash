import { useRef } from "react";

type Key = string | number;

/**
 * Tracks which keys showed up after a list was first rendered, so live
 * additions can be highlighted. Keys present on the first render (or after
 * `scope` changes, e.g. switching env or scope) are never "new". A key stays new for
 * `ttl` ms, long enough for its CSS entrance animation to play once.
 */
export function useArrivals(keys: readonly Key[], scope: string, ttl = 2500) {
  const state = useRef<{ scope: string; seen: Map<Key, number> | null }>({ scope, seen: null });
  if (state.current.scope !== scope) state.current = { scope, seen: null };
  const now = Date.now();
  if (!state.current.seen) {
    state.current.seen = new Map(keys.map((k) => [k, 0]));
  } else {
    for (const k of keys) if (!state.current.seen.has(k)) state.current.seen.set(k, now);
  }
  const seen = state.current.seen;
  return (k: Key) => {
    const t = seen.get(k);
    return t !== undefined && t > 0 && now - t < ttl;
  };
}
