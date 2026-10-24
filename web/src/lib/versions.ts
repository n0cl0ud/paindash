const tokens = (v: string) => v.replace(/^(v|go)(?=\d)/i, "").match(/\d+|[A-Za-z]+/g) ?? [];

/** Loose version order (semver, Go, apk -rN, Debian revisions...): enough to pick a fix. */
export function cmpVersion(a: string, b: string): number {
  const x = tokens(a);
  const y = tokens(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const n = /^\d/.test(x[i]) && /^\d/.test(y[i]) ? Number(x[i]) - Number(y[i]) : x[i].localeCompare(y[i]);
    if (n) return n;
  }
  return x.length - y.length;
}

/**
 * The versions to move to. Advisories list one fix per release line (e.g.
 * 1.10.28, 2.2.28, 2.9.8): each installed version (several are ", "-separated)
 * needs the lowest fix above it, never the first of the list. Falls back to
 * every listed fix when none is above what runs.
 */
export function fixTargets(version: string, fixedIn: string[]): string[] {
  const sorted = [...fixedIn].sort(cmpVersion);
  const out = new Set<string>();
  for (const v of version.split(", ")) {
    const t = sorted.find((x) => cmpVersion(x, v) > 0);
    if (t) out.add(t);
  }
  return out.size ? [...out].sort(cmpVersion) : sorted;
}
