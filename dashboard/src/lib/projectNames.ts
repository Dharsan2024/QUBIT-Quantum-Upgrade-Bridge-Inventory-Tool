/** Naming the project a scan belongs to.
 *
 * Kept free of imports on purpose: these are the only pure functions in the scan path, and living
 * apart from `api/client.ts` (fetch, localStorage, the whole API surface) is what makes them
 * directly testable — see `dashboard/e2e/projectNames.spec.ts`, which exercises them against the
 * exact target strings sitting in a real installation's database.
 */

/** Name the project a scan of `targets` belongs to.
 *
 *  Every dashboard scan used to be filed under one project called "Dashboard scans", so a single
 *  installation ended up with (measured, on the development machine) ten unrelated scans in one
 *  bucket: two source trees, a git remote and three network probes, 872 assets deep. Every tab
 *  then showed that pile as one thing, which is precisely what made the app hard to read. A
 *  project is the thing being scanned, so its name comes from the target.
 *
 *  Rescanning the same target reuses the same project, which is what gives a project history. */
export function projectNameForTargets(
  targets: string[],
  kind: "files" | "network" | "vault" = "files",
): string {
  const first = (targets[0] ?? "").trim();
  const extra = targets.length > 1 ? ` +${targets.length - 1}` : "";
  if (!first) return "Untitled scan";
  if (kind === "vault") return `Vault ${hostOf(first)}${extra}`;
  if (kind === "network") return `${hostOf(first)}${extra}`;
  return `${basenameOf(first)}${extra}`;
}

/** Every separator a target can use. A Windows path, a POSIX path and a git remote all reach this
 *  function, and `git@host:org/repo.git` separates the org with a colon.
 *
 *  Spelled as a character array rather than a regex character class deliberately. The class needs a
 *  literal backslash, which is the escape character in a regex, in a JS string, in a shell heredoc
 *  and in a Python replacement string — and it was silently eaten twice while this was written,
 *  leaving `[\/]`, which matches only forward slashes and left every Windows path as one unsplit
 *  project name. `projectNames.spec.ts` is what caught it; this spelling means there is nothing
 *  left to eat. */
const SEPARATORS = ["/", String.fromCharCode(92), ":"];

/** Last path segment of a local path or git remote, without the `.git` suffix. */
function basenameOf(target: string): string {
  let cleaned = target.replace(/\.git$/i, "");
  while (cleaned.length > 0 && SEPARATORS.includes(cleaned[cleaned.length - 1])) {
    cleaned = cleaned.slice(0, -1);
  }
  const segments = splitOnSeparators(cleaned).filter((s) => s.length > 0);
  const last = segments[segments.length - 1] ?? cleaned;
  // A target that is nothing but separators ("/", "//") strips to an empty string, and an empty
  // project name is rejected by the API — surfacing as a failed scan rather than as the naming
  // problem it is. Fall back through to the raw target, which is at worst literal but never blank.
  return last || cleaned || target.trim();
}

/** Split on any separator, without a regex — see the note on SEPARATORS. */
function splitOnSeparators(value: string): string[] {
  let parts = [value];
  for (const sep of SEPARATORS) {
    parts = parts.flatMap((part) => part.split(sep));
  }
  return parts;
}

function hostOf(target: string): string {
  const withoutScheme = target.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  return withoutScheme.split("/")[0] || target;
}
