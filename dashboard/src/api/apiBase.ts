/** API base-URL normalization, deliberately free of build-time and browser globals.
 *
 * Kept out of `client.ts` because that module touches `import.meta.env` and `localStorage`, neither of
 * which exists in a plain Node process — so a pure unit test could not import it without a Vite
 * transform. This module is importable from anywhere: the client, the desktop shell, a test runner.
 */

/** API route prefix every request path in this client is relative to. */
export const API_PREFIX = "/api/v1";

/** Local default, absolute on purpose (see `normalizeApiBase`). */
export const DEFAULT_API_BASE = `http://127.0.0.1:8787${API_PREFIX}`;

/** Normalize a user- or env-supplied base so it always ends with the `/api/v1` prefix.
 *
 * Every request path in this client is bare (`/health`, `/scans/{id}`), so the base has to carry the
 * prefix. Supplying just an origin — `http://localhost:8000`, the obvious thing to type into the Login
 * page or an env var — used to be accepted verbatim, and then EVERY call 404ed. The visible symptom
 * was the boot gate spinning on "Starting the engine…" forever, which points at the API being down
 * rather than at the URL being one path segment short, so it is genuinely hard to diagnose.
 *
 * Normalizing in one place means the Login page, `VITE_API_BASE`, the desktop shell and the browser
 * tests all get the same treatment. The function is idempotent because the value is normalized both
 * when stored and when read.
 *
 * The empty-input fallback is ABSOLUTE on purpose: a relative `/api/v1` would resolve against
 * `tauri.localhost` in the desktop shell and never reach the local engine.
 */
export function normalizeApiBase(base: string): string {
  const trimmed = base.trim().replace(/\/+$/, "");
  if (!trimmed) return DEFAULT_API_BASE;
  if (trimmed.endsWith(API_PREFIX)) return trimmed;
  // `/api` is the other near-miss worth absorbing rather than 404ing on.
  if (trimmed.endsWith("/api")) return `${trimmed}/v1`;
  return `${trimmed}${API_PREFIX}`;
}
