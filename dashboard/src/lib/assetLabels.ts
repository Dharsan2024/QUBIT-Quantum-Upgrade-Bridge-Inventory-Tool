/**
 * Presentation helpers shared by every view that renders an asset.
 *
 * The scanner's normalizer wraps algorithm names the registry cannot resolve as
 * `UNKNOWN(...)` — protocols and certificate paths land there routinely. That marker is
 * useful provenance in the database but reads as a defect in the UI, so unwrap it here
 * rather than in the data layer (the stored value stays untouched).
 */

/** Human-readable algorithm/finding label. */
export function displayAlgorithm(algorithm: string): string {
  const m = /^UNKNOWN\((.*)\)$/.exec(algorithm);
  if (!m) return algorithm;
  const inner = m[1];
  // A path (certificate/key file) reads best as its file name.
  if (/[\\/]/.test(inner)) return inner.split(/[\\/]/).filter(Boolean).pop() ?? inner;
  return inner;
}

/** Shorten a long absolute path to its trailing segments; keep the full value in a tooltip. */
export function shortPath(path: string, keep = 3): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length <= keep ? path : `…/${parts.slice(-keep).join('/')}`;
}
