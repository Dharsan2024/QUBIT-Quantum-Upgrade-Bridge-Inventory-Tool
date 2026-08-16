import { expect } from '@playwright/test';

/**
 * Shared assertion helpers for the browser suite.
 *
 * These exist because the obvious hand-written version is wrong in a way that is hard to notice.
 * Checking rendered text for broken placeholders looks like a one-liner:
 *
 *     expect(text.toLowerCase()).not.toContain('nan');
 *
 * and that fails on **"financial"** — one of the sensitivity classes this product legitimately
 * prints — while also missing nothing else. A first attempt at fixing it wrote a literal backspace
 * character (a `\b` that went through a shell/Python escape round-trip instead of reaching the regex)
 * so the pattern matched nothing at all and the assertion passed vacuously, which is strictly worse
 * than the false positive it replaced.
 *
 * Centralizing it means the correct, word-bounded form is written once, is unit-tested below by
 * `assertions.spec.ts`, and cannot drift per spec file.
 */

/** Tokens that indicate a rendering bug rather than legitimate content. */
const BROKEN_PLACEHOLDERS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  // Word-bounded so "financial", "nanosecond", "Nancy" and friends do not trip it.
  { pattern: /\bNaN\b/i, label: 'NaN (a number formatted from a missing/invalid field)' },
  { pattern: /\bundefined\b/i, label: 'undefined (a missing field interpolated into text)' },
  { pattern: /\bnull\b/i, label: 'null (an absent value interpolated into text)' },
  { pattern: /\[object Object\]/i, label: '[object Object] (an object interpolated as a string)' },
  { pattern: /\bInvalid Date\b/i, label: 'Invalid Date (an unparseable timestamp)' },
];

/**
 * Fail if `text` contains any placeholder that means the UI rendered a broken value.
 *
 * `where` is included in the failure message because these assertions run over large blobs of page
 * text, and "somewhere on the page there is a NaN" is not actionable on its own.
 */
export function expectNoBrokenPlaceholders(text: string, where: string): void {
  const hits = BROKEN_PLACEHOLDERS.filter(({ pattern }) => pattern.test(text)).map(
    ({ label }) => label,
  );
  expect(
    hits,
    `${where} rendered broken placeholder value(s): ${hits.join(', ')}\n` +
      `--- text under assertion (first 600 chars) ---\n${text.slice(0, 600)}`,
  ).toEqual([]);
}

export { BROKEN_PLACEHOLDERS as _BROKEN_PLACEHOLDERS_FOR_TESTS };
