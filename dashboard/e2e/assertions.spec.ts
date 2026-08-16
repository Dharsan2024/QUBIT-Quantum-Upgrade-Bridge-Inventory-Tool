import { expect, test } from '@playwright/test';

import { expectNoBrokenPlaceholders } from './assertions';

/**
 * Unit tests for the shared assertion helper — it needs its own tests precisely because the naive
 * version of this check has failed in BOTH directions in this repo:
 *
 *  * a substring check for "nan" fired on "financial", a sensitivity class the report legitimately
 *    prints, so a correct page failed;
 *  * the fix for that wrote a literal backspace instead of a regex word boundary, so the pattern
 *    matched nothing and the assertion passed vacuously — a green test proving nothing.
 *
 * A guard that can silently stop guarding is worse than no guard, so both directions are pinned.
 */

test.describe('expectNoBrokenPlaceholders', () => {
  test('accepts real content whose words merely CONTAIN the placeholder letters', () => {
    // Every one of these is legitimate output from this product.
    const legitimate = [
      'Sensitivity: financial, PII, credentials',
      'Median HNDL risk score: 0.10 across 6 scored assets',
      'Governance gate pending maintenance window',
      'Nanosecond-resolution timestamps are not used here',
      'Annulled migration plan',
      'X25519MLKEM768 negotiated',
    ];
    for (const text of legitimate) {
      expectNoBrokenPlaceholders(text, `legitimate sample ${JSON.stringify(text)}`);
    }
  });

  test('rejects each broken placeholder as a standalone token', () => {
    const broken = [
      'Median HNDL risk score: NaN across 6 scored assets',
      'Median HNDL risk score: nan',
      'Scan #undefined',
      'Discovered at null',
      'Target: [object Object]',
      'Finished at Invalid Date',
    ];
    for (const text of broken) {
      // The helper throws through expect(), so assert it does.
      let threw = false;
      try {
        expectNoBrokenPlaceholders(text, 'broken sample');
      } catch {
        threw = true;
      }
      expect(threw, `should have rejected: ${text}`).toBe(true);
    }
  });

  test('failure message names the offending token and shows the text', () => {
    let message = '';
    try {
      expectNoBrokenPlaceholders('Total assets: NaN', 'report main');
    } catch (err) {
      message = (err as Error).message;
    }
    // Actionable: which token, where, and the surrounding text.
    expect(message).toContain('report main');
    expect(message).toContain('NaN');
    expect(message).toContain('Total assets: NaN');
  });
});
