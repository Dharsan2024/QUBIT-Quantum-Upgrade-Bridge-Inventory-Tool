import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

/**
 * WCAG 2.2 Level AA regression, run in a real browser against the real app.
 *
 * This is not a nice-to-have any more: EN 301 549 (the technical standard the European
 * Accessibility Act enforces since 28 June 2025) is anchored to WCAG Level AA, so a regression here
 * is a compliance regression, not a cosmetic one.
 *
 * Three defects were found by running exactly this check against the built app and are pinned
 * below: two Settings inputs whose labels were visual only (no `htmlFor`, announced as "edit text,
 * blank"), the CRQC Timeline algorithm picker with no accessible name at all, and interactive
 * targets under the 24x24 CSS px floor SC 2.5.8 sets — the scan-row delete was 16x21 and the
 * dependency recheck 14x14.
 */

const require = createRequire(import.meta.url);
const AXE_SOURCE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const PAGES: [string, string][] = [
  ['Scans & Jobs', '/scans'],
  ['Projects', '/'],
  ['Inventory', '/inventory'],
  ['Risk Posture', '/risk'],
  ['CRQC Timeline', '/timeline'],
  ['CNSA 2.0', '/compliance'],
  ['Migration Hub', '/migrations'],
  ['Settings', '/settings'],
];

/** The tags EN 301 549 / WCAG 2.2 AA actually require. */
const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

declare global {
  interface Window {
    axe: { run: (ctx: Document, opts: unknown) => Promise<{ violations: AxeViolation[] }> };
  }
}
interface AxeViolation {
  id: string;
  impact: string;
  help: string;
  nodes: { html: string }[];
}

for (const [name, path] of PAGES) {
  test(`${name} has no WCAG 2.2 AA violations`, async ({ page }) => {
    await page.goto(path, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500); // charts and async panels settle
    await page.evaluate(AXE_SOURCE);
    const { violations } = await page.evaluate(
      async (tags) => await window.axe.run(document, { runOnly: { type: 'tag', values: tags } }),
      WCAG_TAGS,
    );
    // Name the offending markup in the failure — a bare count sends the reader hunting.
    const detail = violations
      .map((v) => `${v.impact} ${v.id}: ${v.help}\n    ${v.nodes[0]?.html?.slice(0, 140)}`)
      .join('\n  ');
    expect(violations, `${name}:\n  ${detail}`).toEqual([]);
  });
}

test('every interactive target meets SC 2.5.8 (24x24 CSS px)', async ({ page }) => {
  const undersized: string[] = [];
  for (const [name, path] of PAGES) {
    await page.goto(path, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);
    const small = await page.evaluate(() => {
      const out: { w: number; h: number; html: string }[] = [];
      const selector = 'button, a[href], select, input:not([type=hidden]), [role=button], [role=tab]';
      for (const el of Array.from(document.querySelectorAll(selector))) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue; // not rendered
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') continue;
        if (r.width < 24 || r.height < 24) {
          out.push({
            w: Math.round(r.width),
            h: Math.round(r.height),
            html: el.outerHTML.replace(/\s+/g, ' ').slice(0, 110),
          });
        }
      }
      return out;
    });
    for (const s of small) undersized.push(`${name}: ${s.w}x${s.h} ${s.html}`);
  }
  expect(undersized, `targets below 24x24:\n  ${undersized.join('\n  ')}`).toEqual([]);
});

test('keyboard focus stays visible and unobscured (SC 2.4.7, 2.4.11)', async ({ page }) => {
  await page.goto('/scans', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);

  const problems: string[] = [];
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press('Tab');
    const info = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return null;
      const cs = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      const atCentre = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return {
        label: (el.innerText || el.getAttribute('aria-label') || el.tagName).slice(0, 30),
        visible: (cs.outlineStyle !== 'none' && cs.outlineWidth !== '0px') || cs.boxShadow !== 'none',
        obscured: !!(atCentre && atCentre !== el && !el.contains(atCentre)),
      };
    });
    if (!info) break;
    if (!info.visible) problems.push(`no focus indicator: ${info.label}`);
    if (info.obscured) problems.push(`focus obscured: ${info.label}`);
  }
  expect(problems, problems.join('\n  ')).toEqual([]);
});
