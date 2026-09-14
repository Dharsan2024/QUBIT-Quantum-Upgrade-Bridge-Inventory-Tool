// Walk every route in the running desktop app and report real UI defects.
//
//   1. start the app with CDP:  WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222
//   2. node dashboard/tools/ui-audit.mjs
//
// Checks that a route rendered SOMETHING are worthless: an earlier version asserted
// `innerText.length > 0` and passed the router's "Unexpected Application Error! 404 Not Found"
// boundary at 43 characters. So each route is checked for the boundary itself, uncaught page
// exceptions, console errors, horizontal overflow of the body, elements spilling past the viewport
// without a scroll container, empty headings, and controls with no accessible name.
//
// The accessible-name check counts a wrapping <label>, a <label for>, and aria-labelledby as well
// as aria-label/title/placeholder. Its first version knew only the last three and reported two
// perfectly labelled controls as broken — a check that cries wolf gets ignored, and I nearly
// "fixed" correct code because of it.
import { chromium } from 'playwright-core';

const ROUTES = [
  '/', '/inventory', '/risk', '/timeline', '/migrations', '/scans',
  '/compliance', '/cbom', '/settings',
];

const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
const page = browser.contexts().flatMap((c) => c.pages())[0];
if (!page) { console.log('no page target'); process.exit(1); }

const findings = [];
let consoleErrors = [];
let pageErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 180)); });
page.on('pageerror', (e) => pageErrors.push(String(e).slice(0, 180)));

for (const route of ROUTES) {
  consoleErrors = []; pageErrors = [];
  await page.evaluate((r) => {
    window.history.pushState({}, '', r);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, route);
  await page.waitForTimeout(1800);

  const audit = await page.evaluate(() => {
    const text = document.body?.innerText || '';
    const de = document.documentElement;
    const vw = de.clientWidth;

    // Elements that stick out past the right edge by more than a rounding error.
    const overflowing = [];
    for (const el of document.querySelectorAll('main *')) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.right > vw + 2) {
        const cs = getComputedStyle(el);
        // A deliberate horizontal scroller is not a bug.
        if (cs.overflowX === 'auto' || cs.overflowX === 'scroll') continue;
        let p = el.parentElement, contained = false;
        while (p) {
          const pcs = getComputedStyle(p);
          if (pcs.overflowX === 'auto' || pcs.overflowX === 'scroll' || pcs.overflowX === 'hidden') {
            contained = true; break;
          }
          p = p.parentElement;
        }
        if (!contained) {
          overflowing.push(
            el.tagName.toLowerCase() +
              (el.className && typeof el.className === 'string'
                ? '.' + el.className.split(/\s+/).slice(0, 2).join('.')
                : '') +
              ` (right=${Math.round(r.right)} vw=${vw})`,
          );
        }
      }
    }

    const emptyHeadings = [...document.querySelectorAll('main h1, main h2, main h3')]
      .filter((h) => !(h.textContent || '').trim())
      .map((h) => h.tagName.toLowerCase());

    const namelessControls = [...document.querySelectorAll('main button, main a[href], main input')]
      .filter((el) => {
        // A programmatic label can come from four places, and an earlier version of this check
        // knew about only three — so it reported the Settings inputs, which carry a proper
        // <label htmlFor>, as unlabelled. A check that cries wolf gets ignored.
        let label =
          (el.getAttribute('aria-label') || '') +
          (el.getAttribute('title') || '') +
          (el.textContent || '') +
          (el.getAttribute('placeholder') || '');
        if (el.id) {
          const bound = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
          if (bound) label += bound.textContent || '';
        }
        const wrapping = el.closest('label');
        if (wrapping) label += wrapping.textContent || '';
        const describedBy = el.getAttribute('aria-labelledby');
        if (describedBy) {
          for (const id of describedBy.split(/\s+/)) {
            const n = document.getElementById(id);
            if (n) label += n.textContent || '';
          }
        }
        return !label.trim();
      })
      .map((el) => el.tagName.toLowerCase() + '.' + String(el.className).split(/\s+/)[0]);

    return {
      chars: text.length,
      boundary: /Unexpected Application Error|404 Not Found/i.test(text),
      bodyScrollsX: de.scrollWidth > de.clientWidth + 2,
      scrollWidth: de.scrollWidth,
      clientWidth: de.clientWidth,
      overflowing: overflowing.slice(0, 5),
      emptyHeadings,
      namelessControls: [...new Set(namelessControls)].slice(0, 5),
    };
  });

  const problems = [];
  if (audit.boundary) problems.push('ROUTER ERROR BOUNDARY');
  if (audit.chars === 0) problems.push('rendered nothing');
  if (audit.bodyScrollsX)
    problems.push(`body scrolls horizontally (${audit.scrollWidth} > ${audit.clientWidth})`);
  if (audit.overflowing.length) problems.push('overflow: ' + audit.overflowing.join(', '));
  if (audit.emptyHeadings.length) problems.push('empty headings: ' + audit.emptyHeadings.join(','));
  if (audit.namelessControls.length)
    problems.push('unlabelled controls: ' + audit.namelessControls.join(', '));
  if (pageErrors.length) problems.push('page errors: ' + pageErrors.join(' | '));
  if (consoleErrors.length) problems.push('console errors: ' + consoleErrors.join(' | '));

  if (problems.length) findings.push({ route, problems });
  console.log(
    `${problems.length ? 'ISSUE' : 'ok   '} ${route.padEnd(14)} ${audit.chars} chars` +
      (problems.length ? '\n        - ' + problems.join('\n        - ') : ''),
  );
}

await browser.close();
console.log(`\n${ROUTES.length - findings.length}/${ROUTES.length} routes clean`);
process.exit(findings.length ? 1 : 0);
