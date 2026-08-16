import { expect, test } from '@playwright/test';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Renders the Report page in a real browser against a real API.
 *
 * This closes a gap that was previously an admitted limit. The page had been verified three ways —
 * `tsc -b` proved every API field access matched the declared contract, the served bundle was
 * confirmed to contain the report code, and each endpoint's payload was inspected — and none of that
 * can catch what a browser catches: a component that throws at mount, `median(undefined)` printing
 * NaN, or an export button that produces an empty file while looking like it worked. That last one
 * was a genuine bug (a blob URL revoked synchronously after `click()`), found by reading the code and
 * fixed blind; this test is what would have caught it.
 *
 * The API must be running and reachable. Data is seeded through the public REST API rather than
 * mocked, because the point is to prove the page renders THIS product's real risk-annotated output.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';

const authHeaders = {
  Authorization: `Bearer ${API_TOKEN}`,
  'Content-Type': 'application/json',
};

/** Create a project + a risk-annotated scan over a temp repo, and return the scan id. */
async function seedScan(): Promise<string> {
  // Written to a real directory because the API scans the filesystem — a fabricated payload would
  // test the renderer against data the scanner never produced.
  const dir = mkdtempSync(join(tmpdir(), 'qubit-e2e-'));
  writeFileSync(
    join(dir, 'app.py'),
    [
      'import hashlib',
      'from cryptography.hazmat.primitives.asymmetric import rsa, ec',
      '',
      'def checksum(d): return hashlib.md5(d).hexdigest()',
      'key = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
      'sk = ec.generate_private_key(ec.SECP256R1())',
      '',
    ].join('\n'),
    'utf-8',
  );
  writeFileSync(
    join(dir, 'nginx.conf'),
    'server {\n    ssl_protocols TLSv1 TLSv1.1;\n    ssl_ecdh_curve prime256v1;\n}\n',
    'utf-8',
  );

  const projectResp = await fetch(`${API_BASE}/api/v1/projects`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ name: `E2E Report ${Date.now()}` }),
  });
  expect(projectResp.ok, `project create failed: ${projectResp.status}`).toBeTruthy();
  const project = await projectResp.json();

  const scanResp = await fetch(`${API_BASE}/api/v1/projects/${project.id}/scans`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ targets: [dir], run_risk: true }),
  });
  // Read the body ONCE: a fetch Response body is a stream, so using `await resp.text()` as an
  // assertion message and then calling `resp.json()` throws "Body has already been read".
  const scanBody = await scanResp.text();
  expect(scanResp.status, scanBody).toBe(202);
  const scanId = JSON.parse(scanBody).scan.id;

  // Scans are asynchronous (a JobRunner executes them off the request path), so poll rather than
  // assuming the data is there — reading through is exactly the mistake the API's own warning warns
  // clients about.
  for (let i = 0; i < 60; i++) {
    const status = await (
      await fetch(`${API_BASE}/api/v1/scans/${scanId}`, { headers: authHeaders })
    ).json();
    if (status.status !== 'running' && status.status !== 'queued') {
      expect(status.status, 'seed scan did not succeed').toBe('succeeded');
      return scanId;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('seed scan never finished');
}

let scanId: string;

test.beforeAll(async () => {
  const health = await fetch(`${API_BASE}/api/v1/health`).catch(() => null);
  test.skip(
    !health?.ok,
    `No QUBIT API at ${API_BASE} — start one with \`qubit serve\` (these tests use real data on purpose).`,
  );
  scanId = await seedScan();
});

test.beforeEach(async ({ page }) => {
  // The dashboard reads its token and API base from localStorage (set by the Login page), so seeding
  // them skips the login UI without mocking the auth path itself.
  //
  // `qubit_api_base` must INCLUDE the `/api/v1` prefix — the client's default is
  // `http://127.0.0.1:8787/api/v1` and it appends bare paths like `/health` and `/scans/{id}`. Setting
  // just the origin leaves BootGate polling `:8000/health`, which 404s, so the app never reveals
  // itself and every assertion fails against a "Starting the engine…" splash.
  await page.addInitScript(
    ([base, token]) => {
      localStorage.setItem('qubit_api_base', base as string);
      localStorage.setItem('qubit_token', token as string);
    },
    [`${API_BASE}/api/v1`, API_TOKEN],
  );
  // Any uncaught exception or failed request is a rendering failure even if the DOM looks fine.
  page.on('pageerror', (err) => {
    throw new Error(`uncaught page error: ${err.message}`);
  });
});

/** The report content, scoped to the `<main>` landmark.
 *
 * Asserting against `body` matched the SIDEBAR: "CRQC Timeline" is also a nav link, so a
 * `toContainText(/crqc timeline/i)` passed the instant the shell rendered and the following
 * assertions then ran against a page whose report had not loaded. Scoping to `main` is what makes
 * these assertions about the report rather than about the chrome around it.
 */
const reportMain = (page: import('@playwright/test').Page) => page.getByRole('main');

test('report page renders the executive verdict from real scan data', async ({ page }) => {
  await page.goto(`/report/${scanId}`);
  const main = reportMain(page);

  // "Total assets" is a metric tile that only exists once the scan payload has arrived.
  await expect(main).toContainText(/total assets/i, { timeout: 20_000 });
  const text = (await main.innerText()).toLowerCase();

  // The failure modes type-checking cannot see: a missing field rendering as NaN or undefined.
  //
  // Word-bounded, because a bare substring check for "nan" matches "financial" — one of the
  // sensitivity classes the report legitimately prints. The first version of this test failed on
  // exactly that, which is a good reminder that a too-broad negative assertion is its own bug.
  expect(text).not.toMatch(/\bnan\b/);
  expect(text).not.toMatch(/\bundefined\b/);
  expect(text).not.toContain('[object object]');
  // A real asset count, not an empty tile.
  expect(text, `no numeric metrics rendered in: ${text.slice(0, 300)}`).toMatch(/\d/);
});

test('report page renders the CRQC timeline section with real years', async ({ page }) => {
  await page.goto(`/report/${scanId}`);
  const main = reportMain(page);

  // The heading carries the algorithm name, which distinguishes the report section from the nav link
  // of the same words.
  await expect(main).toContainText(/crqc timeline —/i, { timeout: 20_000 });
  await expect(main).toContainText(/monte-carlo trials/i);

  // p05/median/p95 come from the Monte-Carlo simulator; four-digit years prove they arrived rather
  // than rendering blank.
  const text = await main.innerText();
  const years = text.match(/\b20\d{2}\b/g) ?? [];
  expect(years.length, `expected CRQC years in: ${text.slice(0, 400)}`).toBeGreaterThanOrEqual(2);
});

test('report page lists discovered algorithms', async ({ page }) => {
  await page.goto(`/report/${scanId}`);
  const main = reportMain(page);
  await expect(main).toContainText(/total assets/i, { timeout: 20_000 });

  // The seeded repo contains MD5, an RSA-2048 keygen, a P-256 key and a weak nginx TLS config, so the
  // inventory has to name them. This is the end-to-end proof: scanner -> API -> risk -> rendered page.
  const text = await main.innerText();
  expect(text).toMatch(/MD5/);
  expect(text).toMatch(/RSA/);
  expect(text).toMatch(/TLSv1/);
});

test('export HTML actually downloads a complete, self-contained document', async ({ page }) => {
  await page.goto(`/report/${scanId}`);
  await expect(reportMain(page)).toContainText(/total assets/i, { timeout: 20_000 });

  const downloadPromise = page.waitForEvent('download', { timeout: 20_000 });
  await page.getByRole('button', { name: /export html/i }).click();
  const download = await downloadPromise;

  // The bug this guards: `saveTextFile` revoked its blob URL synchronously after `click()`, which can
  // invalidate the blob before the browser finishes reading it — producing NO file while the button
  // looks like it worked. A download event alone is not enough; the bytes have to be there.
  expect(download.suggestedFilename()).toMatch(/^qubit-report-scan-.*\.html$/);
  const path = await download.path();
  expect(path, 'download produced no file on disk').toBeTruthy();

  const html = readFileSync(path!, 'utf-8');
  const lower = html.toLowerCase();
  expect(html.length, 'exported report is empty').toBeGreaterThan(1000);
  // Case-insensitive: the builder emits `<!doctype html>` lowercase, which is equally valid HTML5.
  expect(lower).toContain('<!doctype html');
  expect(lower).toContain('<title>qubit report');
  expect(lower).toContain('quantum-vulnerable');
  expect(html).toContain('CRQC timeline');
  // Self-contained: the styling must travel WITH the file, or the exported report is unreadable on
  // any machine that does not have the dashboard. (`qubit-print` is the on-screen print view's class,
  // not this document's — the standalone export inlines its own sheet.)
  expect(html).toContain('<style>');
  expect(html).toContain('color-scheme: light');
  expect(html).toMatch(/\.kpi\s*\{/);

  // "Median HNDL risk score" is computed from `risk_scores` on /scans/{id}/summary and appears in the
  // EXPORTED document (the on-screen HUD shows metric tiles instead). If that field were missing this
  // would read "NaN", so it is asserted here rather than on screen.
  //
  // Asserted against TAG-STRIPPED text: the figure is emphasised (`score: <b>0.10</b> across …`), so a
  // regex run over raw HTML sees the markup between the label and the number and fails on a document
  // that is perfectly correct. Stripping tags also makes this a check on what a reader actually reads.
  const plain = html.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').toLowerCase();
  expect(plain).toMatch(/median hndl risk score:\s*\d+\.\d+\s*across\s*\d+\s*scored assets/);
  // The CRQC section must carry real four-digit years, not blanks.
  expect(plain).toMatch(/\b20\d{2}\b\s*\(p05\)/);
  expect(plain).toMatch(/\b20\d{2}\b\s*\(p95\)/);
  expect(lower).not.toMatch(/\bundefined\b/);
  expect(lower).not.toMatch(/\bnan\b/);
});

test('report page for an unknown scan does not crash', async ({ page }) => {
  // A 404 from the API must render a message, not a blank page or an unhandled rejection — the
  // `pageerror` handler in beforeEach turns any uncaught exception into a failure.
  await page.goto('/report/00000000-0000-0000-0000-000000000000');
  await page.waitForLoadState('networkidle');
  const text = await page.locator('body').innerText();
  expect(text.trim().length, 'page rendered nothing at all').toBeGreaterThan(0);
});
