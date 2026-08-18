import { expect, test, type Page } from '@playwright/test';
import { expectNoBrokenPlaceholders } from './assertions';

/**
 * The CNSA 2.0 page and the two real report downloads, exercised in a real browser against a real
 * API and a real scan.
 *
 * These features were the answer to a blunt piece of feedback: the CNSA 2.0 evaluator, the paginated
 * PDF report and the SARIF log all existed as working, tested Python — and none of them was
 * reachable from the app. CNSA 2.0 had no API route at all; PDF and SARIF were CLI-only, so the
 * dashboard's "Save as PDF" was `window.print()`, a browser screenshot of the page rather than the
 * composed document. A test that only checked the Python would have kept saying everything passed.
 *
 * No mocking: the assertions below are about numbers the risk engine actually produced and bytes the
 * PDF writer actually emitted.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';
const authHeaders = { Authorization: `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' };

/** Scan a path that is guaranteed to exist and to contain vulnerable crypto. */
async function seedScan(): Promise<string> {
  const projects = await (
    await fetch(`${API_BASE}/api/v1/projects`, { headers: authHeaders })
  ).json();
  const name = 'E2E compliance';
  let projectId = (projects as { id: string; name: string }[]).find((p) => p.name === name)?.id;
  if (!projectId) {
    projectId = (
      await (
        await fetch(`${API_BASE}/api/v1/projects`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ name }),
        })
      ).json()
    ).id;
  }
  const created = await (
    await fetch(`${API_BASE}/api/v1/projects/${projectId}/scans`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ targets: ['demo-lab/vulnapp-python'], run_risk: true }),
    })
  ).json();
  const scanId = created.scan.id as string;

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
  await page.addInitScript(
    ([base, token]) => {
      localStorage.setItem('qubit_api_base', base as string);
      localStorage.setItem('qubit_token', token as string);
    },
    [API_BASE, API_TOKEN],
  );
  page.on('pageerror', (e) => {
    throw new Error(`Uncaught exception in the page: ${e.message}`);
  });
});

/** Wait for the CNSA page to finish evaluating rather than asserting on the spinner. */
async function openCompliance(page: Page) {
  await page.goto('/compliance');
  const root = page.getByTestId('compliance-root');
  await expect(root).toBeVisible();
  await expect(root).not.toContainText('Evaluating milestones', { timeout: 30_000 });
  return root;
}

test('CNSA 2.0 page renders every milestone with a real deadline and verdict', async ({ page }) => {
  const root = await openCompliance(page);

  // All five NSA milestones, by name — a page that silently rendered an empty table would pass a
  // mere "is visible" check.
  for (const milestone of [
    'Preparation Phase',
    'New NSS Systems',
    'TLS 1.3 Required',
    'Legacy System Update',
    'Full PQC Transition',
  ]) {
    await expect(root).toContainText(milestone);
  }

  // Real ISO deadlines from the policy file, not placeholders.
  await expect(root).toContainText('2025-12-31');
  await expect(root).toContainText('2035-01-01');

  // The demo app is deliberately vulnerable, so at least one milestone must fail.
  await expect(root.getByText('Non-compliant').first()).toBeVisible();

  expectNoBrokenPlaceholders(await root.innerText(), 'CNSA 2.0 page');
});

test('CNSA 2.0 page separates schedule adherence from actual PQC readiness', async ({ page }) => {
  const root = await openCompliance(page);

  // This is the whole reason the page shows two numbers. The backend scores a not-yet-due milestone
  // as met, so "on schedule" can read 100% while most milestones are unmet — presenting that alone
  // under a "compliance" heading would tell the user they were done when they are not.
  await expect(root).toContainText(/on schedule/i);
  await expect(root).toContainText(/pqc readiness/i);

  const readiness = await root.getByText(/^\d+\/\d+$/).first().innerText();
  const [satisfied, total] = readiness.split('/').map(Number);
  expect(total).toBe(5);
  expect(satisfied).toBeLessThan(total); // the vulnerable demo app cannot be fully ready
});

test('CNSA 2.0 is reachable from the sidebar', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: /CNSA 2\.0/i }).click();
  await expect(page.getByTestId('compliance-root')).toBeVisible();
});

test('the PDF button downloads the real composed report, not a page screenshot', async ({
  page,
}) => {
  await page.goto(`/report/${scanId}`);
  await expect(page.getByTestId('report-root')).toBeVisible();

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: /Download PDF report/i }).click();
  const file = await download;

  expect(file.suggestedFilename()).toMatch(/\.pdf$/);
  const stream = await file.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  const bytes = Buffer.concat(chunks);

  // Checked by magic number and trailer, not by size: an HTML error page is also "some bytes", and
  // a truncated PDF opens in some readers and fails in others — the worst outcome for a document
  // someone attaches to a compliance submission.
  expect(bytes.subarray(0, 5).toString()).toBe('%PDF-');
  expect(bytes.subarray(-16).toString()).toContain('%%EOF');
  expect(bytes.length).toBeGreaterThan(1000);
});

test('the SARIF button downloads a valid 2.1.0 log with stable fingerprints', async ({ page }) => {
  await page.goto(`/report/${scanId}`);
  await expect(page.getByTestId('report-root')).toBeVisible();

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: /^SARIF$/i }).click();
  const file = await download;

  expect(file.suggestedFilename()).toMatch(/\.sarif$/);
  const stream = await file.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  const doc = JSON.parse(Buffer.concat(chunks).toString('utf8'));

  expect(doc.version).toBe('2.1.0');
  const run = doc.runs[0];
  expect(run.results.length).toBeGreaterThan(0);
  // Without partialFingerprints a re-scan opens duplicate code-scanning alerts.
  expect(run.results[0].partialFingerprints).toBeTruthy();
  const declared = new Set(run.tool.driver.rules.map((r: { id: string }) => r.id));
  for (const result of run.results) expect(declared.has(result.ruleId)).toBe(true);
});
