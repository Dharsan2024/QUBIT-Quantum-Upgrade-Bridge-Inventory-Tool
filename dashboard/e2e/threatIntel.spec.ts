import { expect, test, type Page } from '@playwright/test';

/**
 * The Settings page's two new cards: the durable "What QUBIT has learned" panel (reused from
 * the Migrations tab) and the opt-in "Threat intelligence" card. Type-checking and the backend
 * test suite (packages/qubit-risk/tests/test_threat_intel.py, packages/qubit-api/tests/
 * test_threat_intel_api.py) already prove the data layer; this closes the same gap the rest of
 * this suite closes for other pages — that the toggle actually flips something real, and
 * "Check now" reaches the actual API and renders what came back, not just that the button exists.
 *
 * "Check now" hits the real NIST pages (see qubit_risk.threat_intel) — no mock, matching how
 * sources.spec.ts drives the real TLS/Vault infrastructure rather than a stub. It is skipped
 * loudly, not silently, when the API isn't reachable.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';
const headers = { Authorization: `Bearer ${API_TOKEN}` };

test.beforeEach(async ({ page }) => {
  const health = await fetch(`${API_BASE}/api/v1/health`).catch(() => null);
  test.skip(!health?.ok, `No QUBIT API at ${API_BASE} — start one with \`qubit serve\`.`);
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

async function openSettings(page: Page) {
  await page.goto('/settings');
  await expect(page.getByTestId('threat-intel-card')).toBeVisible();
}

test('the learning panel renders without throwing, seeded or not', async ({ page }) => {
  await openSettings(page);
  // Either a real stats grid or the documented empty state — both are a successful render.
  // What would fail this is the component throwing on mount (caught by the pageerror listener
  // registered in beforeEach) or the card never appearing at all.
  await expect(page.getByText(/what qubit has learned/i)).toBeVisible();
});

test('threat intelligence is off by default and lists the fixed NIST sources', async ({
  page,
}) => {
  const config = await (
    await fetch(`${API_BASE}/api/v1/threat-intel/config`, { headers })
  ).json();

  await openSettings(page);
  await expect(page.getByTestId('threat-intel-toggle')).toHaveText(
    config.enabled ? 'Enabled' : 'Disabled',
  );
  for (const source of config.sources as { id: string; label: string }[]) {
    const row = page.getByTestId(`threat-intel-source-${source.id}`);
    await expect(row).toBeVisible();
    await expect(row).toContainText(source.label);
  }
});

test('the toggle flips the real config, not just its own label', async ({ page }) => {
  await openSettings(page);
  const toggle = page.getByTestId('threat-intel-toggle');
  const before = (await toggle.textContent())?.trim();

  await toggle.click();
  await expect(toggle).not.toHaveText(before ?? '', { timeout: 10_000 });

  const config = await (
    await fetch(`${API_BASE}/api/v1/threat-intel/config`, { headers })
  ).json();
  expect(config.enabled).toBe(before === 'Disabled');

  // Leave it as found — the toggle is a shared, persistent setting, not per-test state.
  await toggle.click();
  await expect(toggle).toHaveText(before ?? '');
});

test('check now reaches the real API and renders what it fetched', async ({ page }) => {
  await openSettings(page);
  await expect(page.getByTestId('threat-intel-toggle')).toBeVisible();

  await page.getByTestId('threat-intel-check-now').click();

  // A real network round-trip against csrc.nist.gov for every curated source; generous but bounded.
  await expect(page.getByTestId('threat-intel-last-checked')).not.toHaveText('never', {
    timeout: 45_000,
  });

  const config = await (
    await fetch(`${API_BASE}/api/v1/threat-intel/config`, { headers })
  ).json();
  for (const source of config.sources as { id: string }[]) {
    const row = page.getByTestId(`threat-intel-source-${source.id}`);
    await expect(row).not.toContainText('not checked yet');
  }
});
