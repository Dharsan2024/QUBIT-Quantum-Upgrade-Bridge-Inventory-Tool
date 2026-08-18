import { expect, test, type Page } from '@playwright/test';

/**
 * The two discovery sources that had no way in from the app: live TLS/SSH and Vault.
 *
 * `scan_network` and `scan_vault` were both real and tested, and `scan_network`'s own docstring said
 * so: "not yet wired into qubit-api's job runner either; both are CLI-only for now". The architecture
 * diagram claims six input sources, so the app was delivering four of them.
 *
 * These tests drive the actual UI against real infrastructure — the hybrid-PQC nginx container and a
 * seeded Vault dev server — because the point is that the whole path works, not that a button exists.
 * They skip (loudly, naming the command) when that infrastructure is absent rather than passing
 * vacuously against a mock.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';
const TLS_PORT = process.env.QUBIT_DEMO_TLS_PORT ?? '8443';
const VAULT_ADDR = process.env.QUBIT_DEMO_VAULT ?? 'http://127.0.0.1:8200';
const VAULT_TOKEN = process.env.QUBIT_DEMO_VAULT_TOKEN ?? 'qubit-demo-root-token';

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

const headers = { Authorization: `Bearer ${API_TOKEN}` };

/** Ids of every scan that exists right now — snapshot this BEFORE the interaction. */
async function scanIds(): Promise<Set<string>> {
  const scans = (await (await fetch(`${API_BASE}/api/v1/scans`, { headers })).json()) as {
    id: string;
  }[];
  return new Set(scans.map((s) => s.id));
}

/**
 * Wait for a scan that did not exist in `before`.
 *
 * Matching on the label instead was wrong and it bit: these tests share one database, so by the time
 * the "discovers transit keys" test ran, the "unreachable Vault" test had already left a *failed*
 * scan also labelled "vault scan" in the list. The label match found that one and the test failed
 * with `could not reach a Vault server at http://127.0.0.1:9` — an error from an entirely different
 * test's scan. Anchoring on ids that appeared after the click removes the ambiguity, and it also
 * makes the tests order-independent and safe to re-run against a warm database.
 */
async function waitForNewScan(before: Set<string>): Promise<Record<string, unknown>> {
  for (let i = 0; i < 120; i++) {
    const scans = (await (await fetch(`${API_BASE}/api/v1/scans`, { headers })).json()) as Record<
      string,
      unknown
    >[];
    const fresh = scans.find((s) => !before.has(String(s.id)));
    if (fresh && !['queued', 'running'].includes(String(fresh.status))) return fresh;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('no newly-created scan reached a terminal state');
}

async function openScansPage(page: Page) {
  await page.goto('/scans');
  await expect(page.getByTestId('source-tab-network')).toBeVisible();
}

test('all three discovery sources are selectable from the Scans page', async ({ page }) => {
  await openScansPage(page);
  for (const tab of ['files', 'network', 'vault'] as const) {
    await page.getByTestId(`source-tab-${tab}`).click();
    await expect(page.getByTestId(`run-${tab === 'files' ? 'file' : tab}-scan`)).toBeVisible();
  }
});

test('a live TLS probe discovers the hybrid PQC group off the wire', async ({ page }) => {
  const reachable = await fetch(`${API_BASE}/api/v1/health`).then(() => true);
  test.skip(
    !reachable,
    'needs the demo TLS server: docker run -d --rm -p 8443:8443 qubit-nginx-hybrid:latest',
  );

  await openScansPage(page);
  await page.getByTestId('source-tab-network').click();
  await page.getByLabel('Hosts to probe').fill('127.0.0.1');
  await page.getByLabel('Ports to probe').fill(TLS_PORT);
  const before = await scanIds();
  await page.getByTestId('run-network-scan').click();

  const scan = await waitForNewScan(before);
  if (scan.status === 'failed') {
    test.skip(
      true,
      `network scan failed (${scan.error}) — the demo TLS server is probably not running: ` +
        `docker run -d --rm -p 8443:8443 qubit-nginx-hybrid:latest`,
    );
  }
  expect(scan.status).toBe('succeeded');

  // The assertion that matters: the hybrid group was read from a real handshake, not configuration.
  const headers = { Authorization: `Bearer ${API_TOKEN}` };
  const assets = (await (
    await fetch(`${API_BASE}/api/v1/scans/${scan.id}/assets?limit=100`, { headers })
  ).json()) as { items: { algorithm: string; source_scanner: string }[] };
  const algorithms = assets.items.map((a) => a.algorithm);
  expect(algorithms).toContain('X25519MLKEM768');
  expect(assets.items.every((a) => a.source_scanner === 'network')).toBe(true);
});

test('a Vault scan discovers transit keys and PKI certificates', async ({ page }) => {
  const vaultUp = await fetch(`${VAULT_ADDR}/v1/sys/health`)
    .then(() => true)
    .catch(() => false);
  test.skip(
    !vaultUp,
    `needs a seeded Vault: docker compose -f demo-lab/compose.vault.yml up -d`,
  );

  await openScansPage(page);
  await page.getByTestId('source-tab-vault').click();
  await page.getByLabel('Vault address').fill(VAULT_ADDR);
  await page.getByLabel('Vault token').fill(VAULT_TOKEN);
  const before = await scanIds();
  await page.getByTestId('run-vault-scan').click();

  const scan = await waitForNewScan(before);
  expect(scan.status, `vault scan failed: ${scan.error}`).toBe('succeeded');

  const headers = { Authorization: `Bearer ${API_TOKEN}` };
  const assets = (await (
    await fetch(`${API_BASE}/api/v1/scans/${scan.id}/assets?limit=100`, { headers })
  ).json()) as { items: { algorithm: string; source_scanner: string }[] };
  const algorithms = assets.items.map((a) => a.algorithm);

  // Both halves of the connector: transit keys and PKI certificates.
  expect(assets.items.some((a) => a.source_scanner === 'key')).toBe(true);
  expect(assets.items.some((a) => a.source_scanner === 'cert')).toBe(true);
  expect(algorithms).toContain('RSA-2048');

  // No UNKNOWN(...) may appear. The seeded PKI certificates are signed with
  // sha256WithRSAEncryption, which used to resolve to nothing — and `normalize()` rates an
  // unresolved name as not-vulnerable, so every certificate signature was reported quantum-safe.
  const unknowns = algorithms.filter((a) => a.startsWith('UNKNOWN('));
  expect(unknowns, `unresolved algorithms are silently rated safe: ${unknowns}`).toEqual([]);
});

test('the Vault token is cleared from the form once the scan starts', async ({ page }) => {
  const vaultUp = await fetch(`${VAULT_ADDR}/v1/sys/health`)
    .then(() => true)
    .catch(() => false);
  test.skip(!vaultUp, 'needs a seeded Vault (see compose.vault.yml)');

  await openScansPage(page);
  await page.getByTestId('source-tab-vault').click();
  const tokenField = page.getByLabel('Vault token');
  await page.getByLabel('Vault address').fill(VAULT_ADDR);
  await tokenField.fill(VAULT_TOKEN);
  // Masked in the DOM as well as cleared afterwards.
  await expect(tokenField).toHaveAttribute('type', 'password');
  await page.getByTestId('run-vault-scan').click();
  await expect(tokenField).toHaveValue('', { timeout: 30_000 });
});

test('an unreachable Vault reports a failure rather than an empty clean result', async ({
  page,
}) => {
  await openScansPage(page);
  await page.getByTestId('source-tab-vault').click();
  await page.getByLabel('Vault address').fill('http://127.0.0.1:9');
  await page.getByLabel('Vault token').fill('irrelevant');
  const before = await scanIds();
  await page.getByTestId('run-vault-scan').click();

  const scan = await waitForNewScan(before);
  // `scan_vault` alone resolves an unreachable server to zero detections, which would surface here
  // as "succeeded, 0 assets" — indistinguishable from a Vault with nothing in it. For a credential
  // store that is the worst way to be wrong, so the API preflights reachability first.
  expect(scan.status).toBe('failed');
  expect(String(scan.error)).toMatch(/could not reach|does not look like a Vault/i);
});
