import { expect, test, type Page } from '@playwright/test';

/**
 * The "Clean up" control in the top rail: remove previous migrations, scans or projects.
 *
 * It lives in `Layout`, not on a page, because it is what people reach for when a run went wrong
 * or a disk is full — and they reach for it from wherever they happen to be, not only from the
 * panel that owns the data. So the first thing worth asserting is simply that it is *there*, on
 * every route.
 *
 * **This suite never confirms a deletion, deliberately.** It runs against the real API on a real
 * database, and the safety property is the one worth testing anyway: a single click must not
 * destroy anything. Arming and then walking away has to leave the data alone. A test that proved
 * "delete works" by deleting the operator's corpus would be trading the thing being protected for
 * the proof that it is protected.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';
const headers = { Authorization: `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' };

const ROUTES = [
  '/scans',
  '/',
  '/inventory',
  '/risk',
  '/timeline',
  '/compliance',
  '/migrations',
  '/settings',
];

async function counts() {
  const get = async (p: string) => (await fetch(`${API_BASE}/api/v1${p}`, { headers })).json();
  const [projects, scans, plans] = await Promise.all([
    get('/projects'),
    get('/scans'),
    get('/migrate/plans'),
  ]);
  return {
    projects: (projects as unknown[]).length,
    scans: (scans as unknown[]).length,
    plans: (plans as unknown[]).length,
  };
}

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

async function openCleanup(page: Page) {
  await page.getByTestId('cleanup-open').click();
  await expect(page.getByTestId('cleanup-panel')).toBeVisible();
}

for (const route of ROUTES) {
  test(`the cleanup control is reachable from ${route}`, async ({ page }) => {
    await page.goto(route);
    await expect(page.getByTestId('cleanup-open')).toBeVisible();
  });
}

test('it offers all three rungs, weakest first', async ({ page }) => {
  await page.goto('/scans');
  await openCleanup(page);

  for (const rung of ['plans', 'scans', 'projects']) {
    await expect(page.getByTestId(`cleanup-row-${rung}`)).toBeVisible();
  }
  // Order is the point: clearing a migration is cheap to undo, resetting projects is not.
  const labels = await page.getByTestId(/^cleanup-row-/).allTextContents();
  expect(labels[0]).toContain('Clear migrations');
  expect(labels[1]).toContain('Clear scans');
  expect(labels[2]).toContain('Reset everything');
});

test('each rung says what it keeps, not only what it destroys', async ({ page }) => {
  await page.goto('/scans');
  await openCleanup(page);

  await expect(page.getByTestId('cleanup-row-plans')).toContainText('Keeps');
  await expect(page.getByTestId('cleanup-row-plans')).toContainText('every scan and every finding');
  await expect(page.getByTestId('cleanup-row-scans')).toContainText('project shells');
  // The one that survives all three — the expensive thing to lose.
  await expect(page.getByTestId('cleanup-panel')).toContainText('Kept either way');
  await expect(page.getByTestId('cleanup-panel')).toContainText('learned');
});

test('the counts shown are the real ones', async ({ page }) => {
  const before = await counts();
  await page.goto('/scans');
  await openCleanup(page);

  await expect(page.getByTestId('cleanup-row-scans')).toContainText(String(before.scans));
  await expect(page.getByTestId('cleanup-row-projects')).toContainText(String(before.projects));
});

test('one click arms, it does not delete', async ({ page }) => {
  // The assertion this file exists for. Arming is reversible; the data must be untouched after it.
  const before = await counts();
  test.skip(
    before.projects === 0 && before.scans === 0 && before.plans === 0,
    'nothing to remove, so "did not remove it" proves nothing',
  );
  await page.goto('/scans');
  await openCleanup(page);

  const rung = before.plans > 0 ? 'plans' : before.scans > 0 ? 'scans' : 'projects';
  await page.getByTestId(`cleanup-arm-${rung}`).click();

  // Armed: a second, differently-worded button appears, naming the number out loud.
  await expect(page.getByTestId(`cleanup-confirm-${rung}`)).toBeVisible();
  await expect(page.getByTestId(`cleanup-confirm-${rung}`)).toContainText('Yes, delete');

  await page.getByTestId(`cleanup-cancel-${rung}`).click();
  await expect(page.getByTestId(`cleanup-confirm-${rung}`)).toBeHidden();

  expect(await counts()).toEqual(before);
});

test('closing the panel disarms it', async ({ page }) => {
  // An armed destructive button left behind a closed panel is a click waiting to happen to
  // whoever opens it next.
  const before = await counts();
  test.skip(before.plans === 0 && before.scans === 0, 'nothing to arm');
  await page.goto('/scans');
  await openCleanup(page);

  const rung = before.plans > 0 ? 'plans' : 'scans';
  await page.getByTestId(`cleanup-arm-${rung}`).click();
  await expect(page.getByTestId(`cleanup-confirm-${rung}`)).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(page.getByTestId('cleanup-panel')).toBeHidden();
  await openCleanup(page);

  await expect(page.getByTestId(`cleanup-confirm-${rung}`)).toBeHidden();
  await expect(page.getByTestId(`cleanup-arm-${rung}`)).toBeVisible();
  expect(await counts()).toEqual(before);
});
