import { expect, test, type Page } from '@playwright/test';

/**
 * The Settings page's "LLM provider" card: which engine QUBIT calls to generate patches.
 *
 * The backend suites (packages/qubit-api/tests/test_llm_provider_api.py,
 * packages/qubit-migrate/tests/test_llm_provider_dispatch.py) already prove the data layer and
 * the dispatcher. This closes the gap the rest of this suite closes for other pages: that the
 * card actually reads and writes the real config, that switching provider reveals the right
 * fields, and — the one that matters most — that the "Local & offline" claim stops asserting
 * "no cloud LLM is contacted" the moment an external provider is configured.
 *
 * No mock: it drives the real API, matching sources.spec.ts and threatIntel.spec.ts. Skipped
 * loudly when no API is reachable. The saved configuration is restored at the end of each test
 * that changes it, so running this suite does not leave the app pointed somewhere unexpected.
 */

const API_BASE = process.env.QUBIT_API_BASE ?? 'http://127.0.0.1:8000';
const API_TOKEN = process.env.QUBIT_API_TOKEN ?? 'qubit-dev-token-do-not-use-in-prod';
const headers = { Authorization: `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' };

type Config = {
  provider: string;
  base_url: string | null;
  model: string | null;
  api_key_configured: boolean;
  context_tokens: number | null;
};

const readConfig = async (): Promise<Config> =>
  (await fetch(`${API_BASE}/api/v1/llm-provider/config`, { headers })).json();

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
  await expect(page.getByTestId('llm-provider-card')).toBeVisible();
}

test('the card renders and offers both engines', async ({ page }) => {
  await openSettings(page);
  await expect(page.getByTestId('llm-provider-select-ollama')).toBeVisible();
  await expect(page.getByTestId('llm-provider-select-openai-compatible')).toBeVisible();
});

test('choosing External reveals the endpoint fields and the free presets', async ({ page }) => {
  await openSettings(page);
  await page.getByTestId('llm-provider-select-openai-compatible').click();

  await expect(page.locator('#llm-base-url')).toBeVisible();
  await expect(page.locator('#llm-model')).toBeVisible();
  await expect(page.locator('#llm-api-key')).toBeVisible();
  // The API key must never be readable off the page.
  await expect(page.locator('#llm-api-key')).toHaveAttribute('type', 'password');

  for (const preset of ['groq', 'openrouter', 'custom']) {
    await expect(page.getByTestId(`llm-preset-${preset}`)).toBeVisible();
  }

  // A preset prefills the endpoint but never a key — that is always typed by a person.
  await page.getByTestId('llm-preset-groq').click();
  await expect(page.locator('#llm-base-url')).toHaveValue(/api\.groq\.com/);
  await expect(page.locator('#llm-api-key')).toHaveValue('');
});

test('the offline claim tells the truth about the configured engine', async ({ page }) => {
  // The one assertion here that is about honesty rather than mechanics: the card used to state
  // flatly that "no cloud LLM is contacted", which is false the moment a key is configured.
  const before = await readConfig();
  await openSettings(page);

  const claim = page.locator('li', { hasText: 'Patch generation' }).first();
  await expect(claim).toBeVisible();

  if (before.provider === 'openai-compatible' && before.api_key_configured) {
    await expect(claim).toContainText(/external LLM/i);
    await expect(claim).toContainText(String(before.base_url));
    await expect(claim).not.toContainText(/no cloud LLM is contacted/i);
  } else {
    await expect(claim).toContainText(/local/i);
    await expect(claim).toContainText(/no cloud LLM is contacted/i);
  }
});

test('the saved engine round-trips through the API', async ({ page }) => {
  const before = await readConfig();
  await openSettings(page);

  if (before.provider === 'openai-compatible') {
    await expect(page.locator('#llm-base-url')).toHaveValue(before.base_url ?? '');
    await expect(page.locator('#llm-model')).toHaveValue(before.model ?? '');
    // The allowance is what decides patch-vs-guidance for a large file, so it is worth showing.
    if (before.context_tokens) {
      await expect(page.getByTestId('llm-context-tokens')).toContainText(
        before.context_tokens.toLocaleString(),
      );
    }
  } else {
    // Local is the default; the external fields stay hidden until the user opts in.
    await expect(page.locator('#llm-base-url')).toBeHidden();
  }
});

test('a configured key is shown as configured, never as its value', async ({ page }) => {
  const before = await readConfig();
  test.skip(!before.api_key_configured, 'no API key configured on this install');
  await openSettings(page);
  await page.getByTestId('llm-provider-select-openai-compatible').click();

  // The placeholder proves a key is saved without ever putting it in the DOM.
  const placeholder = await page.locator('#llm-api-key').getAttribute('placeholder');
  expect(placeholder).toMatch(/configured/i);
  await expect(page.locator('#llm-api-key')).toHaveValue('');

  // And nothing key-shaped leaks into the rendered page.
  const body = await page.locator('body').innerText();
  expect(body).not.toMatch(/\b(gsk_|csk-|sk-[A-Za-z0-9]{16})/);
});
