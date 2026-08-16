import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests for the dashboard.
 *
 * These exist to close a verification gap that was previously stated as a known limit: the Report
 * page could be typechecked (`tsc -b`), its code confirmed present in the served bundle, and its API
 * payloads validated — but nobody had ever confirmed it RENDERS. Type-checking cannot catch a chart
 * that throws at mount, a `median(undefined)` that yields NaN on screen, or an export button that
 * saves an empty file. Only a real browser can.
 *
 * The API is expected to already be running (see e2e/report.spec.ts for how the fixture seeds it),
 * because the tests need real scan data with risk annotations — a mocked payload would prove the
 * component renders something, not that it renders THIS product's data.
 */
export default defineConfig({
  testDir: './e2e',
  // Rendering assertions are cheap; the seeding fixture is the slow part, so keep it serial and
  // let the API be the shared resource rather than racing several browsers against one SQLite file.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list']],
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    // `localhost`, not the 127.0.0.1 literal: `vite preview` binds only the hostname, which resolves
    // to ::1 here, so the IPv4 literal gets no response at all and the webServer wait times out.
    baseURL: process.env.QUBIT_DASHBOARD_URL ?? 'http://localhost:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  // `vite preview` serves the real production build — the same bundle nginx ships in the container,
  // rather than a dev-server build with different code splitting.
  webServer: process.env.QUBIT_DASHBOARD_URL
    ? undefined
    : {
        command: 'npm run preview -- --port 4173 --strictPort',
        url: 'http://localhost:4173',
        reuseExistingServer: true,
        timeout: 120_000,
      },
});
