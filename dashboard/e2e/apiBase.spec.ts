import { expect, test } from '@playwright/test';

/**
 * `normalizeApiBase` — the fix for a trap that cost real debugging time.
 *
 * Every request path in the API client is bare (`/health`, `/scans/{id}`), so the stored base has to
 * carry the `/api/v1` prefix. Typing the obvious thing into the Login page — an origin like
 * `http://localhost:8000` — used to be stored verbatim, and then every call 404ed. The only visible
 * symptom was the boot gate spinning on "Starting the engine…", which points at a dead API rather
 * than a URL one path segment short.
 *
 * The function lives in `src/api/apiBase.ts` rather than in `client.ts` precisely so a plain unit test
 * can import it: `client.ts` reads `import.meta.env`, a Vite build-time construct that does not exist
 * in a Node test process. The assertions here are pure and need no page.
 */

// Imported from the source module so the test tracks the real implementation.
import { API_PREFIX, normalizeApiBase } from '../src/api/apiBase';

test.describe('normalizeApiBase', () => {
  test('appends the prefix to a bare origin — the case that used to break everything', () => {
    expect(normalizeApiBase('http://localhost:8000')).toBe(`http://localhost:8000${API_PREFIX}`);
    expect(normalizeApiBase('http://127.0.0.1:8787')).toBe(`http://127.0.0.1:8787${API_PREFIX}`);
    expect(normalizeApiBase('https://qubit.example.test')).toBe(
      `https://qubit.example.test${API_PREFIX}`,
    );
  });

  test('leaves an already-correct base alone (idempotent)', () => {
    const good = `http://localhost:8000${API_PREFIX}`;
    expect(normalizeApiBase(good)).toBe(good);
    // Idempotence matters because setApiBase stores the normalized value and getApiBase normalizes
    // again on read — a non-idempotent version would append the prefix twice.
    expect(normalizeApiBase(normalizeApiBase(good))).toBe(good);
  });

  test('tolerates trailing slashes and surrounding whitespace', () => {
    expect(normalizeApiBase('http://localhost:8000/')).toBe(`http://localhost:8000${API_PREFIX}`);
    expect(normalizeApiBase('http://localhost:8000///')).toBe(`http://localhost:8000${API_PREFIX}`);
    expect(normalizeApiBase(`  http://localhost:8000${API_PREFIX}/  `)).toBe(
      `http://localhost:8000${API_PREFIX}`,
    );
  });

  test('completes the near-miss `/api` into `/api/v1`', () => {
    expect(normalizeApiBase('http://localhost:8000/api')).toBe(
      `http://localhost:8000${API_PREFIX}`,
    );
  });

  test('falls back to the local default for an empty value', () => {
    // An empty string in localStorage or an unset env var must not produce a relative `/api/v1`,
    // which in the Tauri desktop shell would resolve against tauri.localhost and never reach the API.
    expect(normalizeApiBase('')).toBe(`http://127.0.0.1:8787${API_PREFIX}`);
    expect(normalizeApiBase('   ')).toBe(`http://127.0.0.1:8787${API_PREFIX}`);
  });
});
