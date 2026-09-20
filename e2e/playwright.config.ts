import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for mon-server's admin UI e2e harness.
 *
 * The app under test is this repo's own Docker image, started by
 * `e2e/docker-compose.yml` (see `make e2e`), listening on the port that
 * compose publishes (E2E_PORT, default 8443) with a self-signed TLS
 * certificate the compose entrypoint mints for 127.0.0.1 — hence
 * ignoreHTTPSErrors.
 *
 * fullyParallel is false and workers is pinned to 1: every spec talks to
 * the one mon-server instance the compose file starts, and requests.spec.ts
 * and settings.spec.ts mutate shared server state (the registry, the
 * settings row) that a spec run in a different worker could observe
 * mid-change — fullyParallel alone only serialises tests within one file,
 * Playwright still schedules different files onto different workers by
 * default.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `https://127.0.0.1:${process.env.E2E_PORT || 8443}`,
    ignoreHTTPSErrors: true,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
