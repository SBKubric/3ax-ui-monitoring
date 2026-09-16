import { defineConfig, devices } from "@playwright/test";

const port = process.env.MON_PORT ?? "8443";

// Registration is rate limited to one request per minute and IP (spec §6), and
// every spec comes from the same address, so a spec that needs a mon-client of
// its own waits out the Retry-After mon-server sends. One minute of waiting
// plus the walk itself does not fit in Playwright's 30 s default.
const testTimeout = 180_000;

// A browser that does not match the pinned @playwright/test — a pre-installed
// one in a sandbox, for instance — is used as it is instead of downloading:
// MON_CHROMIUM=/path/to/chrome. Unset, which is the normal case and the one
// `make e2e` runs, Playwright picks its own browser.
const chromium = process.env.MON_CHROMIUM;

// The suite talks to the container started by docker-compose.yml, which serves
// a self-signed certificate, so TLS errors are expected and ignored here only.
export default defineConfig({
  testDir: "./specs",
  fullyParallel: false,
  workers: 1,
  timeout: testTimeout,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: `https://localhost:${port}`,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: chromium ? { executablePath: chromium } : {},
      },
    },
  ],
});
