import { defineConfig, devices } from "@playwright/test";

const port = process.env.MON_PORT ?? "8443";

// The suite talks to the container started by docker-compose.yml, which serves
// a self-signed certificate, so TLS errors are expected and ignored here only.
export default defineConfig({
  testDir: "./specs",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: `https://localhost:${port}`,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
