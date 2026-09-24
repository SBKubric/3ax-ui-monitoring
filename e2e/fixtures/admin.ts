import { test as base, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';

/**
 * Credentials mon-server is started with. `e2e/docker-compose.yml` passes
 * these into the container (E2E_USERNAME/MON_ADMIN_PASSWORD, the latter fed
 * from E2E_PASSWORD), which the compose entrypoint hands to
 * `mon-server admin set` before the server starts. Kept in sync here via the
 * same env vars so a spec run against a server started outside `make e2e`
 * (E2E_BASE_URL... see playwright.config.ts) can still authenticate by
 * exporting the same variables.
 */
export const E2E_USERNAME = process.env.E2E_USERNAME || 'e2e';
export const E2E_PASSWORD = process.env.E2E_PASSWORD || 'e2e-password';

/**
 * Fills and submits the real login form at /admin/login. Does not assert
 * the outcome — callers check for the Requests redirect (success) or
 * `login-error` (failure).
 */
export async function loginAs(page: Page, username: string, password: string): Promise<void> {
  await page.goto('/admin/login');
  await fieldInput(page, 'login-username').fill(username);
  await fieldInput(page, 'login-password').fill(password);
  await page.getByTestId('login-submit').click();
}

/**
 * Resolves a `data-testid` on one of the Settings page's Ant Design Vue
 * `<a-input>`/`<a-input-password>` fields to the real `<input>` underneath.
 * Ant Design Vue forwards an unrecognized attribute like `data-testid` to
 * the wrapped `<input>` in the common case, but a version that instead
 * stamps it on the outer wrapper still matches the second half of this
 * selector — so a spec never has to know which shape a given antd build
 * produces. This is the one CSS this file uses, and it is still keyed by
 * data-testid, never by class names or DOM position.
 */
export function fieldInput(page: Page, testId: string): Locator {
  return page.locator(`input[data-testid="${testId}"], [data-testid="${testId}"] input`).first();
}

/** Pairing codes are 6 chars [A-Z2-9] (protocol §2.1). */
const PAIRING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789';

export function randomPairingCode(): string {
  let out = '';
  for (let i = 0; i < 6; i++) {
    out += PAIRING_ALPHABET[Math.floor(Math.random() * PAIRING_ALPHABET.length)];
  }
  return out;
}

export type RegisteredRequest = {
  requestId: string;
  pairingCode: string;
};

/**
 * Drives a mon-client's registration request through the wire protocol
 * (mon-protocol.md §2.1), the way a spec author exercises an API-only
 * feature per docs/agents/testing.md ("API-only features walk it through
 * Playwright's request context"). hostname defaults to a name unique per
 * call so repeated registrations in one spec run don't collide in the
 * Requests page or the "attempt" counter.
 */
export async function registerClient(
  request: APIRequestContext,
  opts: { hostname?: string; version?: string; publicIp?: string } = {},
): Promise<RegisteredRequest> {
  const pairingCode = randomPairingCode();
  const post = () =>
    request.post('/v1/register', {
      data: {
        pairingCode,
        hostname: opts.hostname ?? `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
        version: opts.version ?? '0.1.0',
        publicIp: opts.publicIp ?? '203.0.113.5',
      },
    });
  let res = await post();
  if (res.status() === 429) {
    // Every spec registers from the same address, and mon-server takes one
    // request per IP per minute (spec §6). A second spec that registers
    // waits the throttle out, as a real box would, with its own timeout
    // stretched by that wait.
    const waitMs = (Number(res.headers()['retry-after'] || '60') + 1) * 1000;
    base.info().setTimeout(base.info().timeout + waitMs);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    res = await post();
  }
  expect(res.status(), await res.text()).toBe(202);
  const body = await res.json();
  return { requestId: body.requestId, pairingCode };
}

type AdminFixtures = {
  /** A `page` already authenticated through the real login form, resolved on the Requests page. */
  adminPage: Page;
};

export const test = base.extend<AdminFixtures>({
  adminPage: async ({ page }, use) => {
    await loginAs(page, E2E_USERNAME, E2E_PASSWORD);
    await expect(page.getByTestId('requests-page')).toBeVisible();
    await use(page);
  },
});

export { expect };
