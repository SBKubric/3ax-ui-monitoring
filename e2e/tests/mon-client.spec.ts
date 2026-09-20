import { expect, fieldInput, test } from '../fixtures/admin';

/**
 * The hostname the mon-client container reports in its registration request
 * (protocol §2.1, from os.Hostname) — pinned by `hostname:` in
 * e2e/docker-compose.yml so this spec can find that one row among any other
 * requests a spec has filed.
 */
const CLIENT_HOSTNAME = 'mon-client-e2e';

/** The name it is approved under, and therefore its id (the slug of the name, spec §6). */
const CLIENT_NAME = 'e2e-box';
const CLIENT_REGION = 'E2E';

/**
 * How long the box may take to file its request. It registers as soon as it
 * starts, but `make e2e` brings the stack up before Playwright's own
 * install/startup, and a failed first attempt backs off (spec §3).
 */
const REGISTER_TIMEOUT = 60_000;

/**
 * How long it may take to turn ONLINE after approval: it polls the pending
 * request every 10s (protocol §2.2), then fetches GET /v1/config (503
 * config_not_ready here — no panel in this harness), waits out the start
 * jitter (spec §5, ≤ 5s) and only then runs its first empty cycle and
 * heartbeat, which is what makes mon-server call it ONLINE (spec §6).
 */
const ONLINE_TIMEOUT = 90_000;

// The one e2e test that involves a real mon-client rather than a request
// context imitating one (docs/agents/testing.md asks for mon-client and the
// protocol to be covered here): the container registers by itself, an
// administrator approves it through the real UI, and mon-server ends up
// showing it ONLINE with the version it reported. One test rather than
// several, because all of it is one box's single pass through spec §3–§6
// and the steps cannot be reordered or run independently.
test('mon-client registers, is approved through the UI, and goes ONLINE', async ({ adminPage }) => {
  test.setTimeout(REGISTER_TIMEOUT + ONLINE_TIMEOUT + 60_000);

  // The Requests page is rendered once per load (web/assets/page-requests.js
  // fetches on mount), so waiting for the box means reloading it.
  const row = adminPage.getByTestId('request-row').filter({ hasText: CLIENT_HOSTNAME });
  await expect(async () => {
    await adminPage.goto('/admin/requests');
    await expect(row).toHaveCount(1);
  }).toPass({ timeout: REGISTER_TIMEOUT, intervals: [2000] });

  await expect(row.getByTestId('request-hostname')).toHaveText(CLIENT_HOSTNAME);
  // The pairing code the operator would be reading off the box's console
  // (protocol §2.1, rendered "7K3 F9Q" by web/assets/app.js).
  const code = (await row.getByTestId('request-code').innerText()).trim();
  expect(code).toMatch(/^[A-Z2-9]{3} [A-Z2-9]{3}$/);

  // Approve it the way an administrator does: through the modal, not the API.
  await row.getByTestId('request-approve').click();
  const modal = adminPage.getByTestId('approve-modal');
  await expect(modal).toBeVisible();
  await modal.getByTestId('approve-mode-new').click();
  await fieldInput(adminPage, 'approve-name').fill(CLIENT_NAME);
  await fieldInput(adminPage, 'approve-region').fill(CLIENT_REGION);
  await modal.getByTestId('approve-submit').click();
  await expect(adminPage.getByTestId('request-row').filter({ hasText: CLIENT_HOSTNAME })).toHaveCount(0);

  // From here the box is on its own: it polls the request, picks up its
  // token, fetches its config and heartbeats. The admin UI is the operator's
  // view of that, so it is what this spec waits on — again by reloading,
  // since /admin/clients also loads once per visit.
  const clientRow = adminPage.locator(`[data-testid="client-row"][data-client-id="${CLIENT_NAME}"]`);
  await expect(async () => {
    await adminPage.goto('/admin/clients');
    await expect(clientRow).toHaveCount(1);
    await expect(clientRow.getByTestId('client-state')).toHaveText('ONLINE');
  }).toPass({ timeout: ONLINE_TIMEOUT, intervals: [3000] });

  // And the same answer from the API behind that page, which is where the
  // heartbeat's own fields land (protocol §5.3): the session cookie comes
  // from the logged-in page's context, and GET needs no X-Requested-With —
  // that guard is on mutating calls only (internal/admin/admin.go).
  const res = await adminPage.request.get('/admin/api/clients');
  expect(res.status(), await res.text()).toBe(200);
  const body = await res.json();
  expect(body.success).toBe(true);
  const client = body.obj.clients.find((c: { id: string }) => c.id === CLIENT_NAME);
  expect(client, `no mon-client ${CLIENT_NAME} in ${JSON.stringify(body.obj.clients)}`).toBeTruthy();
  expect(client.state).toBe('ONLINE');
  expect(client.enabled).toBe(true);
  // client.version is what the container's build stamped (Dockerfile.mon-client's
  // VERSION arg, "dev" unless a release build overrides it) — non-empty means
  // the heartbeat's client block arrived, not just some row.
  expect(typeof client.version).toBe('string');
  expect(client.version.length).toBeGreaterThan(0);
});
