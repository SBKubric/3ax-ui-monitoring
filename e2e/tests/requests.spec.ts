import { expect, fieldInput, registerClient, test } from '../fixtures/admin';

// Walks the whole registration path (mon-protocol.md §2): a mon-client
// registers over the wire (Playwright's request context, per
// docs/agents/testing.md — "API-only features walk it through Playwright's
// request context"), an administrator approves it through the real UI, the
// approved mon-client shows up on /admin/clients, and the token the box
// receives on its next poll works end to end against GET /v1/config.
test('register, approve through the UI, and use the issued token', async ({ adminPage, request }) => {
  const { requestId, pairingCode } = await registerClient(request, { hostname: 'e2e-ams-1' });

  await adminPage.goto('/admin/requests');
  const row = adminPage.getByTestId('request-row').filter({ hasText: 'e2e-ams-1' });
  await expect(row).toBeVisible();
  await expect(row.getByTestId('request-code')).toHaveText(spaced(pairingCode));

  await row.getByTestId('request-approve').click();

  const modal = adminPage.getByTestId('approve-modal');
  await expect(modal).toBeVisible();
  await modal.getByTestId('approve-mode-new').click();
  await fieldInput(adminPage, 'approve-name').fill('AMS One');
  await fieldInput(adminPage, 'approve-region').fill('NL');
  await modal.getByTestId('approve-submit').click();

  // The row disappears from Requests once approved.
  await expect(adminPage.getByTestId('request-row').filter({ hasText: 'e2e-ams-1' })).toHaveCount(0);

  // The new mon-client shows up on /admin/clients.
  await adminPage.goto('/admin/clients');
  const clientRow = adminPage.getByTestId('client-row').filter({ hasText: 'AMS One' });
  await expect(clientRow).toBeVisible();

  // Poll the registration request the way the mon-client itself would
  // (protocol §2.2) until the approval hands over its one-time token.
  let token = '';
  await expect(async () => {
    const res = await request.get(`/v1/register/${requestId}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('approved');
    expect(typeof body.token).toBe('string');
    token = body.token;
  }).toPass({ timeout: 15000 });

  // The token works end to end: GET /v1/config answers 503 config_not_ready
  // (protocol §4.2) because no panel is configured in this harness — proving
  // the token authenticates rather than merely exists.
  const cfgRes = await request.get('/v1/config', { headers: { Authorization: `Bearer ${token}` } });
  expect(cfgRes.status()).toBe(503);
  const cfgBody = await cfgRes.json();
  expect(cfgBody.error).toBe('config_not_ready');
});

/** Mirrors web/assets/app.js's own `spaced()` rendering of a pairing code ("7K3 F9Q"). */
function spaced(code: string): string {
  return code.slice(0, 3) + ' ' + code.slice(3);
}
