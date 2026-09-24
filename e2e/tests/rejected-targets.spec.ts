import { expect, registerClient, test } from '../fixtures/admin';

// Decision #53 п. 3 (issue #67): a mon-client applies its revision target by
// target and reports the targets it could not turn into probes as
// client.rejectedTargets in every heartbeat (mon-protocol.md §5.3). The
// operator sees them on the mon-clients page (spec §9.3): a tag in the
// Config column, and each target with the box's own error in the Edit
// modal. The box here is Playwright's request context (docs/agents/testing.md:
// "the protocol through Playwright's request context"), because the real
// mon-client container of this harness has no panel behind it and so no
// targets to reject.
test('targets a mon-client rejected are shown with their errors', async ({ adminPage, request }) => {
  const hostname = `e2e-rejecting-${Date.now()}`;
  const { requestId } = await registerClient(request, { hostname });

  // Approve through the admin API — the approval UI has its own spec
  // (requests.spec.ts); this one is about what a heartbeat leaves behind.
  const approved = await adminPage.request.post(`/admin/api/requests/${requestId}/approve`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: { mode: 'new', name: 'Rejecting Box', region: 'E2E', paths: ['proxy', 'direct'] },
  });
  expect(approved.status(), await approved.text()).toBe(200);
  const monClientId: string = (await approved.json()).obj.monClientId;

  let token = '';
  await expect(async () => {
    const res = await request.get(`/v1/register/${requestId}`);
    const body = await res.json();
    expect(body.status).toBe('approved');
    token = body.token;
  }).toPass({ timeout: 15000 });

  const unknownKey = '[Interface] has an unknown key "Foo"';
  const hb = await request.post('/v1/heartbeat', {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      monClientId,
      configRevision: 'rev-e2e',
      client: {
        version: '0.1.0',
        xrayVersion: '',
        uptimeMs: 1000,
        configError: null,
        rejectedTargets: [{ target: 'awg:3:direct', error: unknownKey }],
      },
      cycles: [{ seq: 1, ts: Date.now(), unverified: false, results: [] }],
    },
  });
  expect(hb.status(), await hb.text()).toBe(200);

  await adminPage.goto('/admin/clients');
  const row = adminPage.locator(`[data-testid="client-row"][data-client-id="${monClientId}"]`);
  await expect(row.getByTestId('client-rejected')).toHaveText(/1 rejected/);

  await row.getByTestId('client-actions').click();
  await adminPage.getByTestId('client-edit').click();
  const modal = adminPage.getByTestId('edit-modal');
  await expect(modal).toBeVisible();
  const rejected = modal.getByTestId('edit-rejected-target');
  await expect(rejected).toHaveCount(1);
  await expect(rejected.getByTestId('edit-rejected-target-key')).toHaveText('awg:3:direct');
  await expect(rejected.getByTestId('edit-rejected-target-error')).toHaveText(unknownKey);
  await modal.getByTestId('edit-cancel').click();

  // A heartbeat that no longer lists it clears it.
  const clean = await request.post('/v1/heartbeat', {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      monClientId,
      configRevision: 'rev-e2e-2',
      client: { version: '0.1.0', xrayVersion: '', uptimeMs: 2000, configError: null },
      cycles: [{ seq: 2, ts: Date.now(), unverified: false, results: [] }],
    },
  });
  expect(clean.status(), await clean.text()).toBe(200);
  await adminPage.goto('/admin/clients');
  await expect(row.getByTestId('client-state')).toHaveText('ONLINE');
  await expect(row.getByTestId('client-rejected')).toHaveCount(0);
});
