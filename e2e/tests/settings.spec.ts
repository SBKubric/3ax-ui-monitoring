import { expect, fieldInput, test } from '../fixtures/admin';

test.describe('settings', () => {
  test('thresholds tab: a saved field survives a reload', async ({ adminPage }) => {
    await adminPage.goto('/admin/settings');
    await expect(adminPage.getByTestId('settings-page')).toBeVisible();

    await adminPage.getByTestId('tab-thresholds').click();
    await fieldInput(adminPage, 'field-downAfter').fill('4');
    await adminPage.getByTestId('settings-save').click();
    await expect(adminPage.getByTestId('settings-status')).toBeVisible();

    await adminPage.reload();
    await adminPage.getByTestId('tab-thresholds').click();
    await expect(fieldInput(adminPage, 'field-downAfter')).toHaveValue('4');
  });

  test('check with an unreachable panel URL shows an error and saves nothing', async ({ adminPage }) => {
    await adminPage.goto('/admin/settings');
    await adminPage.getByTestId('tab-real').click();

    // A closed port on the loopback address: nothing is listening, so the
    // request fails fast instead of waiting on a routing black hole.
    await fieldInput(adminPage, 'field-panelUrl').fill('https://127.0.0.1:9/');
    await fieldInput(adminPage, 'field-monToken').fill('not-a-real-token');
    await adminPage.getByTestId('settings-check').click();

    await expect(adminPage.getByTestId('settings-check-result')).toBeVisible({ timeout: 15000 });
    const text = await adminPage.getByTestId('settings-check-result').textContent();
    expect(text).not.toMatch(/^revision /);

    // Check never saves: reloading shows the panel URL field empty again
    // (the settings row was never touched).
    await adminPage.reload();
    await adminPage.getByTestId('tab-real').click();
    await expect(fieldInput(adminPage, 'field-panelUrl')).toHaveValue('');
  });
});
