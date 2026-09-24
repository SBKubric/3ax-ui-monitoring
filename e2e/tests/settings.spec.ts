import * as tls from 'node:tls';
import type { Locator, Page } from '@playwright/test';
import { expect, fieldInput, test } from '../fixtures/admin';

/** The Panel CA textarea (antd may or may not wrap it). */
function panelCaField(page: Page): Locator {
  return page.locator('textarea[data-testid="field-panelCa"], [data-testid="field-panelCa"] textarea').first();
}

/**
 * The certificate mon-server itself serves, as PEM. The harness' mon-server
 * runs on a self-signed certificate for 127.0.0.1 — exactly the shape of a
 * stand panel — so it stands in for "a panel no system CA trusts" in the
 * panelCa spec below.
 */
async function serverCertPEM(): Promise<string> {
  const port = Number(process.env.E2E_PORT || 8443);
  const der: Buffer = await new Promise((resolve, reject) => {
    const sock = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => {
      const raw = sock.getPeerCertificate().raw;
      sock.end();
      resolve(raw);
    });
    sock.on('error', reject);
  });
  const b64 = der.toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

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

  test('panel CA: Check names an untrusted certificate, trusts a pasted one; Save refuses garbage', async ({ adminPage }) => {
    await adminPage.goto('/admin/settings');
    await adminPage.getByTestId('tab-real').click();

    // Inside the container mon-server reaches itself at 127.0.0.1:443 on
    // its self-signed certificate: with the system CAs that is "unknown
    // authority", and Check says so and points at Panel CA.
    await fieldInput(adminPage, 'field-panelUrl').fill('https://127.0.0.1:443/');
    await fieldInput(adminPage, 'field-monToken').fill('not-a-real-token');
    await adminPage.getByTestId('settings-check').click();
    const result = adminPage.getByTestId('settings-check-result');
    await expect(result).toContainText('unknown authority', { timeout: 15000 });
    await expect(result).toContainText('Panel CA');

    // With its certificate pasted as Panel CA the handshake passes; mon-server
    // is not a panel, so what comes back is the contract's bare 404.
    const pem = await serverCertPEM();
    await panelCaField(adminPage).fill(pem);
    await adminPage.getByTestId('settings-check').click();
    await expect(result).toContainText('404', { timeout: 15000 });
    await expect(result).not.toContainText('unknown authority');

    // Save refuses a Panel CA that is not PEM, and keeps nothing of it (the
    // whole form is refused, URL and token included).
    await panelCaField(adminPage).fill('not a certificate');
    await adminPage.getByTestId('settings-save').click();
    await expect(adminPage.getByText(/panelCa/).first()).toBeVisible();
    await adminPage.reload();
    await adminPage.getByTestId('tab-real').click();
    await expect(panelCaField(adminPage)).toHaveValue('');

    // A real certificate saves and survives a reload. The URL and token
    // stay empty so the poll loop is not pointed at mon-server itself for
    // the specs that run after this one.
    await fieldInput(adminPage, 'field-panelUrl').fill('');
    await fieldInput(adminPage, 'field-monToken').fill('');
    await panelCaField(adminPage).fill(pem);
    await adminPage.getByTestId('settings-save').click();
    await expect(adminPage.getByText('Saved.').first()).toBeVisible();
    await adminPage.reload();
    await adminPage.getByTestId('tab-real').click();
    await expect(panelCaField(adminPage)).toHaveValue(pem.trim());
  });
});
