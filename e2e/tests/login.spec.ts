import { E2E_PASSWORD, E2E_USERNAME, expect, loginAs, test } from '../fixtures/admin';

test.describe('login', () => {
  test('wrong password shows login-error and stays on the login page', async ({ page }) => {
    await loginAs(page, E2E_USERNAME, 'definitely-not-the-password');

    await expect(page.getByTestId('login-error')).toBeVisible();
    await expect(page).not.toHaveURL(/\/admin\/requests/);
  });

  test('right password lands on the Requests page', async ({ page }) => {
    await loginAs(page, E2E_USERNAME, E2E_PASSWORD);

    await expect(page).toHaveURL(/\/admin\/requests$/);
    await expect(page.getByTestId('requests-page')).toBeVisible();
  });

  test('logout returns to the login page', async ({ adminPage }) => {
    await adminPage.getByTestId('logout-button').click();

    await expect(adminPage).toHaveURL(/\/admin\/login/);
    await expect(adminPage.getByTestId('login-page')).toBeVisible();
  });

  test('/admin/clients unauthenticated redirects to /admin/login', async ({ page }) => {
    await page.goto('/admin/clients');

    await expect(page).toHaveURL(/\/admin\/login/);
    await expect(page.getByTestId('login-page')).toBeVisible();
  });
});
