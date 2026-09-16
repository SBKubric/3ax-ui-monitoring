// Health check and the admin session (spec mon-server.md §9.1).
//
// Deliberately NOT covered here: the five-failure IP lockout. It would lock
// the address every other spec of this run comes from, so the browser suite
// stops at a single refused password; the lockout itself is covered by the
// unit tests of internal/admin (session_test.go).

import { expect, test } from "@playwright/test";
import {
  adminPassword,
  adminUser,
  button,
  secretField,
  textField,
} from "../support/mon";

test("GET /healthz answers 200 to a caller with no credentials", async ({ request }) => {
  const res = await request.get("/healthz");
  expect(res.status()).toBe(200);
  expect((await res.text()).trim()).toBe("ok");
});

test("an admin page without a session redirects to the login, an admin API call is 401", async ({
  request,
}) => {
  const page = await request.get("/admin/clients", { maxRedirects: 0 });
  expect(page.status()).toBe(303);
  expect(page.headers()["location"]).toBe("/admin/login?next=%2Fadmin%2Fclients");

  // The JSON API answers 401 with the envelope instead of redirecting, so the
  // page can react rather than parse an HTML body (§9.1).
  const api = await request.get("/admin/api/clients");
  expect(api.status()).toBe(401);
  const env = await api.json();
  expect(env.success).toBe(false);
  expect(env.msg).toContain("not signed in");
});

test("the login page renders, refuses a wrong password and accepts the right one", async ({
  page,
}) => {
  await page.goto("/admin/login");
  await expect(page.getByTestId("login-form")).toBeVisible();
  await expect(page.getByTestId("login-subtitle")).toBeVisible();
  await expect(page.getByTestId("login-hint")).toContainText("mon-server admin set");

  // One wrong password, and one only: the sixth would lock this address out
  // for the rest of the run.
  await textField(page, "login-username").fill(adminUser);
  await secretField(page, "login-password").fill("not-the-password");
  await button(page, "login-submit").click();

  await expect(page.getByTestId("login-error")).toBeVisible();
  await expect(page.getByTestId("login-error")).toContainText("Wrong username or password");
  await expect(page).toHaveURL(/\/admin\/login/);
  await expect(page.getByTestId("login-hint")).toContainText("attempts left");

  await secretField(page, "login-password").fill(adminPassword);
  await button(page, "login-submit").click();

  await page.waitForURL("**/admin/requests");
  await expect(page.getByTestId("nav-requests")).toBeVisible();
  await expect(page.getByTestId("requests-table")).toBeVisible();
});

test("logging out ends the session", async ({ page }) => {
  await page.goto("/admin/login");
  await textField(page, "login-username").fill(adminUser);
  await secretField(page, "login-password").fill(adminPassword);
  await button(page, "login-submit").click();
  await page.waitForURL("**/admin/requests");

  // The session works before the logout.
  const before = await page.request.get("/admin/api/clients");
  expect(before.status()).toBe(200);

  await page.getByTestId("nav-logout").click();
  await page.waitForURL("**/admin/login**");
  await expect(page.getByTestId("login-form")).toBeVisible();

  // The cookie the browser still has is no longer a session.
  const after = await page.request.get("/admin/api/clients");
  expect(after.status()).toBe(401);

  await page.goto("/admin/settings");
  await expect(page).toHaveURL(/\/admin\/login\?next=%2Fadmin%2Fsettings/);
  await expect(page.getByTestId("login-form")).toBeVisible();
});
