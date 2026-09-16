// The Settings page and the two operations that must not touch what is stored
// (spec mon-server.md §9.3, §9.4):
//
//   - Save writes the settings, and they survive a reload.
//   - Check calls the panel with the values as typed and saves nothing.
//   - Revoke clears the client token; the observable half of it is that the
//     box's token stops working, which is checked through the request context.

import { expect, test } from "@playwright/test";
import {
  bearer,
  button,
  numberField,
  provisionMonClient,
  secretField,
  textField,
  uiLogin,
} from "../support/mon";

const storedPanelURL = "https://panel.example.test/monitoring";
const unreachablePanelURL = "http://127.0.0.1:1/unreachable";

test("the Settings page saves and the values survive a reload", async ({ page }) => {
  await uiLogin(page);
  await page.goto("/admin/settings");
  await expect(page.getByTestId("settings-status")).toBeVisible();

  await textField(page, "settings-panel-url").fill(storedPanelURL);

  await page.getByTestId("tab-thresholds").click();
  await numberField(page, "settings-down-after").fill("7");
  await numberField(page, "settings-up-after").fill("4");
  await numberField(page, "settings-flap-min").fill("45");

  await page.getByTestId("tab-telegram").click();
  await textField(page, "settings-tg-chat-id").fill("-1001234567890");

  await button(page, "settings-save").click();
  await expect(page.getByTestId("settings-error")).toHaveCount(0);

  await page.reload();
  await expect(textField(page, "settings-panel-url")).toHaveValue(storedPanelURL);

  await page.getByTestId("tab-thresholds").click();
  await expect(numberField(page, "settings-down-after")).toHaveValue("7");
  await expect(numberField(page, "settings-up-after")).toHaveValue("4");
  await expect(numberField(page, "settings-flap-min")).toHaveValue("45");

  await page.getByTestId("tab-telegram").click();
  await expect(textField(page, "settings-tg-chat-id")).toHaveValue("-1001234567890");

  // The read-only half of the page comes from the bootstrap configuration.
  await page.getByTestId("tab-tls").click();
  await expect(page.getByTestId("settings-tls-mode")).toContainText("files");
  await expect(page.getByTestId("settings-admin-hint")).toContainText("mon-server admin set");
});

test("Check reports an unreachable panel and saves nothing", async ({ page }) => {
  await uiLogin(page);
  await page.goto("/admin/settings");

  // A known starting point, so "nothing was saved" is a statement about these
  // values and not about whatever the page happened to hold.
  await textField(page, "settings-panel-url").fill(storedPanelURL);
  await button(page, "settings-save").click();
  await expect(page.getByTestId("settings-error")).toHaveCount(0);
  await page.reload();
  await expect(textField(page, "settings-panel-url")).toHaveValue(storedPanelURL);
  await expect(secretField(page, "settings-mon-token")).toHaveAttribute("placeholder", "not set");

  // Check acts on the values as typed: a panel that refuses the connection.
  await textField(page, "settings-panel-url").fill(unreachablePanelURL);
  await secretField(page, "settings-mon-token").fill("token-typed-for-the-check-only");
  await button(page, "settings-check").click();

  // The panel client retries a transport failure three times, 1 s → 2 s → 4 s.
  await expect(page.getByTestId("settings-check-result")).toContainText("Panel unreachable", {
    timeout: 60_000,
  });

  await page.reload();
  await expect(textField(page, "settings-panel-url")).toHaveValue(storedPanelURL);
  // The typed token was never stored either: the field still offers to store
  // one for the first time.
  await expect(secretField(page, "settings-mon-token")).toHaveAttribute("placeholder", "not set");
});

test("revoking a mon-client stops its token working", async ({ page, request }) => {
  const client = await provisionMonClient({
    name: "Revoke Warsaw",
    region: "PL",
    paths: ["proxy", "direct"],
    hostname: "vps-revoke-1",
  });

  const before = await request.get("/v1/probe?target=xray:12:proxy&n=before-revoke", {
    headers: bearer(client.token),
  });
  expect(before.status(), "the token works before the revoke").toBe(200);

  await uiLogin(page);
  await page.goto("/admin/clients");

  const row = page.getByTestId("client-row").filter({ hasText: client.id });
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("client-revoked")).toHaveCount(0);

  await button(row, "client-operations").click();
  await page.getByTestId(`client-revoke-${client.id}`).click();

  const modal = page.getByTestId("revoke-modal");
  await expect(modal).toBeVisible();
  await expect(modal).toContainText(client.id);
  await button(page, "revoke-submit").click();
  await expect(modal).toBeHidden();

  // The record stays in the registry, marked as having no token: the box will
  // register again and be approved as a replacement (§6).
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("client-revoked")).toContainText("token revoked");

  const after = await request.get("/v1/probe?target=xray:12:proxy&n=after-revoke", {
    headers: bearer(client.token),
  });
  expect(after.status(), "the token is dead after the revoke").toBe(401);
  expect(await after.json()).toMatchObject({ error: "token_revoked" });

  const heartbeat = await request.post("/v1/heartbeat", {
    headers: bearer(client.token),
    data: { monClientId: client.id, cycles: [] },
  });
  expect(heartbeat.status()).toBe(401);
});
