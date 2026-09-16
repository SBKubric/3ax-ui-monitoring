// The registration walk: a box files a request, the administrator approves it
// in the browser, the box collects its token exactly once and appears in the
// registry (spec mon-server.md §6, §9.2, §9.3; mon-protocol.md §2).
//
// This is the one path that touches every layer of mon-server, so it is walked
// end to end: the two /v1/register calls through Playwright's request context,
// the approval through the modal in a real browser.

import { expect, test } from "@playwright/test";
import {
  button,
  checkbox,
  pairingCode,
  pollRegistration,
  spacedCode,
  submitRegistration,
  textField,
  uiLogin,
} from "../support/mon";

const hostname = "vps-walk-1";
const version = "0.4.2";
const name = "Walk Amsterdam";
const region = "NL";
const derivedId = "walk-amsterdam";

test("a box registers, is approved in the browser and collects its token once", async ({
  page,
  request,
}) => {
  const code = pairingCode();

  const submitted = await test.step("the box files a registration request", async () => {
    const submitted = await submitRegistration(request, {
      pairingCode: code,
      hostname,
      version,
      publicIp: "203.0.113.5",
    });
    expect(submitted.requestId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(submitted.pollAfter).toBe(10_000);
    expect(submitted.expiresAt).toBeGreaterThan(Date.now());

    const pending = await pollRegistration(request, submitted.requestId);
    expect(pending.status).toBe(200);
    expect(pending.body.status).toBe("pending");
    expect(pending.body.token).toBeUndefined();
    return submitted;
  });

  await test.step("the administrator sees the pairing code of that box", async () => {
    await uiLogin(page);
    await page.getByTestId("nav-requests").click();
    await page.waitForURL("**/admin/requests");

    const row = page.getByTestId("request-row").filter({ hasText: hostname });
    await expect(row).toHaveCount(1);
    await expect(row.getByTestId("request-hostname")).toHaveText(hostname);
    await expect(row.getByTestId("request-code")).toHaveText(spacedCode(code));
    await expect(row.getByTestId("request-ip")).toHaveText(/^[0-9a-fA-F.:]+$/);
    await expect(row.getByTestId("request-expires")).toContainText("expires in");
    await expect(page.getByTestId("requests-pending-count")).toContainText("pending");
  });

  await test.step("the administrator approves it with a name, a region and paths", async () => {
    const row = page.getByTestId("request-row").filter({ hasText: hostname });
    await button(row, "request-approve").click();

    const modal = page.getByTestId("approve-modal");
    await expect(modal).toBeVisible();
    // The code in the modal is the one the box printed: it is what the
    // administrator compares before approving (§9.2).
    await expect(modal.getByTestId("approve-code")).toHaveText(spacedCode(code));
    await expect(modal.getByTestId("approve-code-warning")).toBeVisible();
    await expect(modal).toContainText(hostname);

    await textField(modal, "approve-name").fill(name);
    await textField(modal, "approve-region").fill(region);
    // A box in a hostile region probes the proxy path only, so the real
    // server's address is never handed to it (§9.2).
    await checkbox(modal, "approve-path-direct").uncheck();
    await expect(checkbox(modal, "approve-path-proxy")).toBeChecked();
    await expect(modal.getByTestId("approve-id")).toHaveText(derivedId);

    await button(page, "approve-submit").click();
    await expect(modal).toBeHidden();
    await expect(page.getByTestId("request-row").filter({ hasText: hostname })).toHaveCount(0);
  });

  const monClientID = await test.step(
    "the box collects its token, and only the first poll gets it",
    async () => {
      const first = await pollRegistration(request, submitted.requestId);
      expect(first.status).toBe(200);
      expect(first.body.status).toBe("approved");
      // The id is the slug of the name the administrator typed. A registry
      // that already holds that slug gets a -2 suffix (§6), which a fresh
      // database never has, but the assertion says the rule rather than the
      // one value.
      expect(first.body.monClientId).toMatch(new RegExp(`^${derivedId}(-\\d+)?$`));
      expect(first.body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const second = await pollRegistration(request, submitted.requestId);
      expect(second.status).toBe(200);
      expect(second.body.status).toBe("approved");
      expect(second.body.monClientId).toBe(first.body.monClientId);
      // The plaintext exists once: a second poll is still approved, but the
      // token is gone (mon-protocol.md §2.2).
      expect(second.body.token).toBeUndefined();
      return first.body.monClientId as string;
    },
  );

  await test.step("the mon-client is in the registry with what was chosen", async () => {
    await page.getByTestId("nav-clients").click();
    await page.waitForURL("**/admin/clients");

    const row = page.getByTestId("client-row").filter({ hasText: monClientID });
    await expect(row).toHaveCount(1);
    await expect(row.getByTestId("client-name")).toHaveText(name);
    await expect(row.getByTestId("client-id")).toContainText(monClientID);
    await expect(row.getByTestId("client-id")).toContainText(region);
    await expect(row.getByTestId("client-paths")).toContainText("proxy");
    await expect(row.getByTestId("client-paths")).not.toContainText("direct");
    // Approved, never heard from: the box has not sent a heartbeat yet (§9.3).
    await expect(row.getByTestId("client-state")).toHaveText("never seen");
    await expect(row.getByTestId("client-version")).toContainText(version);
  });
});
