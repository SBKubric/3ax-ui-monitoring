// The rule spec mon-server.md repeats three times (§1, §9, §9.3): the state of
// targets belongs to the panel's Monitoring page and appears NOWHERE in
// mon-server's admin UI.
//
// The spec first makes mon-server hear about two concrete targets — a tunnel
// probe and a heartbeat that names them — and then walks every page of the
// admin UI asserting that neither the targets nor any target state is on
// screen, and that the JSON behind the pages does not carry them either.

import { expect, test, type Page } from "@playwright/test";
import {
  adminGet,
  bearer,
  button,
  pairingCode,
  pollRegistration,
  submitRegistration,
  targetStates,
  uiLogin,
  visibleText,
} from "../support/mon";

const hostname = "vps-silent-1";
const name = "Silent Lisbon";
const region = "PT";

// The two targets mon-server is told about, and the words that would give
// them away. The inbound id and the diagnostic reason belong to no part of the
// admin UI's own vocabulary — and unlike the bare kind "awg", neither can turn
// up by chance inside a random pairing code — so either of them on a page
// means a target leaked into it.
const xrayInboundID = 4242;
const awgReason = "awg_no_handshake";
const targetWords = [String(xrayInboundID), awgReason];

async function assertNoTargetState(page: Page, where: string): Promise<void> {
  await expect(page.getByTestId(/target/i), `${where}: an element about a target`).toHaveCount(0);

  const text = await visibleText(page);
  for (const state of targetStates) {
    expect(new RegExp(`\\b${state}\\b`).test(text), `${where} shows the target state ${state}`).toBe(
      false,
    );
  }
}

async function assertNoTargets(page: Page, where: string): Promise<void> {
  const text = (await visibleText(page)).toLowerCase();
  for (const word of targetWords) {
    expect(text.includes(word.toLowerCase()), `${where} mentions the target ${word}`).toBe(false);
  }
}

test("the state of targets appears nowhere in the admin UI", async ({ page, request }) => {
  const code = pairingCode();
  const submitted = await submitRegistration(request, {
    pairingCode: code,
    hostname,
    version: "0.1.0",
    publicIp: "203.0.113.5",
  });

  await uiLogin(page);

  await test.step("the Requests page, with a box waiting", async () => {
    await page.goto("/admin/requests");
    const row = page.getByTestId("request-row").filter({ hasText: hostname });
    await expect(row).toHaveCount(1);

    await assertNoTargetState(page, "the Requests page");
    await assertNoTargets(page, "the Requests page");

    // The Approve modal is where a target column would be most tempting.
    await button(row, "request-approve").click();
    await expect(page.getByTestId("approve-modal")).toBeVisible();
    await assertNoTargetState(page, "the Approve modal");
    await assertNoTargets(page, "the Approve modal");
    await button(page, "approve-cancel").click();
    await expect(page.getByTestId("approve-modal")).toBeHidden();

    const env = await adminGet(page.request, "/admin/api/requests");
    expect(JSON.stringify(env), "GET /admin/api/requests carries nothing about targets").not.toMatch(
      /target/i,
    );
  });

  const monClientID = await test.step("the box is approved and reports two targets", async () => {
    // Approved through the API with the page's own session: the modal itself
    // is walked in registration.spec.ts, and this spec is about what the
    // pages do not show.
    const approved = await page.request.post(
      `/admin/api/requests/${encodeURIComponent(submitted.requestId)}/approve`,
      { data: { mode: "new", name, region, paths: ["proxy", "direct"] } },
    );
    const env = await approved.json();
    expect(env.success, env.msg).toBe(true);
    const id: string = env.obj.id;

    const polled = await pollRegistration(request, submitted.requestId);
    const token = polled.body.token as string;
    expect(token).toBeTruthy();

    const probe = await request.get(`/v1/probe?target=awg:0:direct&n=silent-nonce`, {
      headers: bearer(token),
    });
    expect(probe.status()).toBe(200);

    const heartbeat = await request.post("/v1/heartbeat", {
      headers: bearer(token),
      data: {
        monClientId: id,
        configRevision: "",
        client: { version: "0.1.0", xrayVersion: "26.3.27", uptimeMs: 1000, configError: null },
        cycles: [
          {
            seq: 7,
            ts: Date.now(),
            unverified: false,
            results: [
              {
                inboundKind: "xray",
                inboundId: xrayInboundID,
                path: "proxy",
                ok: true,
                connectMs: 3,
                tlsMs: 47,
                ttfbMs: 39,
                handshakeMs: null,
                egressIp: "203.0.113.10",
                reason: null,
                detail: null,
              },
              {
                inboundKind: "awg",
                inboundId: 0,
                path: "direct",
                ok: false,
                connectMs: null,
                tlsMs: null,
                ttfbMs: null,
                handshakeMs: null,
                egressIp: null,
                reason: awgReason,
                detail: "last_handshake_time=0 after 20000ms",
              },
            ],
          },
        ],
      },
    });
    expect(heartbeat.status()).toBe(200);
    return id;
  });

  await test.step("the mon-clients page, with that box in it", async () => {
    await page.goto("/admin/clients");
    const row = page.getByTestId("client-row").filter({ hasText: monClientID });
    await expect(row).toHaveCount(1);
    // The row does carry the state of the mon-client itself, which is a
    // different thing: ONLINE, OFFLINE or "never seen" (§7.3, §9.3).
    await expect(row.getByTestId("client-state")).toHaveText("ONLINE");

    await assertNoTargetState(page, "the mon-clients page");
    await assertNoTargets(page, "the mon-clients page");

    await button(row, "client-operations").click();
    await page.getByTestId(`client-edit-${monClientID}`).click();
    await expect(page.getByTestId("edit-modal")).toBeVisible();
    await assertNoTargetState(page, "the Edit modal");
    await assertNoTargets(page, "the Edit modal");
    await button(page, "edit-cancel").click();
    await expect(page.getByTestId("edit-modal")).toBeHidden();

    const env = await adminGet(page.request, "/admin/api/clients");
    expect(JSON.stringify(env), "GET /admin/api/clients carries nothing about targets").not.toMatch(
      /target/i,
    );
    for (const client of env.obj.clients) {
      expect(targetStates).not.toContain(client.state);
    }
  });

  await test.step("the Settings page, every tab of it", async () => {
    await page.goto("/admin/settings");
    await expect(page.getByTestId("settings-status")).toBeVisible();
    for (const tab of ["tab-real", "tab-telegram", "tab-thresholds", "tab-probe", "tab-tls"]) {
      await page.getByTestId(tab).click();
      await assertNoTargetState(page, `the Settings page, tab ${tab}`);
      await assertNoTargets(page, `the Settings page, tab ${tab}`);
    }

    const env = await adminGet(page.request, "/admin/api/settings");
    expect(JSON.stringify(env), "GET /admin/api/settings carries nothing about targets").not.toMatch(
      /target/i,
    );
  });

  await test.step("the login page", async () => {
    await page.getByTestId("nav-logout").click();
    await page.waitForURL("**/admin/login**");
    await expect(page.getByTestId("login-form")).toBeVisible();
    await assertNoTargetState(page, "the login page");
    await assertNoTargets(page, "the login page");
  });
});
