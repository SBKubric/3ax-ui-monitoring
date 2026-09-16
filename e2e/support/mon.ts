// Shared helpers for the mon-server end-to-end suite (docs/agents/testing.md).
//
// Two kinds of helper live here:
//
//   - the protocol side, which drives /v1 and /admin/api through Playwright's
//     request context the way a mon-client and the admin UI's own fetch calls
//     do, and
//   - the browser side, which turns a data-testid into the control inside it.
//
// Elements are addressed by role or by data-testid only, never by CSS
// structure (docs/agents/testing.md).

import {
  expect,
  request,
  type APIRequestContext,
  type Locator,
  type Page,
} from "@playwright/test";

/** The container published by e2e/docker-compose.yml, or a natively run mon-server. */
export const monPort = process.env.MON_PORT ?? "8443";
export const baseURL = `https://localhost:${monPort}`;

/** The administrator e2e/docker-compose.yml seeds; the defaults match e2e/Makefile. */
export const adminUser = process.env.MON_ADMIN_USER ?? "admin";
export const adminPassword = process.env.MON_ADMIN_PASSWORD ?? "e2e-password";

/** Target states of spec §7.2. None of them may ever reach the admin UI (§1, §9.3). */
export const targetStates = ["UNKNOWN", "UP", "DOWN", "FLAPPING", "PAUSED"] as const;

/** A fresh request context that trusts the self-signed certificate of the run. */
export function newContext(): Promise<APIRequestContext> {
  return request.newContext({ baseURL, ignoreHTTPSErrors: true });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** The Authorization header of mon-protocol.md §3. */
export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

// ---------------------------------------------------------------------------
// Registration (mon-protocol.md §2)
// ---------------------------------------------------------------------------

export interface RegistrationBody {
  pairingCode: string;
  hostname: string;
  version: string;
  publicIp?: string;
}

export interface Submitted {
  requestId: string;
  pollAfter: number;
  expiresAt: number;
}

export interface PollBody {
  status: string;
  monClientId?: string;
  token?: string;
}

const codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789";

/** A pairing code in the shape mon-server accepts: six characters of [A-Z2-9]. */
export function pairingCode(): string {
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += codeAlphabet[Math.floor(Math.random() * codeAlphabet.length)];
  }
  return code;
}

/** The pairing code as the Requests page prints it: three characters, a space, three. */
export function spacedCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/**
 * Files one registration request.
 *
 * Registration is rate limited to one request per minute and IP (spec §6), and
 * every spec of this suite comes from the same address, so a suite that files
 * more than one registration WILL be refused. Rather than pretend otherwise,
 * this helper waits out the Retry-After mon-server itself sends and tries
 * again: the wait is the server's own answer, not a guess about timing.
 */
export async function submitRegistration(
  api: APIRequestContext,
  body: RegistrationBody,
): Promise<Submitted> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const res = await api.post("/v1/register", { data: body });
    if (res.status() === 202) {
      return (await res.json()) as Submitted;
    }
    if (res.status() !== 429) {
      throw new Error(`POST /v1/register answered ${res.status()}: ${await res.text()}`);
    }
    const header = Number(res.headers()["retry-after"]);
    const seconds = Number.isFinite(header) && header > 0 ? header : 60;
    await sleep(seconds * 1000 + 1000);
  }
  throw new Error("POST /v1/register stayed rate limited over three attempts");
}

/** One GET /v1/register/{requestId}. The caller asserts on the body. */
export async function pollRegistration(
  api: APIRequestContext,
  requestId: string,
): Promise<{ status: number; body: PollBody }> {
  const res = await api.get(`/v1/register/${encodeURIComponent(requestId)}`);
  const body = res.status() === 200 ? ((await res.json()) as PollBody) : ({} as PollBody);
  return { status: res.status(), body };
}

// ---------------------------------------------------------------------------
// The admin JSON API (spec §9.1: the {success,msg,obj} envelope)
// ---------------------------------------------------------------------------

export interface Envelope<T = any> {
  success: boolean;
  msg: string;
  obj: T;
}

/** Signs a request context in as the administrator; the cookie rides its jar. */
export async function adminLogin(api: APIRequestContext): Promise<void> {
  const res = await api.post("/admin/api/login", {
    data: { username: adminUser, password: adminPassword },
  });
  expect(res.status(), "POST /admin/api/login").toBe(200);
  const env = (await res.json()) as Envelope;
  expect(env.success, env.msg).toBe(true);
}

/** A request context already signed in as the administrator. */
export async function newAdminContext(): Promise<APIRequestContext> {
  const api = await newContext();
  await adminLogin(api);
  return api;
}

/** Reads one admin API endpoint and unwraps the envelope. */
export async function adminGet<T = any>(
  api: APIRequestContext,
  path: string,
): Promise<Envelope<T>> {
  const res = await api.get(path);
  expect(res.status(), `GET ${path}`).toBe(200);
  return (await res.json()) as Envelope<T>;
}

// ---------------------------------------------------------------------------
// A registered mon-client, for the specs that need one to talk protocol with
// ---------------------------------------------------------------------------

export interface MonClient {
  id: string;
  name: string;
  region: string;
  paths: string[];
  hostname: string;
  pairingCode: string;
  requestId: string;
  token: string;
}

export interface ProvisionOptions {
  name: string;
  region: string;
  paths: string[];
  hostname: string;
  version?: string;
}

/**
 * Registers a box and approves it, so the spec has a real client token.
 *
 * The approval goes through POST /admin/api/requests/{id}/approve rather than
 * the modal: this is setup for specs that test something else, and the modal
 * itself is walked in registration.spec.ts.
 */
export async function provisionMonClient(opts: ProvisionOptions): Promise<MonClient> {
  const anon = await newContext();
  const admin = await newAdminContext();
  try {
    const code = pairingCode();
    const submitted = await submitRegistration(anon, {
      pairingCode: code,
      hostname: opts.hostname,
      version: opts.version ?? "0.1.0",
      publicIp: "203.0.113.5",
    });
    const res = await admin.post(
      `/admin/api/requests/${encodeURIComponent(submitted.requestId)}/approve`,
      { data: { mode: "new", name: opts.name, region: opts.region, paths: opts.paths } },
    );
    const env = (await res.json()) as Envelope<{ id: string }>;
    expect(env.success, env.msg).toBe(true);

    const polled = await pollRegistration(anon, submitted.requestId);
    expect(polled.status).toBe(200);
    expect(polled.body.status).toBe("approved");
    expect(polled.body.token, "the first poll hands out the client token").toBeTruthy();

    return {
      id: env.obj.id,
      name: opts.name,
      region: opts.region,
      paths: opts.paths,
      hostname: opts.hostname,
      pairingCode: code,
      requestId: submitted.requestId,
      token: polled.body.token as string,
    };
  } finally {
    await anon.dispose();
    await admin.dispose();
  }
}

// ---------------------------------------------------------------------------
// The browser side
// ---------------------------------------------------------------------------

type Scope = Page | Locator;

/** The button inside a data-testid wrapper. */
export function button(scope: Scope, testId: string): Locator {
  return scope.getByTestId(testId).getByRole("button");
}

/** The text input inside a data-testid wrapper. */
export function textField(scope: Scope, testId: string): Locator {
  return scope.getByTestId(testId).getByRole("textbox");
}

/** The numeric input of an Ant Design InputNumber, which is a spinbutton. */
export function numberField(scope: Scope, testId: string): Locator {
  return scope.getByTestId(testId).getByRole("spinbutton");
}

/**
 * The password input inside a data-testid wrapper.
 *
 * A password field exposes no ARIA role of its own, so there is no role to ask
 * for; the control is addressed by its type inside the test id that names it.
 */
export function secretField(scope: Scope, testId: string): Locator {
  return scope.getByTestId(testId).locator("input[type=password]");
}

/** The checkbox inside a data-testid wrapper. */
export function checkbox(scope: Scope, testId: string): Locator {
  return scope.getByTestId(testId).getByRole("checkbox");
}

/** Signs in through the login card and lands on the Requests page. */
export async function uiLogin(page: Page): Promise<void> {
  await page.goto("/admin/login");
  await textField(page, "login-username").fill(adminUser);
  await secretField(page, "login-password").fill(adminPassword);
  await button(page, "login-submit").click();
  await page.waitForURL("**/admin/requests");
  await expect(page.getByTestId("nav-requests")).toBeVisible();
}

/** Everything the page shows a human, as one string. */
export function visibleText(page: Page): Promise<string> {
  return page.evaluate(() => document.body.innerText);
}
