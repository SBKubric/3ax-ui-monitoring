// The /v1 protocol with a real client token (mon-protocol.md §3, §4.2, §5.2,
// §5.3). The token comes from a registration walk of this spec's own, so the
// file does not depend on any other.

import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  adminGet,
  bearer,
  newAdminContext,
  newContext,
  provisionMonClient,
  type MonClient,
} from "../support/mon";

let api: APIRequestContext;
let client: MonClient;

test.beforeAll(async () => {
  api = await newContext();
  client = await provisionMonClient({
    name: "Protocol Stockholm",
    region: "SE",
    paths: ["proxy", "direct"],
    hostname: "vps-protocol-1",
  });
});

test.afterAll(async () => {
  await api.dispose();
});

test("GET /v1/config without a token is 401", async () => {
  const res = await api.get("/v1/config");
  expect(res.status()).toBe(401);
  expect(await res.json()).toMatchObject({ error: "token_revoked" });
});

test("GET /v1/config with an unknown token is 401", async () => {
  const res = await api.get("/v1/config", { headers: bearer("not-a-token") });
  expect(res.status()).toBe(401);
  expect(await res.json()).toMatchObject({ error: "token_revoked" });
});

test("GET /v1/config answers 503 config_unavailable until a panel has been polled", async () => {
  // mon-server assembles a configuration document out of the panel's
  // /probe/configs, so before its first successful panel poll there is
  // nothing to serve. It says so with 503 config_unavailable and a
  // Retry-After rather than inventing an empty document, whose revision the
  // mon-client would apply and report (internal/api/config.go).
  const res = await api.get("/v1/config", { headers: bearer(client.token) });
  expect(res.status()).toBe(503);
  expect(res.headers()["retry-after"]).toBe("10");
  expect(await res.json()).toMatchObject({ error: "config_unavailable" });
});

test("GET /v1/probe echoes the nonce and reports the egress address", async () => {
  const nonce = "e2e-nonce-4f2c8a";
  const before = Date.now();
  const res = await api.get(`/v1/probe?target=xray:12:proxy&n=${nonce}`, {
    headers: bearer(client.token),
  });
  expect(res.status()).toBe(200);

  const body = await res.json();
  expect(body.nonce).toBe(nonce);
  // The tunnel probe arrives through the tunnel, so the address mon-server
  // sees is the egress it reports back (mon-protocol.md §5.2).
  expect(body.egressIp).toMatch(/^[0-9a-fA-F.:]+$/);
  expect(body.serverTs).toBeGreaterThanOrEqual(before - 60_000);

  const anonymous = await api.get(`/v1/probe?target=xray:12:proxy&n=${nonce}`);
  expect(anonymous.status()).toBe(401);
});

test("POST /v1/heartbeat is accepted and acknowledges the cycle", async () => {
  const seq = 1441;
  const before = Date.now();
  const res = await api.post("/v1/heartbeat", {
    headers: bearer(client.token),
    data: {
      monClientId: client.id,
      configRevision: "",
      client: { version: "0.1.0", xrayVersion: "26.3.27", uptimeMs: 86_400_000, configError: null },
      cycles: [
        {
          seq,
          ts: before,
          unverified: false,
          results: [
            {
              inboundKind: "xray",
              inboundId: 12,
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
          ],
        },
      ],
    },
  });
  expect(res.status()).toBe(200);

  const ack = await res.json();
  // The revision mon-server has built for this box: it is still empty here,
  // because no configuration exists before the first panel poll.
  expect(ack).toHaveProperty("configRevision");
  expect(typeof ack.configRevision).toBe("string");
  expect(ack.serverTs).toBeGreaterThanOrEqual(before - 60_000);
  expect(ack.ackSeq).toBe(seq);

  // The heartbeat really landed: the registry has heard from the box.
  const admin = await newAdminContext();
  try {
    const env = await adminGet(admin, "/admin/api/clients");
    const row = env.obj.clients.find((c: any) => c.id === client.id);
    expect(row, `${client.id} is in the registry`).toBeTruthy();
    expect(row.state).toBe("ONLINE");
    expect(row.lastHeartbeat).toBeGreaterThan(0);
    expect(row.xrayVersion).toBe("26.3.27");
  } finally {
    await admin.dispose();
  }
});

test("a revoked token is 401 everywhere", async () => {
  const admin = await newAdminContext();
  try {
    const res = await admin.post(`/admin/api/clients/${client.id}/revoke`);
    const env = await res.json();
    expect(env.success, env.msg).toBe(true);
  } finally {
    await admin.dispose();
  }

  const config = await api.get("/v1/config", { headers: bearer(client.token) });
  expect(config.status()).toBe(401);
  expect(await config.json()).toMatchObject({ error: "token_revoked" });

  const heartbeat = await api.post("/v1/heartbeat", {
    headers: bearer(client.token),
    data: { monClientId: client.id, cycles: [] },
  });
  expect(heartbeat.status()).toBe(401);

  const probe = await api.get("/v1/probe?target=xray:12:proxy&n=after-revoke", {
    headers: bearer(client.token),
  });
  expect(probe.status()).toBe(401);
});
