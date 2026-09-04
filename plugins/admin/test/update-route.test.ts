import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

const corePaths: string[] = [];
const core = createServer((req: IncomingMessage, res) => {
  corePaths.push(`${req.method} ${req.url}`);
  if (req.method === "GET" && req.url === "/v1/admin/whoami") {
    if (req.headers["x-admin-actor"] === "U-unreachable@acme") {
      res.writeHead(503, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ error: "unavailable" }));
    }
    const isAdmin = req.headers["x-admin-actor"] === "U-admin@acme";
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(JSON.stringify({ isAdmin }));
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});
await new Promise<void>((resolve) => core.listen(0, resolve));

const originalFetch = globalThis.fetch;
let registryCalls = 0;
globalThis.fetch = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
  if (String(input) === "https://registry.npmjs.org/@yc-software%2fqm/latest") {
    registryCalls++;
    return Promise.resolve(new Response(JSON.stringify({ version: "0.2.0" }), { status: 200 }));
  }
  return originalFetch(input, init);
}) as typeof fetch;

process.env.CORE_API_URL = `http://localhost:${(core.address() as AddressInfo).port}`;
process.env.CORE_ORG_ID = "acme";
process.env.CORE_SIGNING_SECRET = "admin-update-route-test-secret";
process.env.NODE_ENV = "test";
process.env.ALLOW_UNSIGNED_TEST_IDENTITY = "1";
process.env.QM_VERSION = "0.2.0";

const { server } = await import("../src/index.ts");
await new Promise<void>((resolve) => server.listen(0, resolve));
const base = `http://localhost:${(server.address() as AddressInfo).port}`;
const request = (path: string, init?: RequestInit) => originalFetch(`${base}${path}`, init);
const whoamiPaths = () => corePaths.filter((path) => path === "GET /v1/admin/whoami");

test.after(() => {
  server.close();
  core.close();
  globalThis.fetch = originalFetch;
});

test("the update notice requires live core authorization", async () => {
  const before = whoamiPaths().length;
  assert.equal((await request("/api/update")).status, 401);
  const member = await request("/api/update", { headers: { cookie: "admin=U-member" } });
  assert.equal(member.status, 403);
  assert.deepEqual(await member.json(), { error: "forbidden" });
  assert.equal(registryCalls, 0);
  assert.equal(whoamiPaths().length - before, 1);
});

test("the update notice fails closed before registry lookup when core is unavailable", async () => {
  const beforeRegistry = registryCalls;
  const response = await request("/api/update", { headers: { cookie: "admin=U-unreachable" } });
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), {
    error: "core_unreachable",
    message: "could not verify admin status",
  });
  assert.equal(registryCalls, beforeRegistry);
});

test("GET reports the promoted stable release even when the deployment is current", async () => {
  const before = whoamiPaths().length;
  const response = await request("/api/update", { headers: { cookie: "admin=U-admin" } });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    currentVersion: "0.2.0",
    latestVersion: "0.2.0",
    updateAvailable: false,
    updateCommand: "node node_modules/@yc-software/qm/dist/bin/qm.js update --yes --version 0.2.0",
    releaseUrl: "https://github.com/yc-software/qm/releases/tag/v0.2.0",
  });
  assert.equal(registryCalls, 1);
  assert.equal(whoamiPaths().length - before, 1);
  assert.ok(!corePaths.some((path) => path.includes("/updates")));
});

test("the update endpoint has no mutation method", async () => {
  const response = await request("/api/update", {
    method: "POST",
    headers: { cookie: "admin=U-admin", "content-type": "application/json" },
    body: JSON.stringify({ version: "0.2.0" }),
  });
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "not_found" });
  assert.equal(registryCalls, 1);
  assert.ok(!corePaths.some((path) => path.includes("/updates")));
});
