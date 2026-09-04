import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

const core = createServer((req: IncomingMessage, res) => {
  if (req.method === "GET" && req.url === "/v1/admin/whoami") {
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(JSON.stringify({ isAdmin: true }));
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
    return Promise.resolve(new Response("unavailable", { status: 503 }));
  }
  return originalFetch(input, init);
}) as typeof fetch;

process.env.CORE_API_URL = `http://localhost:${(core.address() as AddressInfo).port}`;
process.env.CORE_ORG_ID = "acme";
process.env.CORE_SIGNING_SECRET = "admin-update-outage-test-secret";
process.env.NODE_ENV = "test";
process.env.ALLOW_UNSIGNED_TEST_IDENTITY = "1";
process.env.QM_VERSION = "0.1.9";

const { server } = await import("../src/index.ts");
await new Promise<void>((resolve) => server.listen(0, resolve));
const base = `http://localhost:${(server.address() as AddressInfo).port}`;

test.after(() => {
  server.close();
  core.close();
  globalThis.fetch = originalFetch;
});

test("a registry outage is truthful, graceful, and shared across requests", async () => {
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await originalFetch(`${base}/api/update`, { headers: { cookie: "admin=U-admin" } });
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), {
      error: "registry_unreachable",
      message: "QM release information is temporarily unavailable",
    });
  }
  assert.equal(registryCalls, 1);
});
