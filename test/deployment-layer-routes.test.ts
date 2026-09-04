import "./support/auto-fake-sprites.ts";

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createServer } from "../src/api/server.ts";
import { signRequest } from "../src/auth/source-auth.ts";
import { buildApp } from "../src/wiring.ts";
import { agentApiMatches } from "../src/api/agent-api-catalog.ts";
import { mintCapabilityToken, CAPABILITY_TTL_MS } from "../src/auth/capability-token.ts";
import { scopeId } from "../src/types.ts";
import { testConfig } from "./support/test-config.ts";
import {
  DeploymentLayerPersistedError,
  type DeploymentLayerPrecondition,
} from "../src/deployment/deployment-layer-store.ts";

const SECRET = "layer-routes-secret".repeat(3);
const PATH = "/v1/deployment-layer";

function start(overrides: { deploymentLayerDir?: string } = {}, serverDeps: Record<string, unknown> = {}) {
  const built = buildApp(testConfig({ signingSecret: SECRET, ...overrides }));
  const server = createServer(built.app, {
    signingSecret: SECRET,
    deploymentLayer: built.deploymentLayerStore,
    auditLog: built.auditLog,
    ...serverDeps,
  });
  server.listen(0);
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  return {
    base,
    close: () => new Promise<void>((r) => server.close(() => r())),
    skills: built.skills,
    auditLog: built.auditLog,
    deploymentLayerStore: built.deploymentLayerStore,
  };
}

function signed(method: string, body: string, ts = Math.floor(Date.now() / 1000), path = PATH): Record<string, string> {
  return {
    "content-type": "application/json",
    "x-timestamp": String(ts),
    "x-signature": signRequest(SECRET, ts, `${method}\n${path}\n${body}`),
  };
}

const operationId = (digit: string): string => digit.repeat(32);

function mutationPath(precondition: DeploymentLayerPrecondition, nextOperationId: string): string {
  const query = new URLSearchParams();
  query.set("generation", String(precondition.generation));
  query.set("source", precondition.source);
  if (precondition.contentHash !== null) query.set("contentHash", precondition.contentHash);
  if (precondition.operationId !== null) query.set("currentOperationId", precondition.operationId);
  query.set("operationId", nextOperationId);
  return `${PATH}?${query}`;
}

function mutate(
  base: string,
  method: "PUT" | "DELETE",
  body: string,
  precondition: DeploymentLayerPrecondition,
  nextOperationId: string,
  timestamp = Math.floor(Date.now() / 1000),
): Promise<Response> {
  const path = mutationPath(precondition, nextOperationId);
  return fetch(`${base}${path}`, {
    method,
    headers: signed(method, body, timestamp, path),
    ...(method === "PUT" ? { body } : {}),
  });
}

const absentPrecondition = (source: "none" | "filesystem" = "none"): DeploymentLayerPrecondition => ({
  generation: 0,
  contentHash: null,
  source,
  operationId: null,
});

const bundle = JSON.stringify({
  contract: 1,
  tools: [{ path: "tools/acme/tool.json", content: JSON.stringify({ id: "acme", advertise: "acme CLI" }) }],
  skills: [{ path: "skills/acme/SKILL.md", content: "---\nname: acme\ndescription: Use acme.\n---\nRun acme.\n" }],
});

test("an empty layer GETs the version-0 shape with a source discriminator under source auth", async () => {
  const srv = start();
  try {
    const res = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      contract: 1,
      version: 0,
      generation: 0,
      contentHash: null,
      source: "none",
      operationId: null,
    });
  } finally {
    await srv.close();
  }
});

test("a baked filesystem layer with no durable record GETs source=filesystem", async () => {
  const dir = mkdtempSync(join(tmpdir(), "layer-routes-fs-"));
  mkdirSync(join(dir, "tools", "acme"), { recursive: true });
  writeFileSync(join(dir, "tools", "acme", "tool.json"), JSON.stringify({ id: "acme", advertise: "acme CLI (baked)" }));
  const srv = start({ deploymentLayerDir: dir });
  try {
    const res = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      version: number;
      source: string;
    };
    assert.equal(body.version, 0);
    assert.equal(body.source, "filesystem");
  } finally {
    await srv.close();
  }
});

test("a signed PUT lands under portal-identity enforcement (deploy-time sync is a SYSTEM write)", async () => {
  const srv = start(
    {},
    { requireSignedPortalIdentity: true, capabilitySecret: `${SECRET}-cap`, portalIdentitySecret: `${SECRET}-portal` },
  );
  try {
    const unsigned = await fetch(`${srv.base}${PATH}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: bundle,
    });
    assert.equal(unsigned.status, 401);
    const put = await mutate(srv.base, "PUT", bundle, absentPrecondition(), operationId("1"));
    assert.equal(put.status, 200);
    const putBody = (await put.json()) as { ok: boolean; version: number };
    assert.equal(putBody.ok, true);
    assert.equal(putBody.version, 1);
  } finally {
    await srv.close();
  }
});

test("a correctly signed PUT replaces the layer and a signed GET reads it back", async () => {
  const srv = start();
  try {
    const put = await mutate(srv.base, "PUT", bundle, absentPrecondition(), operationId("1"));
    assert.equal(put.status, 200);
    const putBody = (await put.json()) as {
      ok: boolean;
      version: number;
      durable: boolean;
    };
    assert.equal(putBody.ok, true);
    assert.equal(putBody.version, 1);
    assert.equal(putBody.durable, false, "a memory-backed core reports the PUT as non-durable");

    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(get.status, 200);
    const getBody = (await get.json()) as {
      version: number;
      contentHash: string | null;
      status: string;
      runtimeContentHash: string | null;
      source: string;
    };
    assert.equal(getBody.version, 1);
    assert.equal(getBody.status, "applied");
    assert.equal(getBody.runtimeContentHash, getBody.contentHash);
    assert.equal(getBody.source, "durable");
    assert.ok(getBody.contentHash);
  } finally {
    await srv.close();
  }
});

test("a lost PUT response retries only with the same operation ID", async () => {
  const srv = start();
  const snapshot = absentPrecondition();
  const firstOperationId = operationId("1");
  const timestamp = Math.floor(Date.now() / 1000);
  try {
    const first = await mutate(srv.base, "PUT", bundle, snapshot, firstOperationId, timestamp);
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { version: number; changed: boolean };
    assert.equal(firstBody.version, 1);
    assert.equal(firstBody.changed, true);

    const retry = await mutate(srv.base, "PUT", bundle, snapshot, firstOperationId, timestamp + 1);
    assert.equal(retry.status, 200);
    const retryBody = (await retry.json()) as { version: number; operationId: string; changed: boolean };
    assert.equal(retryBody.version, 1);
    assert.equal(retryBody.operationId, firstOperationId);
    assert.equal(retryBody.changed, true);

    const foreignSameDesired = await mutate(srv.base, "PUT", bundle, snapshot, operationId("2"), timestamp + 2);
    assert.equal(foreignSameDesired.status, 409);
  } finally {
    await srv.close();
  }
});

test("a stale initial PUT and an ABA generation both return 409", async () => {
  const a = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const b = bundle;
  const c = JSON.stringify({
    contract: 1,
    tools: [{ path: "tools/third/tool.json", content: JSON.stringify({ id: "third" }) }],
    skills: [],
  });
  const srv = start();
  try {
    const aOperationId = operationId("1");
    const aPut = await mutate(srv.base, "PUT", a, absentPrecondition(), aOperationId);
    const aBody = (await aPut.json()) as { version: number; contentHash: string };
    const aPrecondition: DeploymentLayerPrecondition = {
      generation: aBody.version,
      contentHash: aBody.contentHash,
      source: "durable",
      operationId: aOperationId,
    };

    const cOperationId = operationId("2");
    const cPut = await mutate(srv.base, "PUT", c, aPrecondition, cOperationId);
    const cBody = (await cPut.json()) as { version: number; contentHash: string };
    const staleForward = await mutate(srv.base, "PUT", b, aPrecondition, operationId("3"));
    assert.equal(staleForward.status, 409);

    const cPrecondition: DeploymentLayerPrecondition = {
      generation: cBody.version,
      contentHash: cBody.contentHash,
      source: "durable",
      operationId: cOperationId,
    };
    const bOperationId = operationId("4");
    const bPut = await mutate(srv.base, "PUT", b, cPrecondition, bOperationId);
    const bBody = (await bPut.json()) as { version: number; contentHash: string };
    const bPrecondition: DeploymentLayerPrecondition = {
      generation: bBody.version,
      contentHash: bBody.contentHash,
      source: "durable",
      operationId: bOperationId,
    };
    const laterCOperationId = operationId("5");
    const laterC = await mutate(srv.base, "PUT", c, bPrecondition, laterCOperationId);
    const laterCBody = (await laterC.json()) as { version: number; contentHash: string };
    const laterB = await mutate(
      srv.base,
      "PUT",
      b,
      {
        generation: laterCBody.version,
        contentHash: laterCBody.contentHash,
        source: "durable",
        operationId: laterCOperationId,
      },
      operationId("6"),
    );
    assert.equal(laterB.status, 200);

    const staleRestore = await mutate(srv.base, "PUT", a, bPrecondition, operationId("7"));
    assert.equal(staleRestore.status, 409);
    const current = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    const currentBody = (await current.json()) as { version: number; contentHash: string };
    assert.equal(currentBody.version, 5);
    assert.equal(currentBody.contentHash, bBody.contentHash);
  } finally {
    await srv.close();
  }
});

test("a signed conditional clear restores exact none and filesystem version-0 states", async () => {
  for (const source of ["none", "filesystem"] as const) {
    const dir = mkdtempSync(join(tmpdir(), "layer-routes-clear-"));
    if (source === "filesystem") {
      mkdirSync(join(dir, "tools", "baked"), { recursive: true });
      writeFileSync(join(dir, "tools", "baked", "tool.json"), JSON.stringify({ id: "baked", advertise: "baked" }));
    }
    const srv = start(source === "filesystem" ? { deploymentLayerDir: dir } : {});
    try {
      const putOperationId = operationId("1");
      const put = await mutate(srv.base, "PUT", bundle, absentPrecondition(source), putOperationId);
      assert.equal(put.status, 200);
      const putBody = (await put.json()) as { contentHash: string; version: number };
      const contentHash = putBody.contentHash;
      const clearPrecondition: DeploymentLayerPrecondition = {
        generation: putBody.version,
        contentHash,
        source: "durable",
        operationId: putOperationId,
      };
      const clearOperationId = operationId("2");
      const timestamp = Math.floor(Date.now() / 1000);
      const clear = await mutate(srv.base, "DELETE", "", clearPrecondition, clearOperationId, timestamp);
      assert.equal(clear.status, 200, await clear.text());
      const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
      assert.deepEqual(await get.json(), {
        contract: 1,
        version: 0,
        generation: 2,
        contentHash: null,
        source,
        operationId: clearOperationId,
      });
      const repeated = await mutate(srv.base, "DELETE", "", clearPrecondition, clearOperationId, timestamp + 1);
      assert.equal(repeated.status, 200);
      const reactivated = await mutate(
        srv.base,
        "PUT",
        bundle,
        { generation: 2, contentHash: null, source, operationId: clearOperationId },
        operationId("3"),
      );
      assert.equal(reactivated.status, 200);
      assert.equal(((await reactivated.json()) as { version: number }).version, 3);
    } finally {
      await srv.close();
    }
  }
});

test("a lost clear response retries through repeated fallback failures and recovers", async (t) => {
  const srv = start();
  const putOperationId = operationId("1");
  const clearOperationId = operationId("2");
  try {
    const put = await mutate(srv.base, "PUT", bundle, absentPrecondition(), putOperationId);
    const putBody = (await put.json()) as { contentHash: string; version: number };
    const precondition: DeploymentLayerPrecondition = {
      generation: putBody.version,
      contentHash: putBody.contentHash,
      source: "durable",
      operationId: putOperationId,
    };
    const archive = srv.skills.archive.bind(srv.skills);
    let failures = 2;
    t.mock.method(srv.skills, "archive", async (id: string) => {
      if (failures > 0) {
        failures--;
        throw new Error("fallback archive failed");
      }
      return archive(id);
    });
    const timestamp = Math.floor(Date.now() / 1000);
    const first = await mutate(srv.base, "DELETE", "", precondition, clearOperationId, timestamp);
    assert.equal(first.status, 202);
    const retry = await mutate(srv.base, "DELETE", "", precondition, clearOperationId, timestamp + 1);
    assert.equal(retry.status, 202);
    const recovered = await mutate(srv.base, "DELETE", "", precondition, clearOperationId, timestamp + 2);
    assert.equal(recovered.status, 200);
    const recoveredBody = (await recovered.json()) as { version: number; operationId: string; changed: boolean };
    assert.equal(recoveredBody.version, 2);
    assert.equal(recoveredBody.operationId, clearOperationId);
    assert.equal(recoveredBody.changed, true);
  } finally {
    await srv.close();
  }
});

test("a conditional clear returns 409 after a third layer wins", async () => {
  const third = JSON.stringify({ contract: 1, tools: [], skills: [] });
  const srv = start();
  try {
    const firstOperationId = operationId("1");
    const first = await mutate(srv.base, "PUT", bundle, absentPrecondition(), firstOperationId);
    const firstBody = (await first.json()) as { contentHash: string; version: number };
    const firstHash = firstBody.contentHash;
    const firstPrecondition: DeploymentLayerPrecondition = {
      generation: firstBody.version,
      contentHash: firstHash,
      source: "durable",
      operationId: firstOperationId,
    };
    const advanced = await mutate(srv.base, "PUT", third, firstPrecondition, operationId("2"));
    assert.equal(advanced.status, 200);
    const advancedHash = ((await advanced.json()) as { contentHash: string }).contentHash;
    const clear = await mutate(srv.base, "DELETE", "", firstPrecondition, operationId("3"));
    assert.equal(clear.status, 409);
    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(((await get.json()) as { contentHash: string }).contentHash, advancedHash);
  } finally {
    await srv.close();
  }
});

test("GET distinguishes a poisoned stored revision from the prior durable revision still live", async (t) => {
  const first = JSON.stringify({
    contract: 1,
    tools: [{ path: "tools/acme/tool.json", content: JSON.stringify({ id: "acme", advertise: "acme v1" }) }],
    skills: [],
  });
  const poisoned = JSON.stringify({
    contract: 1,
    tools: [{ path: "tools/acme/tool.json", content: JSON.stringify({ id: "acme", advertise: "acme v2" }) }],
    skills: [
      { path: "skills/broken/SKILL.md", content: "---\nname: broken\ndescription: Broken.\n---\nRun broken.\n" },
    ],
  });
  const srv = start();
  t.mock.method(console, "error", () => undefined);
  try {
    const initialOperationId = operationId("1");
    const initialPut = await mutate(srv.base, "PUT", first, absentPrecondition(), initialOperationId);
    assert.equal(initialPut.status, 200);
    const initialBody = (await initialPut.json()) as { contentHash: string; version: number };
    const initialHash = initialBody.contentHash;

    t.mock.method(srv.skills, "create", async () => {
      throw new Error("poisoned skill store");
    });
    const failedPut = await mutate(
      srv.base,
      "PUT",
      poisoned,
      {
        generation: initialBody.version,
        contentHash: initialHash,
        source: "durable",
        operationId: initialOperationId,
      },
      operationId("2"),
    );
    assert.equal(failedPut.status, 202, "a persisted revision is reported as accepted but degraded");
    const failedBody = (await failedPut.json()) as { ok: boolean; status: string; message: string };
    assert.equal(failedBody.ok, true);
    assert.equal(failedBody.status, "degraded");
    assert.match(failedBody.message, /poisoned skill store/);
    const audits = await srv.auditLog.events();
    assert.equal(
      audits.filter((event) => event.action === "deployment_layer.updated").length,
      2,
      "both persisted revisions are audited",
    );

    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(get.status, 200);
    const body = (await get.json()) as {
      contentHash: string;
      status: string;
      runtimeContentHash: string | null;
      source: string;
    };
    assert.notEqual(body.contentHash, initialHash, "the desired stored revision remains observable");
    assert.equal(body.status, "degraded");
    assert.equal(body.runtimeContentHash, initialHash);
    assert.equal(body.source, "durable");
  } finally {
    await srv.close();
  }
});

test("a degraded forward PUT retries apply only under its original operation ID", async (t) => {
  const srv = start();
  const retryBundle = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [
      {
        path: "skills/operation-retry-9f3c/SKILL.md",
        content: "---\nname: operation-retry-9f3c\ndescription: Retry.\n---\nRun retry.\n",
      },
    ],
  });
  const putOperationId = operationId("1");
  const timestamp = Math.floor(Date.now() / 1000);
  try {
    const initialOperationId = operationId("0");
    const initial = await mutate(
      srv.base,
      "PUT",
      JSON.stringify({ contract: 1, tools: [], skills: [] }),
      absentPrecondition(),
      initialOperationId,
      timestamp,
    );
    const initialBody = (await initial.json()) as { version: number; contentHash: string };
    const snapshot: DeploymentLayerPrecondition = {
      generation: initialBody.version,
      contentHash: initialBody.contentHash,
      source: "durable",
      operationId: initialOperationId,
    };
    const create = srv.skills.create.bind(srv.skills);
    let fail = true;
    t.mock.method(srv.skills, "create", async (...args: Parameters<typeof srv.skills.create>) => {
      if (fail) {
        fail = false;
        throw new Error("first apply failed");
      }
      return create(...args);
    });
    t.mock.method(console, "error", () => undefined);
    const failed = await mutate(srv.base, "PUT", retryBundle, snapshot, putOperationId, timestamp);
    assert.equal(failed.status, 202);
    const failedBody = (await failed.json()) as { version: number; operationId: string };
    assert.equal(failedBody.version, 2);
    assert.equal(failedBody.operationId, putOperationId);

    const retried = await mutate(srv.base, "PUT", retryBundle, snapshot, putOperationId, timestamp + 1);
    assert.equal(retried.status, 200);
    assert.equal(((await retried.json()) as { version: number }).version, 2);

    const foreignRetry = await mutate(srv.base, "PUT", retryBundle, snapshot, operationId("2"), timestamp + 2);
    assert.equal(foreignRetry.status, 409);
  } finally {
    await srv.close();
  }
});

test("a signed conditional restore survives a foreign draft but rejects published and third-hash drift", async (t) => {
  const poisoned = JSON.stringify({
    contract: 1,
    tools: [],
    skills: [
      { path: "skills/broken/SKILL.md", content: "---\nname: broken\ndescription: Broken.\n---\nRun broken.\n" },
    ],
  });
  const third = JSON.stringify({
    contract: 1,
    tools: [{ path: "tools/third/tool.json", content: JSON.stringify({ id: "third", advertise: "third" }) }],
    skills: [],
  });
  const srv = start();
  const originalCreate = srv.skills.create.bind(srv.skills);
  let rejectBroken = true;
  t.mock.method(srv.skills, "create", async (...args: Parameters<typeof srv.skills.create>) => {
    if (rejectBroken && args[0].manifest.name === "broken") {
      rejectBroken = false;
      throw new Error("poisoned skill store");
    }
    return originalCreate(...args);
  });
  t.mock.method(console, "error", () => undefined);
  try {
    const firstOperationId = operationId("1");
    const first = await mutate(srv.base, "PUT", bundle, absentPrecondition(), firstOperationId);
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { contentHash: string; version: number };
    const firstHash = firstBody.contentHash;

    const failedOperationId = operationId("2");
    const failed = await mutate(
      srv.base,
      "PUT",
      poisoned,
      {
        generation: firstBody.version,
        contentHash: firstHash,
        source: "durable",
        operationId: firstOperationId,
      },
      failedOperationId,
    );
    assert.equal(failed.status, 202);
    const failedBody = (await failed.json()) as { contentHash: string; version: number };
    const attemptedHash = failedBody.contentHash;

    const foreign = await srv.skills.create({
      scopeId: scopeId("org", "default-org"),
      manifest: { name: "acme", description: "Foreign draft.", requiredCapabilities: [], body: "foreign" },
      createdBy: "user:alice",
    });
    const failedPrecondition: DeploymentLayerPrecondition = {
      generation: failedBody.version,
      contentHash: attemptedHash,
      source: "durable",
      operationId: failedOperationId,
    };
    const restoreOperationId = operationId("3");
    const restoreTimestamp = Math.floor(Date.now() / 1000);
    const restored = await mutate(srv.base, "PUT", bundle, failedPrecondition, restoreOperationId, restoreTimestamp);
    const restoredText = await restored.text();
    assert.equal(restored.status, 200, restoredText);
    const restoredBody = JSON.parse(restoredText) as { contentHash: string; version: number };
    assert.equal(restoredBody.contentHash, firstHash);
    assert.equal((await srv.skills.get(foreign.id))?.status, "draft");
    const retry = await mutate(srv.base, "PUT", bundle, failedPrecondition, restoreOperationId, restoreTimestamp + 1);
    assert.equal(retry.status, 200);
    assert.equal(((await retry.json()) as { version: number }).version, restoredBody.version);

    await srv.skills.review(foreign.id, "reviewer", []);
    await assert.rejects(() => srv.skills.publish(foreign.id), /already has a published skill/);
    await srv.skills.archive(foreign.id);

    const advanced = await mutate(
      srv.base,
      "PUT",
      third,
      {
        generation: restoredBody.version,
        contentHash: firstHash,
        source: "durable",
        operationId: restoreOperationId,
      },
      operationId("4"),
    );
    assert.equal(advanced.status, 200);
    const advancedHash = ((await advanced.json()) as { contentHash: string }).contentHash;
    const staleRestore = await mutate(
      srv.base,
      "PUT",
      bundle,
      failedPrecondition,
      restoreOperationId,
      restoreTimestamp + 2,
    );
    assert.equal(staleRestore.status, 409);
    const current = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(((await current.json()) as { contentHash: string }).contentHash, advancedHash);
  } finally {
    await srv.close();
  }
});

test("a bad signature and a stale timestamp are both rejected 401", async () => {
  const srv = start();
  try {
    const forged = await fetch(`${srv.base}${PATH}`, {
      method: "PUT",
      headers: { ...signed("PUT", bundle), "x-signature": "v0=deadbeef" },
      body: bundle,
    });
    assert.equal(forged.status, 401);

    const stale = await fetch(`${srv.base}${PATH}`, {
      method: "PUT",
      headers: signed("PUT", bundle, Math.floor(Date.now() / 1000) - 3600),
      body: bundle,
    });
    assert.equal(stale.status, 401);

    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.deepEqual(
      await get.json(),
      {
        contract: 1,
        version: 0,
        generation: 0,
        contentHash: null,
        source: "none",
        operationId: null,
      },
      "rejected PUTs never landed",
    );
  } finally {
    await srv.close();
  }
});

test("a malformed bundle is a 400, shaped, and never becomes the current layer", async () => {
  const srv = start();
  try {
    const notABundle = JSON.stringify({ contract: 2 });
    const shape = await fetch(`${srv.base}${PATH}`, {
      method: "PUT",
      headers: signed("PUT", notABundle),
      body: notABundle,
    });
    assert.equal(shape.status, 400);
    const shapeBody = (await shape.json()) as { error: string; message: string };
    assert.equal(shapeBody.error, "bad_request");
    assert.match(shapeBody.message, /contract: 1, tools\[\], and skills\[\] required/);

    const invalid = JSON.stringify({
      contract: 1,
      tools: [],
      skills: [
        { path: "skills/a/SKILL.md", content: "---\nname: same\ndescription: One.\n---\nbody\n" },
        { path: "skills/b/SKILL.md", content: "---\nname: same\ndescription: Two.\n---\nbody\n" },
      ],
    });
    const dup = await mutate(srv.base, "PUT", invalid, absentPrecondition(), operationId("1"));
    assert.equal(dup.status, 400);
    const dupBody = (await dup.json()) as { error: string; message: string };
    assert.equal(dupBody.error, "invalid_deployment_layer");
    assert.match(dupBody.message, /duplicate deployment skill name/);

    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(((await get.json()) as { version: number }).version, 0);
  } finally {
    await srv.close();
  }
});

test("cross-tool credential collisions and unpaired surrogates are 400s", async () => {
  const srv = start();
  try {
    const nested = JSON.stringify({
      contract: 1,
      tools: [
        {
          path: "tools/a/tool.json",
          content: JSON.stringify({
            id: "a",
            auth: { check: "c", reauth: "r", credentialPaths: [{ path: ".acme", kind: "directory" }] },
          }),
        },
        {
          path: "tools/b/tool.json",
          content: JSON.stringify({
            id: "b",
            auth: { check: "c", reauth: "r", credentialPaths: [{ path: ".acme/sub/key", kind: "file" }] },
          }),
        },
      ],
      skills: [],
    });
    const collision = await mutate(srv.base, "PUT", nested, absentPrecondition(), operationId("1"));
    assert.equal(collision.status, 400);
    assert.match(((await collision.json()) as { message: string }).message, /incompatible credential paths/);

    const surrogate = `{"contract":1,"tools":[],"skills":[{"path":"skills/acme/SKILL.md","content":"---\\nname: acme\\ndescription: x\\n---\\nbad\\ud800body"}]}`;
    const invalidUnicode = await mutate(srv.base, "PUT", surrogate, absentPrecondition(), operationId("2"));
    assert.equal(invalidUnicode.status, 400);
    assert.match(((await invalidUnicode.json()) as { message: string }).message, /unpaired Unicode surrogate/);

    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    assert.equal(((await get.json()) as { version: number }).version, 0);
  } finally {
    await srv.close();
  }
});

test("a skill collision racing after validation is accepted degraded and audited", async (t) => {
  const srv = start();
  try {
    const record = await srv.deploymentLayerStore.put({ contract: 1, tools: [], skills: [] }, "setup");
    t.mock.method(srv.deploymentLayerStore, "put", async () => {
      throw new DeploymentLayerPersistedError("deployment layer persisted but skills acme collide", record);
    });
    t.mock.method(srv.deploymentLayerStore, "isApplied", () => false);

    const put = await mutate(
      srv.base,
      "PUT",
      bundle,
      {
        generation: record.version,
        contentHash: record.contentHash,
        source: "durable",
        operationId: record.operationId ?? null,
      },
      operationId("1"),
    );
    const responseText = await put.text();
    assert.equal(put.status, 202, responseText);
    const body = JSON.parse(responseText) as { ok: boolean; status: string; contentHash: string; message: string };
    assert.equal(body.ok, true);
    assert.equal(body.status, "degraded");
    assert.match(body.message, /persisted but skills acme collide/);

    const events = await srv.auditLog.events();
    assert.ok(
      events.some((event) => event.action === "deployment_layer.updated" && event.resource === body.contentHash),
    );
    const get = await fetch(`${srv.base}${PATH}`, { headers: signed("GET", "") });
    const current = (await get.json()) as { contentHash: string; status: string };
    assert.equal(current.contentHash, body.contentHash);
    assert.equal(current.status, "degraded");
  } finally {
    await srv.close();
  }
});

test("a VALID capability token is rejected on the deployment-layer routes (source-auth only)", async () => {
  assert.equal(agentApiMatches("GET", PATH), false);
  assert.equal(agentApiMatches("PUT", PATH), false);

  const srv = start();
  try {
    const cap = await mintCapabilityToken(
      { actorId: "U1", scopeId: scopeId("personal", "U1"), exp: Date.now() + CAPABILITY_TTL_MS },
      SECRET,
    );
    const get = await fetch(`${srv.base}${PATH}`, { headers: { "x-agent-capability": cap } });
    assert.equal(get.status, 403);
    const put = await fetch(`${srv.base}${PATH}`, {
      method: "PUT",
      headers: { "content-type": "application/json", "x-agent-capability": cap },
      body: bundle,
    });
    assert.equal(put.status, 403);
  } finally {
    await srv.close();
  }
});
