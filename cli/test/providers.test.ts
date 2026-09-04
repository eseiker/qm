import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HOSTING_PROVIDERS,
  hostingProvider,
  hostingProviderUpFlags,
  type DeployContext,
} from "../src/backends/registry.ts";
import type { QmConfig } from "../src/config.ts";
import { HOSTING_PROVIDER_IDS, hostingProviderChoices, isTarget } from "../src/providers.ts";

const CONFIG_IDENTITY = { dev: -1n, ino: -1n };

test("the hosting provider registry owns target discovery and lifecycle capabilities", () => {
  assert.deepEqual(Object.keys(HOSTING_PROVIDERS), [...HOSTING_PROVIDER_IDS]);
  assert.equal(hostingProviderChoices(), "docker, fly, or aws");
  assert.equal(isTarget("fly"), true);
  assert.equal(isTarget("kubernetes"), false);
  for (const id of HOSTING_PROVIDER_IDS) {
    const provider = hostingProvider(id);
    assert.equal(provider.id, id);
    assert.equal(typeof provider.scaffold.renderConfig, "function");
    assert.equal(typeof provider.validateConfig, "function");
  }
  assert.deepEqual(hostingProvider("docker").upFlags, ["build-from", "only"]);
  assert.ok(hostingProvider("fly").upFlags.includes("image-from"));
  assert.ok(hostingProvider("aws").upFlags.includes("yes"));
  assert.deepEqual(hostingProviderUpFlags(), [
    "build-from",
    "only",
    "image-label",
    "image-from",
    "image-repo-prefix",
    "build-only",
    "yes",
  ]);
});

test("an explicitly empty --build-from value is rejected for every target", () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.com",
    target: "docker",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const base: DeployContext = {
    config,
    configPath: "/deployment/qm.config.jsonc",
    configIdentity: CONFIG_IDENTITY,
    configDir: "/deployment",
    sandboxDir: "/deployment/sandbox",
    target: "docker",
  };
  for (const target of HOSTING_PROVIDER_IDS) {
    const ctx = { ...base, target, config: { ...config, target } };
    for (const value of ["", "   "]) {
      assert.throws(
        () => hostingProvider(target).upOptions(ctx, { "build-from": value }, false),
        /--build-from needs a non-empty path/,
      );
    }
    assert.deepEqual(hostingProvider(target).upOptions(ctx, { "build-from": true }, true).buildFromPath, undefined);
  }
});

test("docker preflight defers implicit source resolution to the sanitized backend boundary", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-provider-preflight-"));
  const previous = process.cwd();
  try {
    process.chdir(dir);
    const config: QmConfig = {
      contract: 1,
      orgId: "acme",
      publicUrl: "http://localhost:8080",
      target: "docker",
      services: ["core"],
      plugins: [],
      skills: [],
      env: {},
      imageOverrides: {},
    };
    const ctx: DeployContext = {
      config,
      configPath: join(dir, "qm.config.jsonc"),
      configIdentity: CONFIG_IDENTITY,
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "docker",
    };
    const provider = hostingProvider("docker");
    const options = provider.upOptions(ctx, { "build-from": true }, false);
    assert.equal(await provider.preflightUp(ctx, options), ctx);
  } finally {
    process.chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("provider preflight rejects missing, blank, and non-file explicit deployment environments", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-provider-env-"));
  try {
    const config: QmConfig = {
      contract: 1,
      orgId: "acme",
      publicUrl: "http://localhost:8080",
      target: "docker",
      services: ["core"],
      plugins: [],
      skills: [],
      env: {},
      imageOverrides: {},
    };
    const configPath = join(dir, "qm.config.jsonc");
    writeFileSync(configPath, "{}\n");
    const base: DeployContext = {
      config,
      configPath,
      configIdentity: CONFIG_IDENTITY,
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      target: "docker",
    };
    const provider = hostingProvider("docker");
    await assert.rejects(() => provider.preflightUp({ ...base, envFile: "" }, { dryRun: true }), /non-empty path/);
    await assert.rejects(
      () => provider.preflightUp({ ...base, envFile: join(dir, "missing.env") }, { dryRun: true }),
      /--env-file not found/,
    );
    const directory = join(dir, "directory.env");
    mkdirSync(directory);
    await assert.rejects(
      () => provider.preflightUp({ ...base, envFile: directory }, { dryRun: true }),
      /must be a regular file/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("docker read and teardown operations retain the deployment environment source", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-provider-env-source-"));
  try {
    const config: QmConfig = {
      contract: 1,
      orgId: "acme",
      publicUrl: "http://localhost:8080",
      target: "docker",
      services: ["core"],
      plugins: [],
      skills: [],
      env: {},
      imageOverrides: {},
    };
    const missing = join(dir, "missing.env");
    const backend = hostingProvider("docker").createBackend({
      config,
      configPath: join(dir, "qm.config.jsonc"),
      configIdentity: CONFIG_IDENTITY,
      configDir: dir,
      sandboxDir: join(dir, "sandbox"),
      envFile: missing,
      target: "docker",
    });
    assert.throws(() => backend.status(), /--env-file not found/);
    await assert.rejects(async () => await backend.logs("core", {}), /--env-file not found/);
    await assert.rejects(async () => await backend.down({}), /--env-file not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("computed-secret delivery collisions fail before any provider call", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-provider-secret-collision-"));
  const marker = join(dir, "provider-called");
  const fly = join(dir, "fly.cjs");
  const previous = process.env.FLY_BIN;
  t.after(() => {
    if (previous === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = previous;
    rmSync(dir, { recursive: true, force: true });
  });
  writeFileSync(fly, `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, "called")\n`);
  chmodSync(fly, 0o755);
  process.env.FLY_BIN = fly;
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.com",
    target: "fly",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    secretEnv: { core: { CORE_SIGNING_SECRET: "OTHER_STORE" } },
    imageOverrides: {},
    appPrefix: "acme",
    region: "iad",
    flyOrg: "personal",
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
  const backend = hostingProvider("fly").createBackend({
    config,
    configPath: join(dir, "qm.config.jsonc"),
    configIdentity: CONFIG_IDENTITY,
    configDir: dir,
    sandboxDir: join(dir, "sandbox"),
    target: "fly",
  });
  await assert.rejects(
    async () => await backend.secretsPush(new Map()),
    /would receive env CORE_SIGNING_SECRET from both/,
  );
  assert.equal(existsSync(marker), false);
});

test("provider output coordinates stay behind the registry", () => {
  const common = {
    contract: 1 as const,
    orgId: "acme",
    publicUrl: "https://qm.example.com",
    services: ["core" as const],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  assert.deepEqual(hostingProvider("docker").coordinates({ ...common, target: "docker" }), {});
  assert.deepEqual(
    hostingProvider("fly").coordinates({
      ...common,
      target: "fly",
      flyOrg: "acme-org",
      region: "iad",
    }),
    { accountOrOrganization: "acme-org", region: "iad" },
  );
  assert.deepEqual(
    hostingProvider("aws").coordinates({
      ...common,
      target: "aws",
      aws: {
        accountId: "123456789012",
        region: "us-east-1",
        cluster: "acme",
        deployRoleArn: "arn:aws:iam::123456789012:role/deploy",
        secretsPrefix: "acme/",
        imageLabel: "v1",
        networking: { cloudMapNamespace: "acme.internal" },
        services: {},
      },
    }),
    { accountOrOrganization: "123456789012", region: "us-east-1" },
  );
});
