import { createHash, generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfigAt, type QmConfig } from "../src/config.ts";
import {
  flyPreflightUp as flyPreflightUpRaw,
  flySecretsPush,
  flyUp as flyUpRaw,
  mpgClusterId,
  mpgDirectUrl,
  verifyLocalFlyTokens,
  type FlyUpOpts,
} from "../src/backends/fly.ts";
import { computedSecrets } from "../src/secrets.ts";
import { hostingProvider, prepareUpSubstrate, type DeployContext } from "../src/backends/registry.ts";
import { readEnvFile } from "../src/util.ts";
import { runChecks } from "../src/commands/check.ts";
import { runnableServices } from "../src/services.ts";

const TEST_CONFIG_IDENTITY = { dev: -1n, ino: -1n };
type TestFlyUpOpts = Omit<FlyUpOpts, "configIdentity"> & { configIdentity?: FlyUpOpts["configIdentity"] };

const flyPreflightUp = (config: QmConfig, configDir: string, opts: TestFlyUpOpts = {}): void =>
  flyPreflightUpRaw(config, configDir, {
    ...opts,
    configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY,
  });

const flyUp = (config: QmConfig, configDir: string, opts: TestFlyUpOpts = {}): ReturnType<typeof flyUpRaw> =>
  flyUpRaw(config, configDir, {
    ...opts,
    configIdentity: opts.configIdentity ?? TEST_CONFIG_IDENTITY,
  });

type RetiredUpdateTokenState = "owned" | "missing-app" | "missing-required" | "missing-token" | "unowned";
type LegacyExternalBackend = "porter" | "smolmachines";

async function runRetiredUpdateTokenCleanup(
  services: QmConfig["services"],
  state: RetiredUpdateTokenState,
  only?: string[],
  legacyBackend?: LegacyExternalBackend,
): Promise<{ calls: string; error: unknown }> {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-retired-update-token-"));
  const fly = join(dir, "fly");
  const log = join(dir, "fly.log");
  const appPrefix = "acme";
  const marker = `QM_OWNER_${createHash("sha256")
    .update(`qm-v2:personal:acme:${appPrefix}`)
    .digest("hex")
    .slice(0, 16)
    .toUpperCase()}`;
  const apps = [`${appPrefix}-core`, ...(state === "missing-app" ? [] : [`${appPrefix}-admin`])];
  const sandboxToken = legacyBackend
    ? { porter: "PORTER_DEPLOY_API_TOKEN", smolmachines: "SMOLMACHINES_TOKEN" }[legacyBackend]
    : "SPRITES_TOKEN";
  const coreSecrets = [
    marker,
    "CAPABILITY_SECRET",
    "CONNECTOR_SECRET_KEY",
    "CORE_SIGNING_SECRET",
    "DATABASE_URL",
    "FLY_API_TOKEN",
    "PORTAL_IDENTITY_SECRET",
    "SKILL_SIGNING_SECRET",
    ...(state === "missing-required" ? [] : [sandboxToken]),
  ];
  const adminSecrets = [
    ...(state === "owned" || state === "missing-token" ? [marker] : []),
    ...coreSecrets.filter((name) => name !== marker),
    ...(state === "owned" || state === "unowned" ? ["QM_UPDATE_GITHUB_TOKEN"] : []),
  ];
  const secrets = {
    [`${appPrefix}-core`]: coreSecrets,
    ...(state === "missing-app" ? {} : { [`${appPrefix}-admin`]: adminSecrets }),
  };
  writeFileSync(
    fly,
    `#!/usr/bin/env node
const fs = require("node:fs");
const a = process.argv.slice(2);
const appIndex = a.indexOf("-a");
const app = appIndex === -1 ? "" : a[appIndex + 1];
const secrets = ${JSON.stringify(secrets)};
fs.appendFileSync(${JSON.stringify(log)}, a.join(" ") + "\\n");
if (a[0] === "apps" && a[1] === "create") console.log("already been taken");
else if (a[0] === "apps" && a[1] === "list") console.log(${JSON.stringify(JSON.stringify(apps.map((Name) => ({ Name }))))});
else if (a[0] === "secrets" && a[1] === "list") {
  const names = secrets[app];
  console.log(names ? JSON.stringify(names.map((Name) => ({ Name }))) : "app not found");
} else if (a[0] === "ips" && a[1] === "list") console.log("private");
else if (a[0] === "status") console.log(JSON.stringify({ Machines: [] }));
else console.log("ok");
`,
  );
  chmodSync(fly, 0o755);
  const prior = process.env.FLY_BIN;
  const priorLog = console.log;
  process.env.FLY_BIN = fly;
  console.log = (): void => {};
  let config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.fly.dev",
    target: "fly",
    appPrefix,
    region: "sjc",
    flyOrg: "personal",
    services,
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
  if (legacyBackend) {
    const configPath = join(dir, "qm.config.jsonc");
    writeFileSync(
      configPath,
      JSON.stringify({
        ...config,
        env: { core: { HARNESS: "mock", SANDBOX_BACKEND: legacyBackend } },
        sandbox: {
          app: "legacy-sandbox",
          image: `registry.fly.io/legacy-sandbox@sha256:${"a".repeat(64)}`,
          baseImage: `ghcr.io/yc-software/qm-sandbox-base@sha256:${"b".repeat(64)}`,
        },
      }),
    );
    config = loadConfigAt(configPath).config;
    assert.equal(config.sandbox, undefined);
    assert.equal(config.env.core?.SANDBOX_BACKEND, legacyBackend);
  }
  let error: unknown;
  try {
    await flyUp(config, dir, only ? { only } : {});
  } catch (caught) {
    error = caught;
  } finally {
    console.log = priorLog;
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
  }
  const calls = readFileSync(log, "utf8");
  rmSync(dir, { recursive: true, force: true });
  return { calls, error };
}

const flyProviderMutation = /^(?:apps create|storage create|secrets (?:set|unset)|mpg create|ips allocate|deploy) /m;

function flyProviderConfig(): QmConfig {
  return {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.fly.dev",
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {
      core: {
        HARNESS: "mock",
        SNAPSHOT_STORE: "s3",
        TRANSFER_STORE: "s3",
        S3_BUCKET: "acme-data",
        S3_REGION: "auto",
      },
    },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
}

function flyAuthAllowlistConfig(): QmConfig {
  const config = flyProviderConfig();
  config.services = ["core", "portal", "auth"];
  config.env = { ...config.env, auth: { AUTH_EMAIL_TRANSPORT: "resend" } };
  return config;
}

function flyAuthSecretPushConfig(): QmConfig {
  const config = flyAuthAllowlistConfig();
  config.services = ["core", "portal", "auth"];
  config.env = { core: { HARNESS: "mock" }, auth: { AUTH_EMAIL_TRANSPORT: "resend" } };
  return config;
}

function requiredFlySecretValues(config: QmConfig): Map<string, string> {
  const values = new Map(
    computedSecrets(config)
      .filter((secret) => secret.required && secret.managedBy === "operator")
      .map((secret, index) => [secret.name, `${secret.name.toLowerCase()}-${index}-`.repeat(4)]),
  );
  if (values.has("AUTH_SIGNING_JWK")) {
    values.set(
      "AUTH_SIGNING_JWK",
      JSON.stringify(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" })),
    );
  }
  if (values.has("AUTH_EMAIL_FROM")) values.set("AUTH_EMAIL_FROM", "Acme <sender@example.com>");
  if (values.has("AUTH_ALLOWED_EMAILS")) values.set("AUTH_ALLOWED_EMAILS", "user@example.com");
  if (values.has("ADMIN_GRANTS")) values.set("ADMIN_GRANTS", "admin@example.com:org_admin");
  if (values.has("PUBLIC_API_URL")) values.set("PUBLIC_API_URL", "https://api.example.com");
  return values;
}

function fakeFlyProvider(
  dir: string,
  config: QmConfig,
  options: {
    extraSecrets?: readonly string[];
    extraSecretsByApp?: Readonly<Record<string, readonly string[]>>;
    extraApps?: readonly string[];
    omitSecrets?: readonly string[];
    replaceEnvFile?: { path: string; content: string };
    statusImage?: string;
  } = {},
): { log: string; restore: () => void } {
  const fly = join(dir, "fly");
  const log = join(dir, "fly.log");
  const storage = join(dir, "storage-created");
  const staged = join(dir, "staged.json");
  const marker = `QM_OWNER_${createHash("sha256")
    .update("qm-v2:personal:acme:acme")
    .digest("hex")
    .slice(0, 16)
    .toUpperCase()}`;
  const omitted = new Set(options.omitSecrets ?? []);
  const secrets = [
    marker,
    "DATABASE_URL",
    ...(options.extraSecrets ?? []),
    ...new Set(
      computedSecrets(config).flatMap((secret) => [secret.name, ...(secret.aliases ?? []).map((alias) => alias.name)]),
    ),
  ].filter((name) => !omitted.has(name));
  const apps = [
    ...new Set([
      ...runnableServices(config.services).map((service) => `acme-${service}`),
      ...config.plugins.map((plugin) => `acme-${plugin.name}`),
      ...(options.extraApps ?? []),
    ]),
  ];
  writeFileSync(log, "");
  writeFileSync(
    fly,
    `#!/usr/bin/env node
const fs = require("node:fs");
const a = process.argv.slice(2);
const appIndex = a.indexOf("-a");
const app = appIndex === -1 ? "" : a[appIndex + 1];
const stagedPath = ${JSON.stringify(staged)};
const staged = fs.existsSync(stagedPath) ? JSON.parse(fs.readFileSync(stagedPath, "utf8")) : {};
const extraSecretsByApp = ${JSON.stringify(options.extraSecretsByApp ?? {})};
fs.appendFileSync(${JSON.stringify(log)}, a.join(" ") + "\\n");
if (a[0] === "apps" && a[1] === "list") console.log(${JSON.stringify(JSON.stringify(apps.map((Name) => ({ Name }))))});
else if (a[0] === "apps" && a[1] === "create") {
  ${options.replaceEnvFile ? `fs.writeFileSync(${JSON.stringify(options.replaceEnvFile.path)}, ${JSON.stringify(options.replaceEnvFile.content)});` : ""}
  console.log("already been taken");
}
else if (a[0] === "secrets" && a[1] === "list") {
  const provider = fs.existsSync(${JSON.stringify(storage)}) ? ["AWS_ACCESS_KEY_ID", "AWS_ENDPOINT_URL_S3", "AWS_SECRET_ACCESS_KEY"] : [];
  const names = [...new Set([${secrets.map((name) => JSON.stringify(name)).join(",")}, ...(extraSecretsByApp[app] || []), ...(staged[app] || []), ...provider])];
  console.log(JSON.stringify(names.map((Name) => ({ Name }))));
} else if (a[0] === "secrets" && a[1] === "set") {
  const assignment = a[a.length - 1];
  const name = assignment.slice(0, assignment.indexOf("="));
  const value = assignment.endsWith("=-") ? fs.readFileSync(0) : Buffer.from(assignment.slice(assignment.indexOf("=") + 1));
  fs.appendFileSync(${JSON.stringify(log)}, "input " + name + " " + value.toString("base64") + "\\n");
  staged[app] = [...new Set([...(staged[app] || []), name])];
  fs.writeFileSync(stagedPath, JSON.stringify(staged));
} else if (a[0] === "storage" && a[1] === "create") fs.writeFileSync(${JSON.stringify(storage)}, "1");
else if (a[0] === "status" && ${JSON.stringify(options.statusImage ?? "")}) console.log(JSON.stringify({ Machines: [{ id: "m1", config: { image: ${JSON.stringify(options.statusImage ?? "")} } }] }));
else if (a[0] === "ips" && a[1] === "list") console.log("private");
else if (a[0] === "logs") console.log("listening on :8080");
else console.log("ok");
`,
  );
  chmodSync(fly, 0o755);
  const prior = process.env.FLY_BIN;
  process.env.FLY_BIN = fly;
  return {
    log,
    restore: () => {
      if (prior === undefined) delete process.env.FLY_BIN;
      else process.env.FLY_BIN = prior;
    },
  };
}

async function runFlyProviderUp(config: QmConfig, configDir: string, envFile?: string): Promise<void> {
  const configPath = join(configDir, "qm.config.jsonc");
  writeFileSync(configPath, JSON.stringify(config));
  const configIdentity = loadConfigAt(configPath).configIdentity;
  const ctx: DeployContext = {
    config,
    configPath,
    configIdentity,
    configDir,
    sandboxDir: join(configDir, "sandbox"),
    ...(envFile ? { envFile } : {}),
    target: "fly",
  };
  const provider = hostingProvider("fly");
  const options = provider.upOptions(ctx, {}, false);
  const preflighted = await provider.preflightUp(ctx, options);
  const prepared = await prepareUpSubstrate(preflighted, options);
  await provider.createBackend(prepared).up(options);
}

function flySecretPushConfig(name = "ZZZ_PLUGIN_SECRET", required = true): QmConfig {
  return {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.fly.dev",
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [
      {
        name: "future",
        image: "ghcr.io/acme/future:1",
        secrets: [{ name, required }],
      },
    ],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
}

function flySecretPushEnvironment(extra?: string): string {
  return [
    `CAPABILITY_SECRET=${"capability".repeat(4)}`,
    `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
    `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
    `PORTAL_IDENTITY_SECRET=${"identity".repeat(4)}`,
    `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
    "SPRITES_TOKEN=SpriteV1-scoped",
    ...(extra ? [extra] : []),
  ].join("\n");
}

function createMinimalFlySource(root: string): void {
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, "deploy", "core"), { recursive: true });
  writeFileSync(join(root, "package.json"), "{}\n");
  writeFileSync(join(root, "src", "index.ts"), "export {};\n");
  writeFileSync(join(root, "deploy", "core", "Dockerfile"), "FROM scratch\n");
  writeFileSync(
    join(root, "deploy", "core", "fly.toml"),
    readFileSync(new URL("../../deploy/core/fly.toml", import.meta.url), "utf8"),
  );
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
  execFileSync("git", ["init", "--quiet", root], { env });
}

test("Fly preflight rejects deployment-layer subroots outside the selected root before every provider call", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-layer-boundary-"));
  const config = flyProviderConfig();
  const fake = fakeFlyProvider(dir, config);
  try {
    const sandbox = join(dir, "sandbox");
    const external = join(dir, "external");
    mkdirSync(join(external, "skill"), { recursive: true });
    writeFileSync(join(external, "skill", "SKILL.md"), "---\nname: external\ndescription: external\n---\nexternal\n");
    mkdirSync(sandbox);
    for (const name of ["skills", "tools"]) {
      symlinkSync(external, join(sandbox, name), "dir");
      assert.throws(
        () => runChecks(config, dir, sandbox, { report: false }),
        /deployment layer directory must be within its root/,
      );
      rmSync(join(sandbox, name));
    }
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly secrets push consumes the passed value map without reading the config directory environment", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-direct-push-values-"));
  const config = flySecretPushConfig();
  const fake = fakeFlyProvider(dir, config);
  const source = join(dir, "values.env");
  const value = "direct-map-plugin-secret";
  writeFileSync(source, flySecretPushEnvironment(`ZZZ_PLUGIN_SECRET=${value}`));
  writeFileSync(join(dir, ".env"), "CORE_SIGNING_SECRET=short\n");
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(source));
    assert.match(
      readFileSync(fake.log, "utf8"),
      new RegExp(`^input ZZZ_PLUGIN_SECRET ${Buffer.from(value).toString("base64")}$`, "m"),
    );
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly custom secret stores use an explicit snapshot and never ambient provider credentials", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-custom-secret-snapshot-"));
  const config = flySecretPushConfig("GITHUB_TOKEN", false);
  const fake = fakeFlyProvider(dir, config);
  const valuesPath = join(dir, "values.env");
  writeFileSync(valuesPath, flySecretPushEnvironment());
  const values = readEnvFile(valuesPath);
  const prior = process.env.GITHUB_TOKEN;
  const log = console.log;
  process.env.GITHUB_TOKEN = "ambient-provider-token-must-not-stage";
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, values);
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /^input GITHUB_TOKEN /m);
    const explicit = "explicit-custom-token";
    await flySecretsPush(config, dir, new Map([...values, ["GITHUB_TOKEN", explicit]]));
    assert.match(
      readFileSync(fake.log, "utf8"),
      new RegExp(`^input GITHUB_TOKEN ${Buffer.from(explicit).toString("base64")}$`, "m"),
    );
  } finally {
    console.log = log;
    if (prior === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly materializes the configured public API coordinate before up and secrets-push staging", async () => {
  const config = flyProviderConfig();
  config.apiUrl = "https://api.example.com";
  config.env = { core: { HARNESS: "pi" } };
  const canonical = "https://api.example.com";
  const supplied = "HTTPS://API.EXAMPLE.COM:443/";

  const pushDir = mkdtempSync(join(tmpdir(), "qm-fly-public-api-push-"));
  const pushFake = fakeFlyProvider(pushDir, config);
  const pushValues = requiredFlySecretValues(config);
  pushValues.set("PUBLIC_API_URL", supplied);
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, pushDir, pushValues);
    assert.match(
      readFileSync(pushFake.log, "utf8"),
      new RegExp(`^input PUBLIC_API_URL ${Buffer.from(canonical).toString("base64")}$`, "m"),
    );
  } finally {
    console.log = log;
    pushFake.restore();
    rmSync(pushDir, { recursive: true, force: true });
  }

  const upDir = mkdtempSync(join(tmpdir(), "qm-fly-public-api-up-"));
  const upFake = fakeFlyProvider(upDir, config, { omitSecrets: ["PUBLIC_API_URL"] });
  console.log = (): void => {};
  try {
    await runFlyProviderUp(config, upDir);
    const calls = readFileSync(upFake.log, "utf8");
    assert.match(calls, new RegExp(`^input PUBLIC_API_URL ${Buffer.from(canonical).toString("base64")}$`, "m"));
    assert.ok(calls.indexOf("secrets set --stage -a acme-core PUBLIC_API_URL=-") < calls.indexOf("deploy --yes"));
  } finally {
    console.log = log;
    upFake.restore();
    rmSync(upDir, { recursive: true, force: true });
  }
});

test("Fly replaces a stale public API coordinate without a local secret value", async () => {
  const config = flyProviderConfig();
  config.apiUrl = "https://new-api.example.com";
  config.env = { core: { HARNESS: "pi" } };
  const encoded = Buffer.from(config.apiUrl).toString("base64");

  for (const operation of ["up", "push"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `qm-fly-public-api-migrate-${operation}-`));
    const fake = fakeFlyProvider(dir, config, { extraSecrets: ["PUBLIC_API_URL"] });
    const values = requiredFlySecretValues(config);
    values.delete("PUBLIC_API_URL");
    const log = console.log;
    console.log = (): void => {};
    try {
      if (operation === "up") await flyUp(config, dir, { preflighted: true });
      else await flySecretsPush(config, dir, values);
      assert.match(readFileSync(fake.log, "utf8"), new RegExp(`^input PUBLIC_API_URL ${encoded}$`, "m"));
    } finally {
      console.log = log;
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("Fly rejects a mismatched public API coordinate before up or secrets-push provider access", async () => {
  for (const operation of ["up", "push"] as const) {
    const dir = mkdtempSync(join(tmpdir(), `qm-fly-public-api-${operation}-reject-`));
    const config = flyProviderConfig();
    config.apiUrl = "https://api.example.com";
    config.env = { core: { HARNESS: "pi" } };
    const fake = fakeFlyProvider(dir, config);
    const values = requiredFlySecretValues(config);
    values.set("PUBLIC_API_URL", "https://attacker.example");
    const envFile = join(dir, "deployment.env");
    writeFileSync(envFile, [...values].map(([name, value]) => `${name}=${value}`).join("\n"));
    try {
      await assert.rejects(
        operation === "push" ? flySecretsPush(config, dir, values) : flyUp(config, dir, { envFile, preflighted: true }),
        /PUBLIC_API_URL/,
      );
      assert.equal(readFileSync(fake.log, "utf8"), "");
    } finally {
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("Fly removes persisted provider destinations and first-party plugin secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-stale-secret-cleanup-"));
  const config = flySecretPushConfig();
  const valuesPath = join(dir, "values.env");
  writeFileSync(valuesPath, flySecretPushEnvironment("ZZZ_PLUGIN_SECRET=valid-plugin-secret"));
  const fake = fakeFlyProvider(dir, config, {
    extraSecretsByApp: {
      "acme-core": ["NODE_ENV", "SESSION_STORE", "RUN_STORE", "FLY_DEPLOY_APP_PREFIX"],
      "acme-future": ["AUTH_CLIENT_SECRET", "CORE_API_URL", "CORE_ORG_ID", "NODE_ENV", "PORT", "QM_DEPLOYMENT_ID"],
    },
  });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(valuesPath));
    const calls = readFileSync(fake.log, "utf8").split("\n");
    const coreUnset = calls.find((line) => line.startsWith("secrets unset --stage -a acme-core "));
    assert.ok(coreUnset);
    for (const name of ["FLY_DEPLOY_APP_PREFIX", "NODE_ENV", "RUN_STORE", "SESSION_STORE", "ZZZ_PLUGIN_SECRET"]) {
      assert.ok(coreUnset.includes(` ${name}`), name);
    }
    assert.doesNotMatch(coreUnset, / QM_OWNER_/);
    const pluginUnset = calls.find((line) => line.startsWith("secrets unset --stage -a acme-future "));
    assert.ok(pluginUnset);
    for (const name of ["AUTH_CLIENT_SECRET", "CORE_API_URL", "CORE_ORG_ID", "PORT", "QM_DEPLOYMENT_ID"]) {
      assert.ok(pluginUnset.includes(` ${name}`), name);
    }
    assert.doesNotMatch(pluginUnset, / CORE_SIGNING_SECRET(?: |$)/);
    assert.match(pluginUnset, / NODE_ENV(?: |$)/);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects provider-owned secret destinations before up or secrets-push mutation", async () => {
  const marker = `QM_OWNER_${createHash("sha256")
    .update("qm-v2:personal:acme:acme")
    .digest("hex")
    .slice(0, 16)
    .toUpperCase()}`;
  for (const destination of [
    marker,
    "AGENT_API_URL",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_DYNAMODB",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
    "DATABASE_URL",
    "FLY_API_TOKEN",
    "FLY_APP_NAME",
    "FLY_MACHINE_ID",
    "SLACK_API_URL",
  ]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-fly-secret-ownership-"));
    const config = flyProviderConfig();
    config.env = { core: { HARNESS: "mock" } };
    config.secretEnv = { core: { [destination]: "ATTACKER_STORE" } };
    const fake = fakeFlyProvider(dir, config);
    const expected = new RegExp(`cannot target provider-owned destination core\\.${destination}`);
    try {
      await assert.rejects(flyUp(config, dir, { preflighted: true }), expected);
      assert.equal(readFileSync(fake.log, "utf8"), "");
      await assert.rejects(flySecretsPush(config, dir, new Map()), expected);
      assert.equal(readFileSync(fake.log, "utf8"), "");
    } finally {
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("Fly rejects active provider credential stores but ignores disabled-service aliases", async () => {
  for (const source of ["FLY_API_TOKEN", "AWS_PROFILE", "AWS_ENDPOINT_URL_DYNAMODB"]) {
    const dir = mkdtempSync(join(tmpdir(), "qm-fly-provider-secret-source-"));
    const config = flyProviderConfig();
    config.env = { core: { HARNESS: "mock" } };
    config.secretEnv = { core: { CUSTOM_RUNTIME_SECRET: source } };
    const fake = fakeFlyProvider(dir, config);
    const expected = new RegExp(`secret store ${source} is reserved for provider credential acquisition`);
    try {
      await assert.rejects(flyUp(config, dir, { preflighted: true }), expected);
      assert.equal(readFileSync(fake.log, "utf8"), "");
      await assert.rejects(flySecretsPush(config, dir, new Map()), expected);
      assert.equal(readFileSync(fake.log, "utf8"), "");
    } finally {
      fake.restore();
      rmSync(dir, { recursive: true, force: true });
    }
  }

  const dir = mkdtempSync(join(tmpdir(), "qm-fly-disabled-secret-source-"));
  const config = flyProviderConfig();
  config.env = { core: { HARNESS: "mock" } };
  config.secretEnv = { slack: { IGNORED_SECRET: "FLY_API_TOKEN" } };
  const fake = fakeFlyProvider(dir, config);
  try {
    await flyUp(config, dir, { preflighted: true });
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /input FLY_API_TOKEN|input IGNORED_SECRET/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects workloads inside the per-deployment app namespace before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-workload-namespace-"));
  const config = flyProviderConfig();
  config.env = { core: { HARNESS: "mock" } };
  mkdirSync(join(dir, "plugins", "d-old"), { recursive: true });
  writeFileSync(join(dir, "plugins", "d-old", "Dockerfile"), "FROM scratch\n");
  const fake = fakeFlyProvider(dir, config, { extraApps: ["acme-d-old"] });
  try {
    await assert.rejects(
      flyUp(config, dir, { preflighted: true }),
      /Fly workload app acme-d-old overlaps the per-deployment app namespace acme-d-\*/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
    await assert.rejects(
      flySecretsPush(config, dir, new Map()),
      /Fly workload app acme-d-old overlaps the per-deployment app namespace acme-d-\*/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly reconciles a removed plugin app inside the deploy-app prefix", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-retired-prefix-plugin-"));
  const config = flyProviderConfig();
  config.env = { core: { HARNESS: "mock" } };
  const fake = fakeFlyProvider(dir, config, {
    extraApps: ["acme-d-old"],
    extraSecretsByApp: { "acme-d-old": ["OLD_PLUGIN_TOKEN"] },
  });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flyUp(config, dir);
    const calls = readFileSync(fake.log, "utf8");
    const unset = calls.split("\n").find((line) => line.startsWith("secrets unset --stage -a acme-d-old "));
    assert.ok(unset);
    assert.match(unset, / OLD_PLUGIN_TOKEN(?: |$)/);
    assert.doesNotMatch(unset, / QM_OWNER_/);
    assert.match(calls, /^scale count 0 -a acme-d-old --yes$/m);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly up preserves signing for a discovered source plugin while reconciling its secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-source-plugin-reconcile-"));
  const config = flyProviderConfig();
  config.env = { core: { HARNESS: "mock" } };
  mkdirSync(join(dir, "plugins", "srcplug"), { recursive: true });
  writeFileSync(join(dir, "plugins", "srcplug", "Dockerfile"), "FROM scratch\n");
  const fake = fakeFlyProvider(dir, config, { extraApps: ["acme-srcplug"] });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flyUp(config, dir);
    const calls = readFileSync(fake.log, "utf8");
    const pluginUnset = calls.split("\n").find((line) => line.startsWith("secrets unset --stage -a acme-srcplug "));
    assert.ok(pluginUnset);
    assert.doesNotMatch(pluginUnset, / CORE_SIGNING_SECRET(?: |$)/);
    assert.match(calls, /deploy --yes -c .*srcplug\.fly\.toml/);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly strips and stops an owned app removed from the deployment", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-retired-app-reconcile-"));
  const config = flyProviderConfig();
  config.env = { core: { HARNESS: "mock" } };
  const fake = fakeFlyProvider(dir, config, {
    extraApps: ["acme-retired"],
    extraSecretsByApp: { "acme-retired": ["STOLEN_PORTAL_KEY"] },
  });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flyUp(config, dir);
    const calls = readFileSync(fake.log, "utf8");
    const retiredUnset = calls.split("\n").find((line) => line.startsWith("secrets unset --stage -a acme-retired "));
    assert.ok(retiredUnset);
    assert.match(retiredUnset, / CORE_SIGNING_SECRET(?: |$)/);
    assert.match(retiredUnset, / STOLEN_PORTAL_KEY(?: |$)/);
    assert.match(calls, /^scale count 0 -a acme-retired --yes$/m);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly --only fails closed when an unselected owned app has stale secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-only-stale-secret-"));
  const config = flyProviderConfig();
  config.services = ["core", "admin"];
  config.env = { core: { HARNESS: "mock" } };
  const fake = fakeFlyProvider(dir, config, {
    extraSecretsByApp: { "acme-admin": ["STOLEN_ADMIN_KEY"] },
  });
  try {
    await assert.rejects(
      flyUp(config, dir, { only: ["core"] }),
      /--only cannot leave stale secrets active on unselected apps:[\s\S]*acme-admin:[^\n]*STOLEN_ADMIN_KEY/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), flyProviderMutation);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly dry-run reports stale secret names without mutating them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-stale-secret-plan-"));
  const config = flySecretPushConfig();
  config.services = ["core", "portal"];
  const coreStale = [
    "AGENT_API_URL",
    "AWS_ACCESS_KEY_ID",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_DYNAMODB",
    "AWS_ENDPOINT_URL_S3",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
    "AWS_SECRET_ACCESS_KEY",
    "DATA_DIR",
    "DEPLOY_PROVIDER",
    "DEPLOYMENT_LAYER",
    "DOCKER_HOST",
    "FLY_REGION",
    "FLY_APP_NAME",
    "FLY_MACHINE_ID",
    "NODE_ENV",
    "QM_CORE_CONTAINER",
    "RUN_STORE",
    "S3_BUCKET",
    "S3_REGION",
    "SESSION_STORE",
    "SLACK_API_URL",
    "SNAPSHOT_STORE",
    "TRANSFER_STORE",
  ];
  const fake = fakeFlyProvider(dir, config, {
    extraSecretsByApp: {
      "acme-core": coreStale,
      "acme-portal": ["AUTH_BROKER_PREFIX", "AUTH_BROKER_UPSTREAM", "CAPABILITY_SECRET", "STOLEN_PORTAL_KEY"],
    },
  });
  const output: string[] = [];
  const log = console.log;
  console.log = (...args: unknown[]): void => void output.push(args.join(" "));
  try {
    await flyUp(config, dir, { dryRun: true });
    const corePlan = output.find((line) => line.includes("acme-core: would stage removal"));
    assert.ok(corePlan);
    for (const name of coreStale) assert.ok(corePlan.includes(name), name);
    assert.match(
      output.join("\n"),
      /acme-portal: would stage removal[^\n]*AUTH_BROKER_PREFIX[^\n]*AUTH_BROKER_UPSTREAM[^\n]*CAPABILITY_SECRET[^\n]*STOLEN_PORTAL_KEY/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), flyProviderMutation);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects a malformed aliased OIDC trust value before every provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-aliased-oidc-validation-"));
  const config = flySecretPushConfig();
  config.services = ["core", "portal"];
  config.plugins = [];
  config.secretEnv = { portal: { OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE" } };
  const source = join(dir, "values.env");
  writeFileSync(
    source,
    [
      flySecretPushEnvironment(),
      "ADMIN_GRANTS=admin@example.com:org_admin",
      "OIDC_CLIENT_ID=client-id",
      "OIDC_CLIENT_SECRET=client-secret",
      "PORTAL_EXPECTED_TEAM_ID=T123",
      `PORTAL_SESSION_SECRET=${"portal-session".repeat(3)}`,
      "PORTAL_ALLOWLIST_STORE=not-an-email",
    ].join("\n"),
  );
  const fake = fakeFlyProvider(dir, config);
  try {
    await assert.rejects(
      flySecretsPush(config, dir, readEnvFile(source)),
      /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly honors a trimmed virtual deploy-provider selector for token setup and cleanup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-virtual-deploy-provider-"));
  const config = flySecretPushConfig();
  config.plugins = [];
  config.services = ["core", "slack"];
  config.env = { core: { HARNESS: "mock" }, slack: { DEPLOY_PROVIDER: "  fly  " } };
  const token = "FlyV1-scoped";
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, flySecretPushEnvironment(`FLY_DEPLOY_API_TOKEN=${token}`));
  const fake = fakeFlyProvider(dir, config, { extraSecrets: ["FLY_DEPLOY_API_TOKEN"] });
  const log = console.log;
  console.log = (): void => {};
  try {
    assert.ok(computedSecrets(config).some((secret) => secret.name === "FLY_DEPLOY_API_TOKEN" && secret.required));
    await flySecretsPush(config, dir, readEnvFile(envFile));
    const pushCalls = readFileSync(fake.log, "utf8");
    assert.match(pushCalls, /^secrets set --stage -a acme-core FLY_DEPLOY_API_TOKEN=-$/m);
    assert.doesNotMatch(pushCalls, /^secrets unset .* FLY_DEPLOY_API_TOKEN$/m);
    writeFileSync(fake.log, "");
    verifyLocalFlyTokens(config, new Map([["FLY_DEPLOY_API_TOKEN", token]]));
    assert.match(readFileSync(fake.log, "utf8"), /^apps list -o personal --json$/m);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

async function withFakeStdin<T>(fn: (emit: (bytes: Buffer) => void) => Promise<T>): Promise<T> {
  const fake = Object.assign(new EventEmitter(), {
    isTTY: true,
    setRawMode(): void {},
    resume(): void {},
    pause(): void {},
  });
  const descriptor = Object.getOwnPropertyDescriptor(process, "stdin")!;
  const write = process.stdout.write.bind(process.stdout);
  Object.defineProperty(process, "stdin", { value: fake, configurable: true });
  process.stdout.write = (() => true) as typeof process.stdout.write;
  try {
    return await fn((bytes) => void fake.emit("data", bytes));
  } finally {
    process.stdout.write = write;
    Object.defineProperty(process, "stdin", descriptor);
  }
}

test("mpgClusterId matches a whole field regardless of column position or spacing", () => {
  const header = "ID              NAME          REGION  STATUS";
  assert.equal(
    mpgClusterId(`${header}\npg-abc123       acme-pg       sjc     ready`, "acme-pg"),
    "pg-abc123",
    "name padded with spaces on both sides",
  );
  assert.equal(
    mpgClusterId(`ID       REGION  NAME\npg-abc123  sjc   acme-pg`, "acme-pg"),
    "pg-abc123",
    "name in the last column (no trailing space)",
  );
  assert.equal(mpgClusterId(`${header}\npg-abc123 acme-pg-2 sjc ready`, "acme-pg"), undefined, "no substring matches");
  assert.equal(mpgClusterId("", "acme-pg"), undefined);
});

test("mpgDirectUrl selects the direct Managed Postgres endpoint without exposing credentials", () => {
  assert.equal(
    mpgDirectUrl(
      JSON.stringify({
        credentials: {
          pgbouncer_uri: "postgresql://fly-user:p%40ss@pgbouncer.pg-123.flympg.net/fly-db",
        },
      }),
      "pg-123",
    ),
    "postgresql://fly-user:p%40ss@direct.pg-123.flympg.net/fly-db",
  );
  assert.equal(
    mpgDirectUrl(
      JSON.stringify({
        credentials: {
          direct_uri: "postgresql://fly-user:p%40ss@direct.pg-123.flympg.net/fly-db",
        },
      }),
      "pg-123",
    ),
    "postgresql://fly-user:p%40ss@direct.pg-123.flympg.net/fly-db",
  );
  assert.throws(() => mpgDirectUrl("{", "pg-123"), /invalid JSON/);
  assert.throws(
    () =>
      mpgDirectUrl(
        JSON.stringify({ credentials: { pgbouncer_uri: "postgresql://direct.pg-456.flympg.net/db" } }),
        "pg-123",
      ),
    /unrecognized database hostname/,
  );
  assert.throws(
    () =>
      mpgDirectUrl(JSON.stringify({ credentials: { direct_uri: "https://direct.pg-123.flympg.net/db" } }), "pg-123"),
    /invalid database connection scheme/,
  );
});

test("fly up strips and stops the retired Admin app when Admin is disabled", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core"], "owned");
  assert.equal(error, undefined);
  assert.match(calls, /^secrets unset --stage -a acme-admin .*\bQM_UPDATE_GITHUB_TOKEN\b/m);
  assert.match(calls, /^scale count 0 -a acme-admin --yes$/m);
});

test("fly up fails closed when a core-only deploy would leave stale Admin secrets", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core", "admin"], "owned", ["core"]);
  assert.match(
    String(error),
    /--only cannot leave stale secrets active on unselected apps:[\s\S]*QM_UPDATE_GITHUB_TOKEN/,
  );
  assert.doesNotMatch(calls, /^secrets unset /m);
});

test("fly up stages retired Admin update-token removal when Admin deploys", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core", "admin"], "owned");
  assert.equal(error, undefined);
  assert.match(calls, /^secrets unset --stage -a acme-admin .*\bQM_UPDATE_GITHUB_TOKEN\b/m);
  assert.doesNotMatch(calls, /^secrets unset -a acme-admin QM_UPDATE_GITHUB_TOKEN$/m);
});

test("fly up removes the retired core FLY_API_TOKEN alias after legacy external-backend migration", async (t) => {
  for (const backend of ["porter", "smolmachines"] as const) {
    await t.test(backend, async () => {
      const { calls, error } = await runRetiredUpdateTokenCleanup(["core"], "owned", undefined, backend);
      assert.equal(error, undefined);
      assert.match(calls, /^secrets unset --stage -a acme-core .*\bFLY_API_TOKEN\b/m);
    });
  }
});

test("fly up leaves an absent Admin app or retired update token alone", async () => {
  for (const state of ["missing-app", "missing-token"] as const) {
    const { calls, error } = await runRetiredUpdateTokenCleanup(["core"], state);
    assert.equal(error, undefined);
    assert.doesNotMatch(calls, /^secrets unset (?:--stage )?-a acme-admin QM_UPDATE_GITHUB_TOKEN$/m);
  }
});

test("fly up surfaces but never mutates an unselected unowned Admin app", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core"], "unowned");
  assert.match(String(error), /unowned app uses the deployment prefix; verify and remove it/);
  assert.doesNotMatch(calls, /^secrets unset (?:--stage )?-a acme-admin QM_UPDATE_GITHUB_TOKEN$/m);
  assert.match(calls, /^secrets list -a acme-admin --json$/m);
  assert.match(calls, /^status -a acme-admin --json$/m);
});

test("fly preflight rejects a selected unowned Admin app before mutation", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core", "admin"], "unowned");
  assert.match(String(error), /acme-admin is not marked as owned by deployment qm-v2:personal:acme:acme/);
  assert.doesNotMatch(calls, flyProviderMutation);
});

test("Fly validates required secrets before any deployment mutation", async () => {
  const { calls, error } = await runRetiredUpdateTokenCleanup(["core"], "missing-required");
  assert.match(String(error), /acme-core is missing required secrets: SPRITES_TOKEN/);
  assert.doesNotMatch(calls, /^(?:apps create|secrets (?:set|unset)|mpg create|deploy) /m);
});

test("Fly rejects an invalid active email allowlist before provider mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-allowlist-preflight-"));
  const config = flyAuthAllowlistConfig();
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, "AUTH_ALLOWED_EMAILS=not-an-email\n");
  const fake = fakeFlyProvider(dir, config);
  try {
    await assert.rejects(runFlyProviderUp(config, dir, envFile), /AUTH_ALLOWED_EMAILS/);
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects a missing explicit env file before provider access", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-missing-env-"));
  const config = flyProviderConfig();
  const fake = fakeFlyProvider(dir, config);
  try {
    assert.throws(() => flyPreflightUp(config, dir, { envFile: join(dir, "missing.env") }), /--env-file not found/);
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects an env alias to the loaded config after the config path is replaced", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-config-identity-"));
  const configPath = join(dir, "qm.config.jsonc");
  const originalConfig = join(dir, "loaded.config.jsonc");
  const envFile = join(dir, "deployment.env");
  const config = flyProviderConfig();
  writeFileSync(configPath, JSON.stringify(config));
  const loaded = loadConfigAt(configPath);
  renameSync(configPath, originalConfig);
  writeFileSync(configPath, JSON.stringify({ ...config, orgId: "replacement" }));
  symlinkSync(originalConfig, envFile);
  const fake = fakeFlyProvider(dir, config);
  try {
    assert.throws(
      () =>
        flyPreflightUp(loaded.config, dir, {
          configIdentity: loaded.configIdentity,
          envFile,
        }),
      /deployment environment file must be separate from the deployment config/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly preflight credits a valid local email allowlist and up stages it before deploy", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-allowlist-recovery-"));
  const config = flyAuthAllowlistConfig();
  config.env = { core: { HARNESS: "mock" }, auth: { AUTH_EMAIL_TRANSPORT: "resend" } };
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, "AUTH_ALLOWED_EMAILS=admin@example.com\n");
  const fake = fakeFlyProvider(dir, config, { omitSecrets: ["AUTH_ALLOWED_EMAILS"] });
  const log = console.log;
  console.log = (): void => {};
  try {
    flyPreflightUp(config, dir, { envFile });
    await flyUp(config, dir, { envFile, preflighted: true });
    const calls = readFileSync(fake.log, "utf8");
    const stage = calls.indexOf("secrets set --stage -a acme-core AUTH_ALLOWED_EMAILS=-");
    assert.ok(stage >= 0, calls);
    assert.ok(stage < calls.indexOf("deploy --yes"), calls);
    assert.match(calls, new RegExp(`input AUTH_ALLOWED_EMAILS ${Buffer.from("admin@example.com").toString("base64")}`));
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly up stages its initial environment snapshot when the env file changes after validation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-allowlist-snapshot-"));
  const config = flyAuthAllowlistConfig();
  config.env = { core: { HARNESS: "mock" }, auth: { AUTH_EMAIL_TRANSPORT: "resend" } };
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, "AUTH_ALLOWED_EMAILS=initial@example.com\n");
  const fake = fakeFlyProvider(dir, config, {
    omitSecrets: ["AUTH_ALLOWED_EMAILS"],
    replaceEnvFile: { path: envFile, content: "AUTH_ALLOWED_EMAILS=changed@example.com\n" },
  });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flyUp(config, dir, { envFile, preflighted: true });
    const calls = readFileSync(fake.log, "utf8");
    assert.match(
      calls,
      new RegExp(`input AUTH_ALLOWED_EMAILS ${Buffer.from("initial@example.com").toString("base64")}`),
    );
    assert.doesNotMatch(calls, new RegExp(Buffer.from("changed@example.com").toString("base64")));
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects NUL in selected deployment secrets before provider mutation", async (t) => {
  for (const [name, value] of [
    ["AUTH_ALLOWED_EMAILS", "admin@example.com\0ignored"],
    ["DATABASE_URL", "postgres://external/db\0ignored"],
    ["FUTURE_TOKEN", "future\0ignored"],
  ] as const) {
    await t.test(name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-fly-nul-preflight-"));
      const config = name === "AUTH_ALLOWED_EMAILS" ? flyAuthAllowlistConfig() : flyProviderConfig();
      if (name === "FUTURE_TOKEN") {
        config.plugins.push({
          name: "future",
          image: "ghcr.io/acme/future:1",
          secrets: [{ name: "FUTURE_TOKEN", required: false }],
        });
      }
      const envFile = join(dir, "deployment.env");
      writeFileSync(envFile, `${name}=${value}\n`);
      const fake = fakeFlyProvider(dir, config);
      try {
        await assert.rejects(runFlyProviderUp(config, dir, envFile), (error) => {
          assert.match(String(error), new RegExp(`${name} contains a NUL byte`));
          assert.doesNotMatch(String(error), /ignored/);
          return true;
        });
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Fly rejects an oversized selected plugin secret before any provider call", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-selected-secret-limit-"));
  const config = flySecretPushConfig();
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, `ZZZ_PLUGIN_SECRET=${"x".repeat(65_537)}\n`);
  const fake = fakeFlyProvider(dir, config);
  try {
    assert.throws(
      () => flyPreflightUp(config, dir, { envFile }),
      /ZZZ_PLUGIN_SECRET exceeds the 65536-byte provider limit/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects every invalid supplied secret before any provider call", async (t) => {
  const cases = [
    {
      name: "edge whitespace",
      secret: "ZZZ_PLUGIN_SECRET",
      line: 'ZZZ_PLUGIN_SECRET=" padded "',
      error: /ZZZ_PLUGIN_SECRET has leading or trailing whitespace/,
    },
    {
      name: "Go-only edge whitespace",
      secret: "ZZZ_PLUGIN_SECRET",
      line: "ZZZ_PLUGIN_SECRET=\u0085padded",
      error: /ZZZ_PLUGIN_SECRET has leading or trailing whitespace/,
    },
    {
      name: "over 64 KiB",
      secret: "ZZZ_PLUGIN_SECRET",
      line: `ZZZ_PLUGIN_SECRET=${"x".repeat(65_537)}`,
      error: /ZZZ_PLUGIN_SECRET exceeds the 65536-byte provider limit/,
    },
    {
      name: "email allowlist",
      secret: "AUTH_ALLOWED_EMAILS",
      line: "AUTH_ALLOWED_EMAILS=not-an-email",
      error: /required secrets are missing or invalid: AUTH_ALLOWED_EMAILS/,
    },
    {
      name: "email sender",
      secret: "AUTH_EMAIL_FROM",
      line: "AUTH_EMAIL_FROM=not-an-email",
      error: /required secrets are missing or invalid: AUTH_EMAIL_FROM/,
    },
    {
      name: "private JWK",
      secret: "AUTH_SIGNING_JWK",
      line: "AUTH_SIGNING_JWK=not-a-jwk",
      error: /required secrets are missing or invalid: AUTH_SIGNING_JWK/,
    },
  ] as const;
  for (const example of cases) {
    await t.test(example.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-fly-invalid-push-secret-"));
      const firstParty = example.secret.startsWith("AUTH_");
      const config = firstParty ? flyAuthSecretPushConfig() : flySecretPushConfig(example.secret);
      const envFile = join(dir, "deployment.env");
      writeFileSync(envFile, flySecretPushEnvironment(example.line));
      const fake = fakeFlyProvider(dir, config);
      try {
        const supplied = readEnvFile(envFile);
        const values = firstParty ? new Map([...requiredFlySecretValues(config), ...supplied]) : supplied;
        await assert.rejects(flySecretsPush(config, dir, values), example.error);
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Fly rejects individually valid duplicate security and auth secrets before any provider call", async (t) => {
  for (const kind of ["security", "auth"] as const) {
    await t.test(kind, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-fly-duplicate-push-secret-"));
      const config = flySecretPushConfig();
      const duplicate = "same-secret-value".repeat(3);
      let environment: string;
      let expected: RegExp;
      if (kind === "security") {
        environment = flySecretPushEnvironment("ZZZ_PLUGIN_SECRET=valid").replace(
          /CONNECTOR_SECRET_KEY=.*\nCORE_SIGNING_SECRET=.*/,
          `CONNECTOR_SECRET_KEY=${duplicate}\nCORE_SIGNING_SECRET=${duplicate}`,
        );
        expected = /required secrets are missing or invalid: CONNECTOR_SECRET_KEY, CORE_SIGNING_SECRET/;
      } else {
        Object.assign(config, flyAuthSecretPushConfig());
        environment = `AUTH_CLIENT_SECRET=${duplicate}\nAUTH_TOKEN_SECRET=${duplicate}`;
        expected = /required secrets are missing or invalid: AUTH_CLIENT_SECRET, AUTH_TOKEN_SECRET/;
      }
      const envFile = join(dir, "deployment.env");
      writeFileSync(envFile, environment);
      const fake = fakeFlyProvider(dir, config);
      try {
        const supplied = readEnvFile(envFile);
        const values = kind === "auth" ? new Map([...requiredFlySecretValues(config), ...supplied]) : supplied;
        await assert.rejects(flySecretsPush(config, dir, values), (error) => {
          assert.match(String(error), expected);
          assert.doesNotMatch(String(error), new RegExp(duplicate));
          return true;
        });
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Fly rejects NUL in a prompted plugin secret before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-prompted-nul-"));
  const config = flySecretPushConfig();
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, flySecretPushEnvironment());
  const fake = fakeFlyProvider(dir, config);
  try {
    await withFakeStdin(async (emit) => {
      const pending = flySecretsPush(config, dir, readEnvFile(envFile));
      emit(Buffer.from("prompted\0secret\r"));
      await assert.rejects(pending, (error) => {
        assert.match(String(error), /ZZZ_PLUGIN_SECRET contains a NUL byte/);
        assert.doesNotMatch(String(error), /prompted/);
        return true;
      });
    });
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly stages a valid plugin secret with its interior whitespace intact", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-lossless-secret-"));
  const config = flySecretPushConfig();
  const envFile = join(dir, "deployment.env");
  const value = "valid pass phrase";
  writeFileSync(envFile, flySecretPushEnvironment(`ZZZ_PLUGIN_SECRET=${value}`));
  const fake = fakeFlyProvider(dir, config);
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(envFile));
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /^secrets set --stage -a acme-future ZZZ_PLUGIN_SECRET=-$/m);
    assert.match(calls, new RegExp(`^input ZZZ_PLUGIN_SECRET ${Buffer.from(value).toString("base64")}$`, "m"));
    assert.doesNotMatch(calls, /^secrets (?:set|unset) (?!.*--stage)/m);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly stages a plugin secret at the 65536-byte provider limit without changing it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-max-secret-"));
  const config = flySecretPushConfig();
  const envFile = join(dir, "deployment.env");
  const value = "x".repeat(65_536);
  writeFileSync(envFile, flySecretPushEnvironment(`ZZZ_PLUGIN_SECRET=${value}`));
  const fake = fakeFlyProvider(dir, config);
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(envFile));
    const calls = readFileSync(fake.log, "utf8");
    const encoded = /^input ZZZ_PLUGIN_SECRET (.*)$/m.exec(calls)?.[1];
    assert.ok(encoded);
    assert.equal(Buffer.from(encoded, "base64").toString(), value);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly secrets push stages retired Admin-token removal and every secret mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-stage-only-push-"));
  const config = flySecretPushConfig();
  config.services = ["core", "admin"];
  config.plugins = [];
  const envFile = join(dir, "deployment.env");
  writeFileSync(envFile, flySecretPushEnvironment());
  const fake = fakeFlyProvider(dir, config, { extraSecrets: ["QM_UPDATE_GITHUB_TOKEN"] });
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(envFile));
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /^secrets unset --stage -a acme-admin .*\bQM_UPDATE_GITHUB_TOKEN\b/m);
    for (const call of calls.match(/^secrets (?:set|unset).*$/gm) ?? [])
      assert.match(call, /^secrets (?:set|unset) --stage /);
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rejects an appPrefix traversal before writing or calling Fly", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-prefix-traversal-"));
  const config = flySecretPushConfig();
  config.appPrefix = "../../escaped";
  const fake = fakeFlyProvider(dir, config);
  try {
    assert.throws(() => flyPreflightUp(config, dir), /unsafe Fly generated output path/);
    assert.equal(readFileSync(fake.log, "utf8"), "");
    assert.equal(existsSync(join(dir, ".generated")), false);
    assert.equal(existsSync(join(dir, "..", "..", "escaped")), false);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly refuses linked generated output paths before provider mutation", async (t) => {
  for (const attack of ["ancestor-symlink", "output-hardlink"] as const) {
    await t.test(attack, async () => {
      const root = mkdtempSync(join(tmpdir(), "qm-fly-generated-link-"));
      const configDir = join(root, "deployment");
      const externalDir = join(root, "external");
      const generatedDir = join(configDir, ".generated", "fly", "acme");
      const externalOutputDir = attack === "ancestor-symlink" ? join(externalDir, "fly", "acme") : externalDir;
      const externalOutput = join(externalOutputDir, "core.fly.toml");
      const sentinel = `external-${attack}-sentinel`;
      mkdirSync(configDir, { recursive: true });
      mkdirSync(externalOutputDir, { recursive: true });
      writeFileSync(externalOutput, sentinel);
      if (attack === "ancestor-symlink") {
        symlinkSync(externalDir, join(configDir, ".generated"));
      } else {
        mkdirSync(generatedDir, { recursive: true });
        linkSync(externalOutput, join(generatedDir, "core.fly.toml"));
      }
      const config = flyProviderConfig();
      const fake = fakeFlyProvider(root, config);
      const priorAllowlist = process.env.AUTH_ALLOWED_EMAILS;
      delete process.env.AUTH_ALLOWED_EMAILS;
      try {
        await assert.rejects(runFlyProviderUp(config, configDir), /unsafe Fly generated output/);
        assert.equal(readFileSync(externalOutput, "utf8"), sentinel);
        assert.doesNotMatch(readFileSync(fake.log, "utf8"), flyProviderMutation);
      } finally {
        if (priorAllowlist === undefined) delete process.env.AUTH_ALLOWED_EMAILS;
        else process.env.AUTH_ALLOWED_EMAILS = priorAllowlist;
        fake.restore();
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
});

test("Fly source discovery preserves trailing whitespace and ignores ambient Git redirection", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-source-root-"));
  const source = join(dir, "source  ");
  const redirected = join(dir, "redirected");
  const configDir = join(source, "deployment");
  createMinimalFlySource(source);
  createMinimalFlySource(redirected);
  mkdirSync(configDir);
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.fly.dev",
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
  const fake = fakeFlyProvider(dir, config, {
    statusImage: `registry.fly.io/acme-core@sha256:${"a".repeat(64)}`,
  });
  const priorGitDir = process.env.GIT_DIR;
  const priorGitWorkTree = process.env.GIT_WORK_TREE;
  const log = console.log;
  process.env.GIT_DIR = join(redirected, ".git");
  process.env.GIT_WORK_TREE = redirected;
  console.log = (): void => {};
  try {
    await flyUp(config, configDir, { buildFrom: true });
    const calls = readFileSync(fake.log, "utf8");
    const discovered = realpathSync(source);
    assert.ok(
      calls.includes(`--dockerfile ${join(discovered, "deploy", "core", "Dockerfile")} ${discovered}\n`),
      calls,
    );
    assert.equal(calls.includes(join(redirected, "deploy", "core", "Dockerfile")), false);
  } finally {
    console.log = log;
    if (priorGitDir === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = priorGitDir;
    if (priorGitWorkTree === undefined) delete process.env.GIT_WORK_TREE;
    else process.env.GIT_WORK_TREE = priorGitWorkTree;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly source builds do not claim immutable source provenance", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-storage-"));
  const fly = join(dir, "fly");
  const log = join(dir, "fly.log");
  const state = join(dir, "storage-created");
  const marker = "QM_OWNER_CD83933C6C53374D";
  writeFileSync(
    fly,
    `#!/usr/bin/env node
const fs = require("node:fs");
const a = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, a.join(" ") + "\\n");
if (a[0] === "apps" && a[1] === "create") console.log("already been taken");
else if (a[0] === "apps" && a[1] === "list") console.log(JSON.stringify([{ Name: "acme-core" }, { Name: "acme-admin" }]));
else if (a[0] === "secrets" && a[1] === "list") {
  const names = ${JSON.stringify([
    marker,
    "CAPABILITY_SECRET",
    "CONNECTOR_SECRET_KEY",
    "CORE_SIGNING_SECRET",
    "FLY_DEPLOY_API_TOKEN",
    "FLY_API_TOKEN",
    "PORTAL_IDENTITY_SECRET",
    "QM_UPDATE_GITHUB_TOKEN",
    "SECURITY_SCREEN_PROXY_TOKEN",
    "SKILL_SIGNING_SECRET",
    "SPRITES_TOKEN",
  ])};
  if (fs.existsSync(${JSON.stringify(state)})) names.push("AWS_ACCESS_KEY_ID", "AWS_ENDPOINT_URL_S3", "AWS_SECRET_ACCESS_KEY");
  console.log(JSON.stringify(names.map((Name) => ({ Name }))));
} else if (a[0] === "storage" && a[1] === "create") fs.writeFileSync(${JSON.stringify(state)}, "1");
else if (a[0] === "status") {
  const selected = process.env.QM_TEST_SWAP_FLY_CONFIG;
  const target = process.env.QM_TEST_SWAP_FLY_TARGET;
  if (selected && target && !fs.lstatSync(selected).isSymbolicLink()) {
    fs.renameSync(selected, selected + ".loaded");
    fs.symlinkSync(target, selected);
  }
  console.log(JSON.stringify({ Machines: [{ config: { image: "registry.fly.io/acme-core:deployment-123" } }] }));
}
else if (a[0] === "image" && a[1] === "show") console.log(JSON.stringify([{ Registry: "registry.fly.io", Repository: "acme-core", Tag: "deployment-123", Digest: "sha256:${"b".repeat(64)}" }]));
else if (a[0] === "mpg" && a[1] === "list") console.log("pg-1 acme-pg");
else if (a[0] === "mpg" && a[1] === "status") console.log(JSON.stringify({ credentials: { direct_uri: "postgresql://u:p@direct.pg-1.flympg.net/db" } }));
else console.log("ok");
`,
  );
  chmodSync(fly, 0o755);
  const prior = process.env.FLY_BIN;
  process.env.FLY_BIN = fly;
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.fly.dev",
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "admin"],
    plugins: [],
    skills: [],
    env: {
      core: { HARNESS: "mock", SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" },
    },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
  };
  const configPath = join(dir, "custom-deployment.jsonc");
  writeFileSync(configPath, JSON.stringify(config, null, 2));
  const source = join(dir, "source");
  for (const service of ["core", "admin"]) {
    const deploy = join(source, "deploy", service);
    mkdirSync(deploy, { recursive: true });
    writeFileSync(join(deploy, "Dockerfile"), "FROM scratch\n");
    writeFileSync(
      join(deploy, "fly.toml"),
      readFileSync(new URL(`../../deploy/${service}/fly.toml`, import.meta.url), "utf8"),
    );
  }
  mkdirSync(join(source, "src"), { recursive: true });
  mkdirSync(join(source, "cli"), { recursive: true });
  writeFileSync(join(source, "package.json"), "{}\n");
  writeFileSync(join(source, "src", "index.ts"), "export {};\n");
  writeFileSync(join(source, "cli", "package.json"), JSON.stringify({ version: "1.2.3-test" }));
  const priorSwapConfig = process.env.QM_TEST_SWAP_FLY_CONFIG;
  const priorSwapTarget = process.env.QM_TEST_SWAP_FLY_TARGET;
  try {
    await flyUp(config, dir, {
      buildFrom: true,
      buildFromPath: source,
      configPath,
      configIdentity: loadConfigAt(configPath).configIdentity,
    });
    const calls = readFileSync(log, "utf8");
    assert.match(calls, /storage create --name acme-data --app acme-core --org personal --yes/);
    const coreUnset = calls.split("\n").find((line) => line.startsWith("secrets unset --stage -a acme-core "));
    const adminUnset = calls.split("\n").find((line) => line.startsWith("secrets unset --stage -a acme-admin "));
    assert.ok(coreUnset);
    assert.ok(adminUnset);
    assert.match(coreUnset, / SECURITY_SCREEN_PROXY_TOKEN(?: |$)/);
    assert.match(coreUnset, / FLY_DEPLOY_API_TOKEN(?: |$)/);
    assert.match(adminUnset, / QM_UPDATE_GITHUB_TOKEN(?: |$)/);
    assert.ok(calls.indexOf("secrets unset") < calls.indexOf("deploy"));
    assert.ok(calls.indexOf("storage create") < calls.indexOf("deploy"));
    assert.doesNotMatch(calls, /GIT_SHA|QM_VERSION/);
    assert.equal(
      JSON.parse(readFileSync(configPath, "utf8")).imageOverrides.core,
      `registry.fly.io/acme-core@sha256:${"b".repeat(64)}`,
    );
    assert.equal(existsSync(join(dir, "qm.config.jsonc")), false);
    const target = join(dir, "unrelated.json");
    const targetRaw = '{"unrelated":true}\n';
    writeFileSync(target, targetRaw);
    const loaded = loadConfigAt(configPath);
    const loadedRaw = readFileSync(configPath, "utf8");
    process.env.QM_TEST_SWAP_FLY_CONFIG = configPath;
    process.env.QM_TEST_SWAP_FLY_TARGET = target;
    await assert.rejects(
      flyUp(config, dir, {
        buildFrom: true,
        buildFromPath: source,
        configPath,
        configIdentity: loaded.configIdentity,
      }),
      /deployment config changed while recording Fly image coordinates/,
    );
    assert.equal(readFileSync(target, "utf8"), targetRaw);
    assert.equal(readFileSync(`${configPath}.loaded`, "utf8"), loadedRaw);
  } finally {
    if (priorSwapConfig === undefined) delete process.env.QM_TEST_SWAP_FLY_CONFIG;
    else process.env.QM_TEST_SWAP_FLY_CONFIG = priorSwapConfig;
    if (priorSwapTarget === undefined) delete process.env.QM_TEST_SWAP_FLY_TARGET;
    else process.env.QM_TEST_SWAP_FLY_TARGET = priorSwapTarget;
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--only "slack" explains the virtual service runs in-process on the core', async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-up-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme2",
    publicUrl: "https://acme2-portal.fly.dev",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "slack"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme2-sandboxes" },
  };
  try {
    await assert.rejects(
      flyUp(config, dir, { only: ["slack"] }),
      /--only "slack": slack is a virtual service — it runs in-process on the core, so deploy it with --only core/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
