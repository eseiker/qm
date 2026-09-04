import { spawnSync } from "node:child_process";
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfigAt, type QmConfig } from "../src/config.ts";
import {
  derivedTomlFor,
  derivedPluginTomlFor,
  flyCheckLive,
  flyLiveSessionCommand,
  flyS3ProbeCommand,
  flyUp,
} from "../src/backends/fly.ts";
import type { ResolvedPlugin } from "../src/plugins.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TEST_CONFIG_IDENTITY = { dev: -1n, ino: -1n };

test("Fly runs the live session smoke inside the private core machine", () => {
  assert.equal(flyLiveSessionCommand(), "node src/deployment/postdeploy-smoke.ts session http://127.0.0.1:8080");
});

test("a Fly deployment configures core to create Sprites with the configured name prefix", () => {
  const { config } = loadConfigAt(join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"));
  const cfg = {
    ...config,
    sandbox: {
      backend: "sprites" as const,
      namePrefix: "acme-sb",
    },
  };

  const core = derivedTomlFor(cfg, "core", repoRoot);
  assert.match(core, /SANDBOX_BACKEND = "sprites"/);
  assert.match(core, /SPRITES_NAME_PREFIX = "acme-sb"/);

  const admin = derivedTomlFor(cfg, "admin", repoRoot);
  assert.doesNotMatch(admin, /SANDBOX_BACKEND|SPRITES_NAME_PREFIX/);
});

test("a legacy Fly sandbox app preserves the historical Sprite name prefix", () => {
  const { config } = loadConfigAt(join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"));
  const core = derivedTomlFor({ ...config, sandbox: { app: "acme-sandboxes" } }, "core", repoRoot);
  assert.match(core, /SANDBOX_BACKEND = "sprites"/);
  assert.doesNotMatch(core, /SPRITES_NAME_PREFIX/);
});

test("the fly target routes security screen proxy configuration only to core", () => {
  const { config } = loadConfigAt(join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"));
  const screened: QmConfig = {
    ...config,
    securityScreen: {
      backend: "proxy",
      provider: "example-screen",
      endpoint: "https://screen.example.test/classify",
      rollout: "shadow",
    },
  };
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(generatedEnv(derivedTomlFor(screened, "core", repoRoot))).filter(([name]) =>
        name.startsWith("SECURITY_SCREEN_"),
      ),
    ),
    {
      SECURITY_SCREEN_BACKEND: "proxy",
      SECURITY_SCREEN_PROXY_ENDPOINT: "https://screen.example.test/classify",
      SECURITY_SCREEN_PROXY_PROVIDER: "example-screen",
      SECURITY_SCREEN_PROXY_ROLLOUT: "shadow",
    },
  );
  assert.deepEqual(
    Object.keys(generatedEnv(derivedTomlFor(screened, "admin", repoRoot))).filter((name) =>
      name.startsWith("SECURITY_SCREEN_"),
    ),
    [],
  );
});

test("the Fly portal receives the same effective deployment apps domain selected by the core", () => {
  const base: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "portal"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  for (const [name, core, expected] of [
    [
      "common",
      {
        DEPLOY_PROVIDER: "porter",
        DEPLOY_APPS_DOMAIN: "common.example.com",
        PORTER_DEPLOY_APPS_DOMAIN: "porter.example.com",
        AWS_DEPLOY_APPS_DOMAIN: "aws.example.com",
      },
      "common.example.com",
    ],
    ["legacy AWS fallback", { DEPLOY_PROVIDER: "fly", AWS_DEPLOY_APPS_DOMAIN: "aws.example.com" }, "aws.example.com"],
  ] as const) {
    const config: QmConfig = { ...base, env: { core } };
    const portal = generatedEnv(derivedTomlFor(config, "portal", repoRoot));
    assert.equal(portal.DEPLOY_APPS_DOMAIN, expected, name);
  }
  const noDomain = generatedEnv(
    derivedTomlFor(
      { ...base, env: { core: { DEPLOY_PROVIDER: "fly", PORTER_DEPLOY_APPS_DOMAIN: "porter.example.com" } } },
      "portal",
      repoRoot,
    ),
  );
  assert.equal(noDomain.DEPLOY_APPS_DOMAIN, undefined);
});

test("the fly target derives a plugin fly.toml wiring it to the core over 6PN", () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "qm",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [{ name: "linear" }],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const plugin: ResolvedPlugin = { name: "linear", kind: "image", image: "ghcr.io/x:1", env: { LINEAR_REGION: "us" } };
  const toml = derivedPluginTomlFor(config, plugin);

  assert.match(toml, /app = "qm-linear"/, "app is <appPrefix>-<name>");
  assert.match(toml, /primary_region = "sjc"/);
  assert.match(toml, /CORE_API_URL = "http:\/\/qm-core\.internal:8080"/, "plugin reaches core over 6PN");
  assert.match(toml, /CORE_ORG_ID = "acme"/);
  assert.match(toml, /PORT = "8080"/);
  assert.match(toml, /LINEAR_REGION = "us"/, "the entry's non-secret env is forwarded");
  assert.match(
    toml,
    /\[checks\.ready\][\s\S]*type = "tcp"[\s\S]*port = 8080/,
    "plugins declare a private TCP readiness check",
  );
  assert.doesNotMatch(toml, /CORE_SIGNING_SECRET/, "the source-auth secret must not be in the toml");
});

test("a plugin's entry env can override the injected wiring (entry env wins)", () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "qm",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const plugin: ResolvedPlugin = { name: "custom", kind: "source", env: { CORE_API_URL: "http://elsewhere:9000" } };
  assert.match(derivedPluginTomlFor(config, plugin), /CORE_API_URL = "http:\/\/elsewhere:9000"/);
});

test("Fly forces production mode after every image and source plugin environment merge", () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "qm",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  for (const plugin of [
    { name: "image-plugin", kind: "image" as const, image: "ghcr.io/x:1", env: { NODE_ENV: "development" } },
    { name: "source-plugin", kind: "source" as const, env: { NODE_ENV: "test" } },
  ]) {
    const toml = derivedPluginTomlFor(config, plugin);
    assert.match(toml, /^\s*NODE_ENV = "production"$/m, plugin.name);
    assert.doesNotMatch(toml, /^\s*NODE_ENV = "(?:development|test)"$/m, plugin.name);
  }
});

test("a plugin env value with quotes/backslashes is escaped into valid TOML", () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "qm",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const plugin: ResolvedPlugin = { name: "quoter", kind: "source", env: { JSON_CFG: '{"x":"y"}\\end' } };
  const toml = derivedPluginTomlFor(config, plugin);
  assert.match(toml, /JSON_CFG = "\{\\"x\\":\\"y\\"\}\\\\end"/, "quotes and backslash are escaped");
});

test("--only rejects a name that is neither a service nor a plugin (before any Fly call)", async () => {
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    appPrefix: "qm",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [{ name: "linear", image: "ghcr.io/x:1" }],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const emptyDir = mkdtempSync(join(tmpdir(), "qm-fly-only-"));
  await assert.rejects(
    () => flyUp(config, emptyDir, { configIdentity: TEST_CONFIG_IDENTITY, dryRun: true, only: ["nope"] }),
    /--only "nope" is not a service or plugin/,
  );
});

import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { flyRollback, flySecretsPush } from "../src/backends/fly.ts";
import { readEnvFile } from "../src/util.ts";

function fakeFly(dir: string, script: string): { log: string; restore: () => void } {
  const bin = join(dir, "fly-fake");
  const log = join(dir, "fly.log");
  const state = join(dir, "fly-state.json");
  writeFileSync(log, "");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const a = args.join(" ");
const fakeStatePath = ${JSON.stringify(state)};
const fakeState = fs.existsSync(fakeStatePath) ? JSON.parse(fs.readFileSync(fakeStatePath, "utf8")) : { apps: [], secrets: {} };
const fakeAppIndex = args.indexOf("-a");
const fakeTargetApp = args[0] === "apps" && args[1] === "create" ? args[2] : fakeAppIndex < 0 ? "" : args[fakeAppIndex + 1];
if (args[0] === "apps" && args[1] === "create" && fakeTargetApp && !fakeState.apps.includes(fakeTargetApp)) fakeState.apps.push(fakeTargetApp);
if (args[0] === "secrets" && args[1] === "set" && fakeTargetApp) {
  const assignment = args[args.length - 1];
  const name = assignment.slice(0, assignment.indexOf("="));
  fakeState.secrets[fakeTargetApp] = [...new Set([...(fakeState.secrets[fakeTargetApp] || []), name])];
}
if (args[0] === "secrets" && args[1] === "unset" && fakeTargetApp) {
  const removed = new Set(args.slice(fakeAppIndex + 2));
  fakeState.secrets[fakeTargetApp] = (fakeState.secrets[fakeTargetApp] || []).filter((name) => !removed.has(name));
}
fs.writeFileSync(fakeStatePath, JSON.stringify(fakeState));
fs.appendFileSync(${JSON.stringify(log)}, a + "\\n");
let fakeEmitted = false;
const fakeOutput = console.log.bind(console);
console.log = (...values) => {
  if (args[0] === "secrets" && args[1] === "list" && values.length === 1 && values[0] === "ok") return;
  fakeEmitted = true;
  fakeOutput(...values);
};
${script}
if (!fakeEmitted && args[0] === "apps" && args[1] === "list") console.log(JSON.stringify(fakeState.apps.map((Name) => ({ Name }))));
else if (!fakeEmitted && args[0] === "secrets" && args[1] === "list") console.log(JSON.stringify((fakeState.secrets[fakeTargetApp] || []).map((Name) => ({ Name }))));
else if (!fakeEmitted && args[0] === "status") console.log(JSON.stringify({ Machines: [] }));
`,
  );
  chmodSync(bin, 0o755);
  const prior = process.env.FLY_BIN;
  process.env.FLY_BIN = bin;
  return {
    log,
    restore: () => {
      if (prior === undefined) delete process.env.FLY_BIN;
      else process.env.FLY_BIN = prior;
    },
  };
}

function generatedEnv(toml: string): Record<string, string> {
  const env: Record<string, string> = {};
  let inEnv = false;
  for (const line of toml.split("\n")) {
    const section = line.match(/^\s*\[(.+)\]\s*$/);
    if (section) {
      inEnv = section[1] === "env";
      continue;
    }
    const match = inEnv ? line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*("(?:[^"\\]|\\.)*")\s*$/) : null;
    if (match?.[1] && match[2]) env[match[1]] = JSON.parse(match[2]) as string;
  }
  return env;
}

test("the Fly S3 probe is valid CommonJS that reports async failures", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-s3-probe-syntax-"));
  try {
    const command = flyS3ProbeCommand();
    const encoded = command.match(/Buffer\.from\('([^']+)'/)?.[1];
    assert.ok(encoded, "probe command carries encoded source");
    const source = Buffer.from(encoded, "base64").toString("utf8");
    assert.doesNotMatch(source, /^\s*import\s/m, "eval never receives a static ESM import");
    assert.match(source, /\(async \(\) => \{/);
    assert.match(source, /\.catch\(\(error\) => \{/);
    const path = join(dir, "probe.cjs");
    writeFileSync(path, source);
    const checked = spawnSync(process.execPath, ["--check", path], { encoding: "utf8" });
    assert.equal(checked.status, 0, checked.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push stages runtime and Sprites credentials on the core app", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-push-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "slack"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "pi" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sb" },
  };
  mkdirSync(join(dir, "plugins", "srcplug"), { recursive: true });
  writeFileSync(join(dir, "plugins", "srcplug", "Dockerfile"), "FROM scratch\n");
  writeFileSync(
    join(dir, ".env"),
    [
      "ANTHROPIC_API_KEY=k",
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "SPRITES_TOKEN=f",
      "PUBLIC_API_URL=https://acme.example.com",
      "SLACK_BOT_TOKEN=xoxb",
      "SLACK_APP_TOKEN=xapp",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `const v = fs.readFileSync(0, "utf8"); fs.appendFileSync(${JSON.stringify(join(dir, "fly.log"))}, "value:" + v + "\\n");`,
  );
  const priorAnthropic = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = "proc-wins";
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(
      calls.includes("secrets set --stage -a acme-core ANTHROPIC_API_KEY=-"),
      "plain name for the core process",
    );
    assert.ok(calls.includes("secrets set --stage -a acme-core SPRITES_TOKEN=-"));
    assert.ok(
      calls.includes("secrets set --stage -a acme-core SLACK_BOT_TOKEN=-"),
      "virtual-service secrets stage plain on core",
    );
    assert.ok(
      calls.includes("secrets set --stage -a acme-srcplug CORE_SIGNING_SECRET=-"),
      "discovered source plugins get the signing secret",
    );
    assert.ok(calls.includes("apps create acme-core --org personal"), "the service app exists before secret staging");
    assert.ok(calls.includes("apps create acme-srcplug --org personal"), "source plugin apps are created too");
    assert.ok(
      !calls.includes("apps create acme-sb --org personal"),
      "secret delivery never adopts or creates the separately managed sandbox registry app",
    );
    assert.ok(!calls.includes("-a acme-srcplug SLACK_BOT_TOKEN"), "other secrets do not fan out to plugins");
    assert.ok(calls.includes("value:k\n"), "the deployment .env wins over ambient process credentials");
    assert.ok(!calls.includes("value:proc-wins"), "ambient credentials do not replace deployment-scoped values");
  } finally {
    console.log = log;
    if (priorAnthropic === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = priorAnthropic;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push warns that staged secrets are not live when machines are running", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-push-staged-warn-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sb" },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "SPRITES_TOKEN=fly",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("status -a acme-core")) console.log(JSON.stringify({ Machines: [{ id: "m1", state: "started" }] }));
else if (a.startsWith("secrets set ")) fs.readFileSync(0, "utf8");
`,
  );
  const log = console.log;
  const warnLog = console.warn;
  const warnings: string[] = [];
  console.log = (): void => {};
  console.warn = (msg: string): void => {
    warnings.push(msg);
  };
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    assert.ok(
      warnings.some((line) => line.includes("staged secrets are NOT live yet on acme-core")),
      warnings.join("\n"),
    );
    assert.ok(warnings.some((line) => line.includes("run `qm up`")));
  } finally {
    console.log = log;
    console.warn = warnLog;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push stays quiet about staging when no machines are running", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-push-staged-quiet-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sb" },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "SPRITES_TOKEN=fly",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("status -a")) console.log(JSON.stringify({ Machines: [] }));
else if (a.startsWith("secrets set ")) fs.readFileSync(0, "utf8");
`,
  );
  const log = console.log;
  const warnLog = console.warn;
  const warnings: string[] = [];
  console.log = (): void => {};
  console.warn = (msg: string): void => {
    warnings.push(msg);
  };
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    assert.ok(!warnings.some((line) => line.includes("staged secrets are NOT live")), warnings.join("\n"));
  } finally {
    console.log = log;
    console.warn = warnLog;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push removes retired core publisher aliases while ignoring disabled routes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-push-publisher-off-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "admin"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    secretEnv: {
      slack: { FLY_API_TOKEN: "DISABLED_FLY_TOKEN" },
    },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "SPRITES_TOKEN=fly",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }, { Name: "acme-admin" }]));
else if (a === "secrets list -a acme-core --json") console.log(JSON.stringify(["QM_OWNER_CD83933C6C53374D", "FLY_DEPLOY_API_TOKEN", "FLY_API_TOKEN"].map((Name) => ({ Name }))));
else if (a === "secrets list -a acme-admin --json") console.log(JSON.stringify([{ Name: "QM_OWNER_CD83933C6C53374D" }]));
else if (a.startsWith("secrets set ")) fs.readFileSync(0, "utf8");
`,
  );
  const log = console.log;
  const messages: string[] = [];
  console.log = (...args: unknown[]): void => {
    messages.push(args.join(" "));
  };
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    const calls = readFileSync(fake.log, "utf8");
    assert.match(calls, /secrets unset --stage -a acme-core .*\bFLY_DEPLOY_API_TOKEN\b/);
    assert.match(calls, /secrets unset --stage -a acme-core .*\bFLY_API_TOKEN\b/);
    assert.doesNotMatch(calls, /input DISABLED_FLY_TOKEN|secrets set[^\n]*FLY_API_TOKEN/);
    assert.ok(messages.some((line) => line.includes("FLY_API_TOKEN")));
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push rejects FLY_API_TOKEN routed through active core topology", async (t) => {
  for (const route of ["core", "slack"] as const) {
    await t.test(route, async () => {
      const dir = mkdtempSync(join(tmpdir(), `qm-fly-push-current-${route}-fly-secrets-`));
      const config: QmConfig = {
        contract: 1,
        orgId: "acme",
        publicUrl: "https://acme.example.com",
        target: "fly",
        region: "sjc",
        flyOrg: "personal",
        services: route === "core" ? ["core"] : ["core", "slack"],
        plugins: [],
        skills: [],
        env: { core: { HARNESS: "mock" } },
        imageOverrides: {},
        secretEnv: {
          [route]: {
            FLY_API_TOKEN: "CURRENT_FLY_TOKEN",
          },
        },
      };
      const configPath = join(dir, "qm.config.jsonc");
      writeFileSync(configPath, JSON.stringify(config));
      const loadedConfig = loadConfigAt(configPath).config;
      writeFileSync(
        join(dir, ".env"),
        [
          "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
          `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
          `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
          "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
          `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
          "SPRITES_TOKEN=fly",
          "CURRENT_FLY_TOKEN=current-fly",
        ].join("\n"),
      );
      const fake = fakeFly(
        dir,
        `
if (a === "secrets list -a acme-core --json") console.log(JSON.stringify([{ Name: "FLY_API_TOKEN" }]));
else if (a.startsWith("secrets set ")) fs.readFileSync(0, "utf8");
`,
      );
      const log = console.log;
      console.log = (): void => {};
      try {
        await assert.rejects(
          flySecretsPush(loadedConfig, dir, readEnvFile(join(dir, ".env"))),
          /cannot target provider-owned destination core\.FLY_API_TOKEN/,
        );
        assert.equal(readFileSync(fake.log, "utf8"), "");
      } finally {
        console.log = log;
        fake.restore();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("fly secrets push falls back to an ambient secret when the scaffold entry is blank", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-push-blank-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
  };
  writeFileSync(
    join(dir, ".env"),
    [
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      "CORE_SIGNING_SECRET=",
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "SPRITES_TOKEN=fly",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `const v = fs.readFileSync(0, "utf8"); fs.appendFileSync(${JSON.stringify(join(dir, "fly.log"))}, "value:" + v + "\\n");`,
  );
  const prior = process.env.CORE_SIGNING_SECRET;
  process.env.CORE_SIGNING_SECRET = "ambient-signing-secret-that-is-long-enough";
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    assert.match(readFileSync(fake.log, "utf8"), /value:ambient-signing-secret-that-is-long-enough/);
  } finally {
    console.log = log;
    if (prior === undefined) delete process.env.CORE_SIGNING_SECRET;
    else process.env.CORE_SIGNING_SECRET = prior;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check requires deployed machines and a healthy public endpoint", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    apiUrl: "https://api.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "web-ui", "portal"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const liveEnvs = Object.fromEntries(
    ["core", "web-ui", "portal"].map((service) => [
      service,
      generatedEnv(derivedTomlFor(config, service as "core" | "web-ui" | "portal", repoRoot)),
    ]),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify(["core", "web-ui", "portal"].map((service) => ({ Name: "acme-" + service }))));
else if (a.startsWith("status")) {
  const app = process.argv[process.argv.indexOf("-a") + 1];
  const service = app.slice("acme-".length);
  console.log(JSON.stringify({ Machines: [{ id: "machine-" + service, state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(liveEnvs)}[service] } }] }));
}
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  const lines: string[] = [];
  const log = console.log;
  console.log = (...args: unknown[]): void => void lines.push(args.join(" "));
  try {
    const healthUrls: string[] = [];
    await flyCheckLive(config, dir, {
      fetchImpl: async (url, init) => {
        assert.equal(init?.redirect, "manual");
        healthUrls.push(String(url));
        return new Response('{"ok":true}', { status: 200 });
      },
      report: false,
    });
    assert.deepEqual(healthUrls, ["https://qm.example.test/healthz", "https://api.example.test/healthz"]);
    await assert.rejects(
      flyCheckLive(config, dir, {
        fetchImpl: async (url, init) => {
          assert.equal(init?.redirect, "manual");
          return String(url).startsWith(config.apiUrl!)
            ? new Response(null, { status: 302, headers: { location: config.publicUrl } })
            : new Response('{"ok":true}', { status: 200 });
        },
        report: false,
      }),
      /https:\/\/api\.example\.test\/healthz: HTTP 302/,
    );
    assert.deepEqual(lines, [], "JSON callers can suppress all human-readable live-check output");
    const calls = readFileSync(fake.log, "utf8");
    for (const app of ["acme-core", "acme-web-ui", "acme-portal"]) {
      assert.ok(calls.includes(`status -a ${app} --json`));
    }
    assert.match(
      calls,
      /ssh console -a acme-core --machine machine-core .* --quiet/,
      "live readiness proves S3 from the running core",
    );
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check rejects stale secrets on their wrong workload", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-stale-secrets-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["portal"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const stale = [
    "AWS_ACCESS_KEY_ID",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "CAPABILITY_SECRET",
    "FLY_APP_NAME",
    "MixedCaseSecret",
    "SLACK_API_URL",
    "STOLEN_PORTAL_KEY",
    "lowercase_secret",
  ];
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-portal" }]));
else if (a.startsWith("secrets list")) console.log(${JSON.stringify(
      [
        "NAME  DIGEST  CREATED AT",
        "QM_OWNER_CD83933C6C53374D digest now",
        ...stale.map((name) => `${name} digest now`),
      ].join("\n"),
    )});
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ state: "started", region: "sjc", config: { image: "registry.fly.io/acme-portal@sha256:${"a".repeat(64)}", env: { QM_DEPLOYMENT_ID: "qm-v2:personal:acme:acme" } } }] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok"), report: false }),
      (error: unknown) => {
        const message = String(error);
        for (const name of stale) assert.match(message, new RegExp(name));
        return true;
      },
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check rejects a mismatched materialized public API coordinate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-public-api-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    apiUrl: "https://api.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "pi" } },
    imageOverrides: {},
  };
  const env = generatedEnv(derivedTomlFor(config, "core", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("secrets list")) console.log(JSON.stringify([{ Name: "QM_OWNER_CD83933C6C53374D" }, { Name: "PUBLIC_API_URL" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ id: "machine-core", state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(env)} } }] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else if (a.includes("QM_PUBLIC_API_URL_CHECK=1")) { console.error("mismatch"); process.exit(42); }
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok"), report: false }),
      /PUBLIC_API_URL does not match the configured public API coordinate/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /^secrets (?:set|unset)|^scale count|^apps destroy/m);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check surfaces an unowned zero-machine app in the deployment prefix", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-unowned-prefix-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["portal"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
  };
  const env = generatedEnv(derivedTomlFor(config, "portal", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-portal" }, { Name: "acme-retired" }]));
else if (a === "secrets list -a acme-portal --json") console.log(JSON.stringify([{ Name: "QM_OWNER_CD83933C6C53374D" }]));
else if (a === "secrets list -a acme-retired --json") console.log("[]");
else if (a === "status -a acme-retired --json") console.log(JSON.stringify({ Machines: [] }));
else if (a === "status -a acme-portal --json") console.log(JSON.stringify({ Machines: [{ id: "machine-portal", state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(env)} } }] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok"), report: false }),
      /acme-retired: unowned app uses the deployment prefix; verify and remove it or restore its ownership marker/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /^secrets (?:set|unset)|^scale count|^apps destroy/m);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness rejects the wrong organization identity, region, and rendered env", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-identity-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{
  id: "machine-core", state: "started", region: "ord",
  config: { image: "registry.fly.io/app@sha256:abc", env: { QM_DEPLOYMENT_ID: "qm-v2:other-org:acme:acme" } }
}] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      (error: unknown) => {
        assert.match((error as Error).message, /lack deployment identity qm-v2:personal:acme:acme/);
        assert.equal((error as { clause?: string }).clause, "fly.live-readiness");
        return true;
      },
    );
    assert.doesNotMatch(
      readFileSync(fake.log, "utf8"),
      /ssh console/,
      "an unowned core never receives the storage probe",
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness rejects the wrong region after deployment identity matches", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-region-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const env = generatedEnv(derivedTomlFor(config, "core", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{
  id: "machine-core", state: "started", region: "ord",
  config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(env)} }
}] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /machine region is ord instead of sjc/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness rejects rendered environment drift after identity and region match", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-env-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const env = { ...generatedEnv(derivedTomlFor(config, "core", repoRoot)), S3_BUCKET: "wrong-bucket" };
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{
  id: "machine-core", state: "started", region: "sjc",
  config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(env)} }
}] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /rendered config drift \(machine 1 env S3_BUCKET\)/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness requires the generated TCP check for plugins", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-plugin-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [{ name: "linear", image: "ghcr.io/example/linear:1" }],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const plugin: ResolvedPlugin = { name: "linear", kind: "image", image: "ghcr.io/example/linear:1", env: {} };
  const liveEnvs = {
    core: generatedEnv(derivedTomlFor(config, "core", repoRoot)),
    linear: generatedEnv(derivedPluginTomlFor(config, plugin)),
  };
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }, { Name: "acme-linear" }]));
else if (a.startsWith("status")) {
  const app = process.argv[process.argv.indexOf("-a") + 1];
  const service = app.slice("acme-".length);
  console.log(JSON.stringify({ Machines: [{ id: "machine-" + service, state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(liveEnvs)}[service] } }] }));
}
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.doesNotReject(() =>
      flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok"), report: false }),
    );
    assert.match(
      readFileSync(fake.log, "utf8"),
      /checks list -a acme-linear --json/,
      "plugin readiness is verified through its generated TCP check",
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness rejects a plugin whose TCP check is not passing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-plugin-failed-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [{ name: "linear", image: "ghcr.io/example/linear:1" }],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const plugin: ResolvedPlugin = { name: "linear", kind: "image", image: "ghcr.io/example/linear:1", env: {} };
  const liveEnvs = {
    core: generatedEnv(derivedTomlFor(config, "core", repoRoot)),
    linear: generatedEnv(derivedPluginTomlFor(config, plugin)),
  };
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }, { Name: "acme-linear" }]));
else if (a.startsWith("status")) {
  const app = process.argv[process.argv.indexOf("-a") + 1];
  const service = app.slice("acme-".length);
  console.log(JSON.stringify({ Machines: [{ id: "machine-" + service, state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(liveEnvs)}[service] } }] }));
}
else if (a.startsWith("checks list") && a.includes("acme-linear")) console.log(JSON.stringify({ machine: [{ status: "failing" }] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /acme-linear: 1 health check not passing/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness fails when core cannot round-trip durable object storage", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-storage-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const env = generatedEnv(derivedTomlFor(config, "core", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ id: "machine-core", state: "started", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc", env: ${JSON.stringify(env)} } }] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else if (a.startsWith("ssh console")) { console.error("AccessDenied"); process.exit(1); }
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /S3 put\/get\/delete probe failed.*AccessDenied/s,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness rejects a healthy machine on the wrong configured image digest", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-image-"));
  const configured = `registry.fly.io/acme-core@sha256:${"a".repeat(64)}`;
  const running = `registry.fly.io/acme-core@sha256:${"b".repeat(64)}`;
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: { core: configured },
  };
  const env = generatedEnv(derivedTomlFor(config, "core", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ id: "machine-core", state: "started", region: "sjc", config: { image: ${JSON.stringify(running)}, env: ${JSON.stringify(env)} } }] }));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /do not run configured image digest/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live readiness resolves deployment tags to their immutable image digest", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-image-tag-"));
  const digest = `sha256:${"a".repeat(64)}`;
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: { core: `registry.fly.io/acme-core@${digest}` },
  };
  const env = generatedEnv(derivedTomlFor(config, "core", repoRoot));
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ id: "machine-core", state: "started", region: "sjc", config: { image: "registry.fly.io/acme-core:deployment-123", env: ${JSON.stringify(env)} } }] }));
else if (a.startsWith("image show")) console.log(JSON.stringify([{ MachineID: "machine-core", Registry: "registry.fly.io", Repository: "acme-core", Tag: "deployment-123", Digest: ${JSON.stringify(digest)} }]));
else if (a.startsWith("checks list")) console.log(JSON.stringify({ machine: [{ status: "passing" }] }));
else console.log("ok");`,
  );
  try {
    await assert.doesNotReject(() =>
      flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok"), report: false }),
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check rejects stopped workloads even when the public endpoint responds", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const fake = fakeFly(
    dir,
    `if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }])); else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [{ id: "machine-core", state: "stopped", region: "sjc", config: { image: "registry.fly.io/app@sha256:abc" } }] })); else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /machine state is stopped instead of started/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly live check rejects a configured workload with no deployed machine", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-live-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://qm.example.test",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { SNAPSHOT_STORE: "s3", TRANSFER_STORE: "s3", S3_BUCKET: "acme-data", S3_REGION: "auto" } },
    imageOverrides: {},
  };
  const fake = fakeFly(
    dir,
    `if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }])); else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [] })); else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flyCheckLive(config, dir, { fetchImpl: async () => new Response("ok") }),
      /acme-core: no deployed machine/,
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push rejects weak signing keys before staging anything", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-weak-secret-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
  };
  writeFileSync(
    join(dir, ".env"),
    `CAPABILITY_SECRET=${"capability".repeat(4)}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nPORTAL_IDENTITY_SECRET=${"identity".repeat(4)}\nCORE_SIGNING_SECRET=short\nSKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}\nSPRITES_TOKEN=f\n`,
  );
  const fake = fakeFly(dir, "");
  try {
    await assert.rejects(
      () => flySecretsPush(config, dir, readEnvFile(join(dir, ".env"))),
      /required secrets are missing or invalid: CORE_SIGNING_SECRET/,
    );
    assert.equal(readFileSync(fake.log, "utf8"), "");
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push refuses an unmarked pre-existing app", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-owner-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sb" },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      `CAPABILITY_SECRET=${"capability".repeat(4)}`,
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      `SPRITES_TOKEN=SpriteV1-scoped`,
      `PORTAL_IDENTITY_SECRET=${"identity".repeat(4)}`,
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps create")) console.log("already been taken");
else if (a.startsWith("apps list")) console.log(JSON.stringify([{ Name: "acme-core" }]));
else if (a.startsWith("secrets list")) console.log(JSON.stringify([{ Name: "CORE_SIGNING_SECRET" }]));
else if (a.startsWith("status")) console.log(JSON.stringify({ Machines: [] }));
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flySecretsPush(config, dir, readEnvFile(join(dir, ".env"))),
      /cannot reconcile Fly secrets without verified ownership:[\s\S]*missing deployment marker/,
    );
    assert.doesNotMatch(readFileSync(fake.log, "utf8"), /CAPABILITY_SECRET=-/);
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly secrets push refuses a same-named app outside the configured Fly organization", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-wrong-org-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "operator-org",
    services: ["core"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    sandbox: { backend: "sprites", namePrefix: "acme-sb" },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      `CAPABILITY_SECRET=${"capability".repeat(4)}`,
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      `SPRITES_TOKEN=SpriteV1-scoped`,
      `PORTAL_IDENTITY_SECRET=${"identity".repeat(4)}`,
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `
if (a.startsWith("apps create")) console.log("already been taken");
else if (a.startsWith("apps list")) console.log("[]");
else console.log("ok");`,
  );
  try {
    await assert.rejects(
      () => flySecretsPush(config, dir, readEnvFile(join(dir, ".env"))),
      /app acme-core exists outside configured Fly organization operator-org/,
    );
    assert.doesNotMatch(
      readFileSync(fake.log, "utf8"),
      /secrets set --stage/,
      "no credential is delivered across the organization boundary",
    );
  } finally {
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly rollback is unsupported", () => {
  assert.throws(
    () =>
      flyRollback(
        {
          contract: 1,
          orgId: "acme",
          publicUrl: "https://acme.example.com",
          target: "fly",
          services: ["core"],
          plugins: [],
          skills: [],
          env: {},
          imageOverrides: {},
          sandbox: { backend: "sprites", namePrefix: "acme" },
        },
        "/deployment/qm.config.jsonc",
        "old",
      ),
    /rollback is not implemented for target fly/,
  );
});

test("fly secrets push stages a secretEnv alias under its declared env name on its service's app", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-alias-"));
  const config: QmConfig = {
    contract: 1,
    orgId: "acme",
    publicUrl: "https://acme.example.com",
    target: "fly",
    region: "sjc",
    flyOrg: "personal",
    services: ["core", "portal"],
    plugins: [],
    skills: [],
    env: { core: { HARNESS: "mock" } },
    imageOverrides: {},
    secretEnv: { core: { DEPLOY_APPS_SESSION_SECRET: "DEPLOY_APPS_STORE", EXTRA_API_KEY: "EXTRA_API_KEY" } },
  };
  writeFileSync(
    join(dir, ".env"),
    [
      "CAPABILITY_SECRET=capability-secret-that-is-long-enough",
      `CONNECTOR_SECRET_KEY=${"connector".repeat(4)}`,
      `CORE_SIGNING_SECRET=${"core-signing".repeat(3)}`,
      "SPRITES_TOKEN=fly",
      "PORTAL_IDENTITY_SECRET=portal-identity-secret-that-is-long-enough",
      `SKILL_SIGNING_SECRET=${"skill-signing".repeat(3)}`,
      "ADMIN_GRANTS=admin@example.com:org_admin",
      "OIDC_CLIENT_ID=client",
      "OIDC_CLIENT_SECRET=oidc",
      "PORTAL_EXPECTED_TEAM_ID=T1",
      `PORTAL_SESSION_SECRET=${"portal-session".repeat(3)}`,
      `DEPLOY_APPS_STORE=${"deploy-session".repeat(3)}`,
      "EXTRA_API_KEY=extra-value",
    ].join("\n"),
  );
  const fake = fakeFly(
    dir,
    `const v = fs.readFileSync(0, "utf8"); fs.appendFileSync(${JSON.stringify(join(dir, "fly.log"))}, "value:" + v + "\\n");`,
  );
  const log = console.log;
  console.log = (): void => {};
  try {
    await flySecretsPush(config, dir, readEnvFile(join(dir, ".env")));
    const calls = readFileSync(fake.log, "utf8");
    assert.ok(
      calls.includes("secrets set --stage -a acme-portal PORTAL_SESSION_SECRET=-"),
      "the portal keeps its plain delivery",
    );
    assert.ok(
      calls.includes("secrets set --stage -a acme-core DEPLOY_APPS_SESSION_SECRET=-"),
      "the alias delivers the stored value under its declared env name on core",
    );
    assert.ok(!calls.includes("-a acme-core PORTAL_SESSION_SECRET"), "the alias adds no plain-name delivery on core");
    assert.ok(
      calls.includes("secrets set --stage -a acme-core EXTRA_API_KEY=-"),
      "config secretEnv extras stage on their service",
    );
    assert.ok(
      calls.includes(`value:${"deploy-session".repeat(3)}`),
      "the aliased delivery pushes the store secret's value",
    );
  } finally {
    console.log = log;
    fake.restore();
    rmSync(dir, { recursive: true, force: true });
  }
});
