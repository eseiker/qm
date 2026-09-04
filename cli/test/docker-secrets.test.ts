import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONFIG_FILENAME, loadConfigAt } from "../src/config.ts";
import {
  dockerDown,
  dockerLogs,
  dockerServiceEnv,
  dockerStatus,
  dockerUp,
  type DockerEnvironmentSource,
} from "../src/backends/docker.ts";
import { sandboxBaseRef } from "../src/manifest.ts";
import { computedSecrets } from "../src/secrets.ts";

const VALID_CAPABILITY_SECRET = "capability".repeat(4);
const VALID_PORTAL_IDENTITY_SECRET = "identity".repeat(5);

const SECRETS = {
  ANTHROPIC_API_KEY: "anthropic-supersecret",
  APPS_SESSION_SECRET: "apps-session-supersecret",
  CAPABILITY_SECRET: VALID_CAPABILITY_SECRET,
  CONNECTOR_SECRET_KEY: "connector-supersecret".repeat(2),
  CORE_SIGNING_SECRET: "core-signing-supersecret".repeat(2),
  DATABASE_CA_CERT: "database-ca-supersecret",
  CONTAINER_DOCKER_CONFIG_SECRET: "container-docker-config-supersecret",
  PORTAL_IDENTITY_SECRET: VALID_PORTAL_IDENTITY_SECRET,
  SKILL_SIGNING_SECRET: "skill-signing-supersecret".repeat(2),
  PLUG_TOKEN: "plugin-supersecret",
  SLACK_BOT_TOKEN: "xoxb-supersecret",
  SLACK_APP_TOKEN: "xapp-supersecret",
  PUBLIC_API_URL: "https://folded.example.com",
  EXTRA_API_KEY: "config-declared-extra-supersecret",
  EXAMPLE_SCREEN_TOKEN: "security-screen-supersecret",
};

function fakeDocker(
  dir: string,
  options: { replaceEnv?: { path: string; contents: string }; waitPostgresOnce?: boolean } = {},
): {
  argvLog: string;
  envCopy: string;
  envLog: string;
  socket: string;
  statLog: string;
} {
  const replaceEnv = options.replaceEnv;
  const argvLog = join(dir, "docker-argv.log");
  const envCopy = join(dir, "env-copy.log");
  const envLog = join(dir, "docker-env.log");
  writeFileSync(argvLog, "");
  writeFileSync(envCopy, "");
  writeFileSync(envLog, "");
  const bin = join(dir, "docker");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const crypto = require("node:crypto");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(argvLog)}, JSON.stringify(args) + "\\n");
fs.appendFileSync(${JSON.stringify(envLog)}, JSON.stringify({
  command: args[0],
  keys: Object.keys(process.env).sort(),
  valueHashes: [...new Set(Object.values(process.env).map((value) => crypto.createHash("sha256").update(value).digest("hex")))],
  controls: Object.fromEntries(["BUILDKIT_HOST", "BUILDX_GIT_INFO", "BUILDX_GIT_LABELS", "DOCKER_CLI_PLUGIN_EXTRA_DIRS", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST", "KUBECONFIG", "PATH"].map((name) => [name, process.env[name] ?? null])),
}) + "\\n");
if (args[0] === "version") { ${replaceEnv ? `fs.writeFileSync(${JSON.stringify(replaceEnv.path)}, ${JSON.stringify(replaceEnv.contents)});` : ""} console.log("25.0"); process.exit(0); }
if (args[0] === "context" && args[1] === "inspect") {
  console.log(JSON.stringify(process.env.DOCKER_HOST || process.env.QM_TEST_DOCKER_ENDPOINT || "unix:///var/run/docker.sock"));
  process.exit(0);
}
${
  options.waitPostgresOnce
    ? `if (args[0] === "exec" && args.includes("pg_isready")) {
  const marker = ${JSON.stringify(join(dir, "postgres-waited"))};
  if (!fs.existsSync(marker)) { fs.writeFileSync(marker, ""); process.exit(1); }
  process.exit(0);
}`
    : ""
}
if (args[0] === "run" || args[0] === "create") {
  const i = args.indexOf("--env-file");
  if (i !== -1) {
    const path = args[i + 1];
    const mode = (fs.statSync(path).mode & 0o777).toString(8);
    fs.appendFileSync(${JSON.stringify(envCopy)}, "mode=" + mode + "\\n" + fs.readFileSync(path, "utf8") + "---\\n");
  }
  for (let index = 0; index < args.length - 1; index++) {
    if (args[index] === "--env" && !args[index + 1].includes("=")) {
      const key = args[index + 1];
      fs.appendFileSync(${JSON.stringify(envCopy)}, "overlay " + key + "=" + JSON.stringify(process.env[key]) + "\\n---\\n");
    }
  }
  if (args[0] === "run" && args.includes("postgres:16") && process.env.QM_TEST_DOCKER_FAIL === "postgres-run") {
    console.error("postgres run failed");
    process.exit(1);
  }
  if (args[0] === "create" && ["create", "create-cleanup"].includes(process.env.QM_TEST_DOCKER_FAIL)) {
    fs.writeFileSync(${JSON.stringify(join(dir, "create-failed"))}, "");
    console.error("create failed");
    process.exit(1);
  }
  console.log("cid");
  process.exit(0);
}
if (args[0] === "cp") {
  if (process.env.QM_TEST_DOCKER_FAIL === "cp") { console.error("copy failed"); process.exit(1); }
  const path = args[1];
  const mode = (fs.statSync(path).mode & 0o777).toString(8);
  const dirMode = (fs.statSync(require("node:path").dirname(path)).mode & 0o777).toString(8);
  fs.appendFileSync(${JSON.stringify(envCopy)}, "copy-mode=" + mode + " dir-mode=" + dirMode + "\\ncopy=" + JSON.stringify(fs.readFileSync(path, "utf8")) + "\\n---\\n");
  process.exit(0);
}
if (args[0] === "start" && process.env.QM_TEST_DOCKER_FAIL === "start") { console.error("start failed"); process.exit(1); }
if (args[0] === "rm" && process.env.QM_TEST_DOCKER_FAIL === "create-cleanup" && fs.existsSync(${JSON.stringify(join(dir, "create-failed"))})) {
  console.error("cleanup failed");
  process.exit(1);
}
if (args[0] === "logs") {
  const name = args[1] ?? "";
  if (name.endsWith("-portal")) console.log("public front door on :8080");
  else if (name.endsWith("-auth")) console.log("sign-in broker on :8080");
  else if (name.endsWith("-web-ui")) console.log("surface on http://localhost:8080");
  else if (name.endsWith("-admin")) console.log("[admin-plugin] http://localhost:8080");
  else console.log("listening on :8080");
  process.exit(0);
}
if (args[0] === "volume") { console.error("No such volume"); process.exit(1); }
if (args[0] === "inspect") {
  if (String(args[args.length - 1]).endsWith("-pg")) { console.error("No such object"); process.exit(1); }
  console.log("true");
  process.exit(0);
}
process.exit(0);
`,
  );
  chmodSync(bin, 0o755);
  const statLog = join(dir, "stat.log");
  const stat = join(dir, "stat");
  writeFileSync(stat, `#!/bin/sh\nprintf invoked > ${JSON.stringify(statLog)}\nexit 99\n`);
  chmodSync(stat, 0o755);
  const socket = join(dir, "docker.sock");
  writeFileSync(socket, "");
  const host = "unix://" + socket;
  process.env.DOCKER_HOST = host;
  return { argvLog, envCopy, envLog, socket, statLog };
}

function fakeGit(dir: string, repoRoot: string): string {
  const log = join(dir, "git-env.log");
  writeFileSync(log, "");
  const bin = join(dir, "git");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const crypto = require("node:crypto");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({
  args,
  keys: Object.keys(process.env).sort(),
  valueHashes: [...new Set(Object.values(process.env).map((value) => crypto.createHash("sha256").update(value).digest("hex")))],
}) + "\\n");
if (args.includes("--show-toplevel")) {
  console.log(${JSON.stringify(repoRoot)});
  process.exit(0);
}
console.error("unexpected git invocation");
process.exit(99);
`,
  );
  chmodSync(bin, 0o755);
  return log;
}

function fakeBuildx(dir: string, name: string): { bin: string; log: string } {
  const log = join(dir, `${name}.log`);
  const bin = join(dir, name);
  writeFileSync(log, "");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const fs = require("node:fs");
const crypto = require("node:crypto");
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({
  args: process.argv.slice(2),
  keys: Object.keys(process.env).sort(),
  valueHashes: [...new Set(Object.values(process.env).map((value) => crypto.createHash("sha256").update(value).digest("hex")))],
  override: process.env.DOCKER_BUILDX_BIN ?? null,
  metadata: { info: process.env.BUILDX_GIT_INFO ?? null, labels: process.env.BUILDX_GIT_LABELS ?? null },
}) + "\\n");
`,
  );
  chmodSync(bin, 0o755);
  return { bin, log };
}

function writeCoreDeployment(dir: string, fields: Record<string, unknown> = {}): void {
  writeFileSync(
    join(dir, CONFIG_FILENAME),
    JSON.stringify({
      contract: 1,
      orgId: "dockertest",
      publicUrl: "http://localhost:8080",
      target: "docker",
      services: ["core"],
      ...fields,
    }),
  );
  writeFileSync(
    join(dir, ".env"),
    `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n`,
  );
}

function loadDockerDeployment(
  configDir: string,
  envFile?: string,
): {
  config: ReturnType<typeof loadConfigAt>["config"];
  environmentSource: DockerEnvironmentSource;
} {
  const loaded = loadConfigAt(join(configDir, CONFIG_FILENAME));
  return {
    config: loaded.config,
    environmentSource: {
      configDir,
      configPath: loaded.path,
      configIdentity: loaded.configIdentity,
      ...(envFile !== undefined ? { envFile } : {}),
    },
  };
}

function validDockerSecretValue(name: string, index: number): string {
  if (name === "AUTH_ALLOWED_EMAILS") return "operator@example.com";
  if (name === "AUTH_EMAIL_FROM") return "QM Operator <operator@example.com>";
  if (name === "AUTH_SIGNING_JWK") {
    return JSON.stringify(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }));
  }
  if (name === "OIDC_CLIENT_ID") return "oidc-client-id";
  if (name === "PORTAL_EXPECTED_TEAM_ID") return "T123";
  return `${name.toLowerCase()}-${index}-`.repeat(4);
}

function writeCompleteDockerEnvironment(
  dir: string,
  config: Parameters<typeof computedSecrets>[0],
  overrides: Readonly<Record<string, string | undefined>> = {},
): void {
  const values = new Map(
    computedSecrets(config)
      .filter((secret) => secret.required && secret.managedBy === "operator")
      .map((secret, index) => [secret.name, validDockerSecretValue(secret.name, index)]),
  );
  values.set("DATABASE_URL", "postgres://external/db");
  for (const [name, value] of Object.entries(overrides)) {
    if (value !== undefined) values.set(name, value);
  }
  writeFileSync(join(dir, ".env"), `${[...values].map(([name, value]) => `${name}=${value}`).join("\n")}\n`);
}

test("Docker gives portal only the trusted deployment apps domain", async (t) => {
  for (const testCase of [
    {
      name: "common domain takes precedence",
      core: {
        DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
        AWS_DEPLOY_APPS_DOMAIN: "aws.portal.example.com",
        PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com",
      },
      expected: "apps.portal.example.com",
    },
    {
      name: "AWS compatibility domain is the fallback",
      core: {
        DEPLOY_PROVIDER: "porter",
        AWS_DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
      },
      expected: "apps.portal.example.com",
    },
    {
      name: "Porter ingress alone is not trusted",
      core: { DEPLOY_PROVIDER: "porter", PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" },
      expected: undefined,
    },
    { name: "no domain remains unset", core: {}, expected: undefined },
  ] as const) {
    await t.test(testCase.name, () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-portal-domain-"));
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "portaldomain",
            publicUrl: "https://portal.example.com",
            target: "docker",
            services: ["core", "portal"],
            env: {
              core: { HARNESS: "mock", ...testCase.core },
              portal: { OIDC_CLIENT_ID: "oidc-client-id", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
            },
          }),
        );
        const { config } = loadConfigAt(join(dir, CONFIG_FILENAME));
        assert.equal(dockerServiceEnv(config, "portal").DEPLOY_APPS_DOMAIN, testCase.expected);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker broker wiring follows the effective portal origin", async (t) => {
  for (const testCase of [
    { name: "canonical portal coordinate without gated apps", gated: false },
    { name: "canonical portal coordinate with gated apps", gated: true },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-portal-origin-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const log = console.log,
        warn = console.warn;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "portalorigin",
            publicUrl: "https://portal.example.com",
            target: "docker",
            services: ["core", "portal", "auth"],
            sandbox: { backend: "sprites" },
            env: {
              core: {
                HARNESS: "mock",
                ...(testCase.gated
                  ? {
                      DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
                    }
                  : {}),
              },
              portal: { PORTAL_PUBLIC_URL: "HTTPS://PORTAL.EXAMPLE.COM:443/" },
              auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
            },
          }),
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        writeCompleteDockerEnvironment(dir, config);
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(config, environmentSource, {});
        const argv = readFileSync(fake.argvLog, "utf8");
        assert.match(argv, /OIDC_ISSUER=https:\/\/portal\.example\.com\/idp/);
        assert.match(argv, /AUTH_REDIRECT_URI=https:\/\/portal\.example\.com\/auth\/callback/);
        assert.match(argv, /PORTAL_PUBLIC_URL=https:\/\/portal\.example\.com/);
        if (testCase.gated) {
          assert.match(argv, /DEPLOY_APPS_DOMAIN=apps\.portal\.example\.com/);
          assert.match(argv, /PUBLIC_WEB_URL=https:\/\/portal\.example\.com/);
        } else {
          assert.doesNotMatch(argv, /DEPLOY_APPS_DOMAIN=/);
        }
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker forces built-in production and portal trust wiring after configured merges", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-forced-production-env-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const log = console.log,
    warn = console.warn;
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "forcedproduction",
        publicUrl: "https://portal.example.com",
        target: "docker",
        services: ["core", "web-ui", "admin", "portal", "auth"],
        sandbox: { backend: "sprites" },
        env: {
          core: { HARNESS: "mock" },
          auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
        },
      }),
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const { config, environmentSource } = loadDockerDeployment(dir);
    const overriddenConfig: typeof config = {
      ...config,
      env: {
        ...config.env,
        core: {
          ...config.env.core,
          NODE_ENV: "test",
          REQUIRE_SIGNED_PORTAL_IDENTITY: "0",
          SESSION_STORE: "memory",
          RUN_STORE: "memory",
        },
        "web-ui": { ...config.env["web-ui"], NODE_ENV: "test", ALLOW_UNSIGNED_TEST_IDENTITY: "1" },
        admin: { ...config.env.admin, NODE_ENV: "test", ALLOW_UNSIGNED_TEST_IDENTITY: "1" },
        portal: {
          ...config.env.portal,
          NODE_ENV: "test",
          WEB_UI_UPSTREAM: "https://attacker.example.com/web-ui",
          ADMIN_UPSTREAM: "https://attacker.example.com/admin",
        },
        auth: { ...config.env.auth, NODE_ENV: "test" },
      },
    };
    writeCompleteDockerEnvironment(dir, overriddenConfig);
    console.log = (): void => {};
    console.warn = console.log;
    await dockerUp(overriddenConfig, environmentSource);
    const calls = readFileSync(fake.argvLog, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    for (const service of ["core", "web-ui", "admin", "portal", "auth"] as const) {
      const args = calls.find(
        (entry) => ["run", "create"].includes(entry[0]!) && entry.includes(`qm-forcedproduction-${service}`),
      );
      assert.ok(args);
      assert.ok(args.includes("NODE_ENV=production"));
      assert.ok(!args.includes("NODE_ENV=test"));
    }
    const core = calls.find(
      (entry) => ["run", "create"].includes(entry[0]!) && entry.includes("qm-forcedproduction-core"),
    );
    assert.ok(core?.includes("REQUIRE_SIGNED_PORTAL_IDENTITY=1"));
    assert.ok(!core?.includes("REQUIRE_SIGNED_PORTAL_IDENTITY=0"));
    assert.ok(core?.includes("SESSION_STORE=postgres"));
    assert.ok(core?.includes("RUN_STORE=postgres"));
    assert.ok(!core?.includes("SESSION_STORE=memory"));
    assert.ok(!core?.includes("RUN_STORE=memory"));
    const portal = calls.find(
      (entry) => ["run", "create"].includes(entry[0]!) && entry.includes("qm-forcedproduction-portal"),
    );
    assert.ok(portal?.includes("WEB_UI_UPSTREAM=http://web-ui:8080"));
    assert.ok(portal?.includes("ADMIN_UPSTREAM=http://admin:8080"));
    assert.ok(portal?.includes("AUTH_BROKER_UPSTREAM=http://qm-forcedproduction-auth.internal:8080"));
    assert.ok(portal?.includes("AUTH_BROKER_PREFIX=/idp"));
    assert.ok(!portal?.some((entry) => entry.includes("attacker.example.com")));
    for (const service of ["web-ui", "admin"] as const) {
      const args = calls.find(
        (entry) => ["run", "create"].includes(entry[0]!) && entry.includes(`qm-forcedproduction-${service}`),
      );
      assert.ok(!args?.some((entry) => entry.startsWith("ALLOW_UNSIGNED_TEST_IDENTITY=")));
    }
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects a post-load built-in auth broker override before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-auth-broker-bypass-"));
  const priorDockerHost = process.env.DOCKER_HOST;
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "brokerbypass",
        publicUrl: "https://portal.example.com",
        target: "docker",
        services: ["core", "portal", "auth"],
        sandbox: { backend: "sprites" },
        env: {
          core: { HARNESS: "mock" },
          auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
        },
      }),
    );
    const fake = fakeDocker(dir);
    const { config, environmentSource } = loadDockerDeployment(dir);
    const overriddenConfig: typeof config = {
      ...config,
      env: {
        ...config.env,
        portal: {
          ...config.env.portal,
          AUTH_BROKER_UPSTREAM: "https://attacker.example.com/auth",
          AUTH_BROKER_PREFIX: "/attacker-idp",
        },
      },
    };
    writeCompleteDockerEnvironment(dir, overriddenConfig);
    await assert.rejects(() => dockerUp(overriddenConfig, environmentSource), /AUTH_BROKER_UPSTREAM/);
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
    assert.equal(readFileSync(fake.envCopy, "utf8"), "");
  } finally {
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker removes internal auth broker transport from an external portal after effective env merges", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-external-portal-broker-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const log = console.log,
    warn = console.warn;
  const attackerUpstream = "https://attacker.example.com/auth";
  const attackerPrefix = "attacker-broker-prefix-secret-value";
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "externalportal",
        publicUrl: "https://portal.example.com",
        target: "docker",
        services: ["core", "portal"],
        sandbox: { backend: "sprites" },
        env: {
          core: { HARNESS: "mock" },
          portal: { OIDC_CLIENT_ID: "oidc-client-id", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
        },
      }),
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const { config, environmentSource } = loadDockerDeployment(dir);
    const overriddenConfig: typeof config = {
      ...config,
      env: {
        ...config.env,
        portal: { ...config.env.portal, AUTH_BROKER_UPSTREAM: attackerUpstream },
      },
      secretEnv: { ...config.secretEnv, portal: { AUTH_BROKER_PREFIX: "ATTACKER_BROKER_PREFIX" } },
    };
    writeCompleteDockerEnvironment(dir, overriddenConfig, { ATTACKER_BROKER_PREFIX: attackerPrefix });
    console.log = (): void => {};
    console.warn = console.log;
    await dockerUp(overriddenConfig, environmentSource);
    const launchedEnvironment = `${readFileSync(fake.argvLog, "utf8")}\n${readFileSync(fake.envCopy, "utf8")}`;
    assert.doesNotMatch(launchedEnvironment, /AUTH_BROKER_(?:UPSTREAM|PREFIX)=/);
    assert.ok(!launchedEnvironment.includes(attackerUpstream));
    assert.ok(!launchedEnvironment.includes(attackerPrefix));
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker config rejects provider-owned core coordinates before any provider call", async (t) => {
  for (const testCase of [
    { source: "env", service: "core", name: "DATA_DIR", value: "/attacker-data" },
    { source: "secretEnv", service: "slack", name: "DATA_DIR", value: "ATTACKER_DATA_SECRET" },
    { source: "env", service: "slack", name: "DOCKER_HOST", value: "tcp://attacker.example.com:2375" },
    { source: "secretEnv", service: "core", name: "DOCKER_HOST", value: "ATTACKER_DOCKER_SECRET" },
    { source: "env", service: "core", name: "QM_CORE_CONTAINER", value: "attacker-core" },
    { source: "secretEnv", service: "slack", name: "QM_CORE_CONTAINER", value: "ATTACKER_CORE_SECRET" },
    { source: "env", service: "slack", name: "DEPLOYMENT_LAYER", value: "/attacker-layer" },
    { source: "secretEnv", service: "core", name: "DEPLOYMENT_LAYER", value: "ATTACKER_LAYER_SECRET" },
  ] as const) {
    await t.test(`${testCase.source}.${testCase.service}.${testCase.name}`, () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-reserved-core-env-"));
      try {
        writeCoreDeployment(dir, {
          services: ["core", "slack"],
          [testCase.source]: { [testCase.service]: { [testCase.name]: testCase.value } },
        });
        const fake = fakeDocker(dir);
        assert.throws(() => loadDockerDeployment(dir), new RegExp(testCase.name));
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker removes configured Slack API origins before core launch", async (t) => {
  for (const testCase of ["plaintext virtual environment", "secret-backed core environment"] as const) {
    await t.test(testCase, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-slack-api-origin-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const log = console.log,
        warn = console.warn;
      const attacker = "https://attacker.example.com/slack-api";
      try {
        writeCoreDeployment(dir, { services: ["core", "slack"], sandbox: { backend: "sprites" } });
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        const overriddenConfig: typeof config = {
          ...config,
          ...(testCase === "plaintext virtual environment"
            ? { env: { ...config.env, slack: { ...config.env.slack, SLACK_API_URL: attacker } } }
            : { secretEnv: { core: { SLACK_API_URL: "ATTACKER_SLACK_API_SECRET" } } }),
        };
        writeCompleteDockerEnvironment(dir, overriddenConfig, { ATTACKER_SLACK_API_SECRET: attacker });
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(overriddenConfig, environmentSource);
        const argv = readFileSync(fake.argvLog, "utf8");
        const envFiles = readFileSync(fake.envCopy, "utf8");
        assert.doesNotMatch(`${argv}\n${envFiles}`, /SLACK_API_URL|attacker\.example\.com/);
        const attackerHash = createHash("sha256").update(attacker).digest("hex");
        for (const line of readFileSync(fake.envLog, "utf8").split("\n").filter(Boolean)) {
          const entry = JSON.parse(line) as { valueHashes: string[] };
          assert.ok(!entry.valueHashes.includes(attackerHash));
        }
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker owns core storage, layer, and local sandbox coordinates after effective env merges", async (t) => {
  for (const testCase of [
    { name: "local sandbox with a deployment layer", backend: "local", layer: true },
    { name: "remote sandbox without a deployment layer", backend: "sprites", layer: false },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-forced-core-env-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const log = console.log,
        warn = console.warn;
      try {
        writeCoreDeployment(dir, {
          services: ["core", "slack"],
          sandbox: { backend: testCase.backend },
          env: { core: { DEPLOYMENT_LAYER: "/attacker-layer" } },
        });
        if (testCase.layer) mkdirSync(join(dir, "sandbox", "skills"), { recursive: true });
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        const overriddenConfig: typeof config = {
          ...config,
          env: {
            ...config.env,
            core: {
              ...config.env.core,
              DATA_DIR: "/attacker-data",
            },
            slack: {
              ...config.env.slack,
              DOCKER_HOST: "tcp://attacker.example.com:2375",
            },
          },
          secretEnv: {
            slack: { QM_CORE_CONTAINER: "ATTACKER_CORE_CONTAINER_SECRET" },
          },
        };
        writeCompleteDockerEnvironment(dir, overriddenConfig, {
          ATTACKER_CORE_CONTAINER_SECRET: "attacker-core",
        });
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(overriddenConfig, environmentSource);
        const calls = readFileSync(fake.argvLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as string[]);
        const core = calls.find(
          (entry) => ["run", "create"].includes(entry[0]!) && entry.includes("qm-dockertest-core"),
        );
        assert.ok(core);
        const coreEnvironment = `${core.join("\n")}\n${readFileSync(fake.envCopy, "utf8")}`;
        assert.ok(coreEnvironment.includes("DATA_DIR=/data"));
        assert.equal(coreEnvironment.includes("DEPLOYMENT_LAYER=/layer"), testCase.layer);
        assert.equal(coreEnvironment.includes("DOCKER_HOST=unix:///var/run/docker.sock"), testCase.backend === "local");
        assert.equal(coreEnvironment.includes("QM_CORE_CONTAINER=qm-dockertest-core"), testCase.backend === "local");
        for (const value of [
          "DATA_DIR=/attacker-data",
          "DEPLOYMENT_LAYER=/attacker-layer",
          "DOCKER_HOST=tcp://attacker.example.com:2375",
          "QM_CORE_CONTAINER=attacker-core",
        ]) {
          assert.ok(!coreEnvironment.includes(value));
        }
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker shares the portal session secret with gated deployment apps", async (t) => {
  for (const testCase of [
    {
      name: "common gated domain",
      core: { DEPLOY_APPS_DOMAIN: "apps.portal.example.com" },
      expectedAlias: true,
    },
    {
      name: "AWS compatibility domain",
      core: { AWS_DEPLOY_APPS_DOMAIN: "apps.portal.example.com" },
      expectedAlias: true,
    },
    {
      name: "Porter ingress only",
      core: { DEPLOY_PROVIDER: "porter", PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" },
      expectedAlias: false,
    },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-app-session-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const log = console.log,
        warn = console.warn;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "appsession",
            publicUrl: "https://portal.example.com",
            target: "docker",
            services: ["core", "portal"],
            sandbox: { backend: "sprites" },
            env: {
              core: { HARNESS: "mock", ...testCase.core },
              portal: { OIDC_CLIENT_ID: "oidc-client-id", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
            },
          }),
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        const sessionSecret = "portal-session-secret-".repeat(2);
        writeCompleteDockerEnvironment(dir, config, { PORTAL_SESSION_SECRET: sessionSecret });
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(config, environmentSource, {});
        const secretFiles = readFileSync(fake.envCopy, "utf8");
        assert.match(secretFiles, new RegExp(`^PORTAL_SESSION_SECRET=${sessionSecret}$`, "m"));
        if (testCase.expectedAlias) {
          assert.match(secretFiles, new RegExp(`^DEPLOY_APPS_SESSION_SECRET=${sessionSecret}$`, "m"));
        } else {
          assert.doesNotMatch(secretFiles, /^DEPLOY_APPS_SESSION_SECRET=/m);
        }
        const argv = readFileSync(fake.argvLog, "utf8");
        assert.match(argv, /PUBLIC_WEB_URL=https:\/\/portal\.example\.com/);
        assert.ok(!argv.includes(sessionSecret));
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker rejects invalid gated deployment app session secrets before provider calls", async (t) => {
  for (const testCase of [
    { name: "placeholder", value: "replace-me", collision: false },
    { name: "short", value: "short-session-secret", collision: false },
    { name: "core signing collision", value: "shared-signing-secret-".repeat(2), collision: true },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-app-session-invalid-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "appsessioninvalid",
            publicUrl: "https://portal.example.com",
            target: "docker",
            services: ["core", "portal"],
            env: {
              core: { HARNESS: "mock", DEPLOY_APPS_DOMAIN: "apps.portal.example.com" },
              portal: { OIDC_CLIENT_ID: "oidc-client-id", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
            },
          }),
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        writeCompleteDockerEnvironment(dir, config, {
          PORTAL_SESSION_SECRET: testCase.value,
          ...(testCase.collision ? { CORE_SIGNING_SECRET: testCase.value } : {}),
        });
        await assert.rejects(dockerUp(config, environmentSource, {}), (error: unknown) => {
          const message = (error as Error).message;
          assert.match(message, /Docker deployment secrets.*PORTAL_SESSION_SECRET/);
          assert.ok(!message.includes(testCase.value));
          return true;
        });
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(readFileSync(fake.envLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("docker up keeps secrets and AWS container credentials out of argv", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-"));
  const priorPath = process.env.PATH;
  const priorDb = process.env.DATABASE_URL;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDockerConfig = process.env.DOCKER_CONFIG;
  const priorProviderControls = new Map(
    ["BUILDKIT_HOST", "DOCKER_CLI_PLUGIN_EXTRA_DIRS", "KUBECONFIG"].map((name) => [name, process.env[name]]),
  );
  const awsContainerCredentials = {
    AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://169.254.170.2/attacker",
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/attacker",
    AWS_CONTAINER_AUTHORIZATION_TOKEN: "attacker-authorization-token",
    AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: "/tmp/attacker-authorization-token",
  };
  const priorAwsContainerCredentials = new Map(
    Object.keys(awsContainerCredentials).map((name) => [name, process.env[name]]),
  );
  const priorDatabaseCaFile = process.env.DATABASE_CA_CERT_FILE;
  const priorAliases = new Map(
    ["APPS_SESSION_ALIAS", "SECURITY_SCREEN_PROXY_TOKEN", "UNRELATED_DUPLICATE_SECRET"].map((name) => [
      name,
      process.env[name],
    ]),
  );
  const priorSecrets = new Map(Object.keys(SECRETS).map((name) => [name, process.env[name]]));
  const log = console.log,
    warn = console.warn;
  const lines: string[] = [];
  const ambientAnthropic = "ambient-anthropic-supersecret";
  const pluginNodeEnvSecret = "plugin-node-environment-value".repeat(2);
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "sekrit",
        publicUrl: "https://folded.example.com",
        target: "docker",
        services: ["core", "slack"],
        plugins: [
          {
            name: "linear",
            image: "ghcr.io/x:1",
            env: { LINEAR_REGION: "us" },
            secrets: [{ name: "PLUG_TOKEN" }, { name: "EMPTY_TOKEN", required: false }],
          },
        ],
        sandbox: {
          backend: "local",
        },
        securityScreen: {
          backend: "proxy",
          provider: "example-screen",
          endpoint: "https://screen.example.test/classify",
          rollout: "enforce",
        },
        secretEnv: {
          core: {
            EXTRA_API_KEY: "EXTRA_API_KEY",
            APPS_SESSION_ALIAS: "APPS_SESSION_SECRET",
            DOCKER_CONFIG: "CONTAINER_DOCKER_CONFIG_SECRET",
            SECURITY_SCREEN_PROXY_TOKEN: "EXAMPLE_SCREEN_TOKEN",
          },
        },
        env: {
          core: { HARNESS: "pi" },
          slack: { WEB_UI_PUBLIC_URL: "https://folded.example.com" },
        },
      }),
    );
    writeFileSync(
      join(dir, ".env"),
      [
        ...Object.entries(SECRETS)
          .filter(([name]) => name !== "ANTHROPIC_API_KEY")
          .map(([k, v]) => `${k}=${v}`),
        "ANTHROPIC_API_KEY=",
        "EMPTY_TOKEN=",
        "HARNESS=pi",
      ].join("\n"),
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.BUILDKIT_HOST = `unix://${fake.socket}`;
    process.env.DOCKER_CLI_PLUGIN_EXTRA_DIRS = join(dir, "docker-plugins");
    process.env.DOCKER_CONFIG = join(dir, "provider-docker-config");
    process.env.KUBECONFIG = join(dir, "kubeconfig");
    process.env.DATABASE_CA_CERT_FILE = "/tmp/ambient-ca-file";
    process.env.DATABASE_URL = "postgres://external/db";
    for (const [name, value] of Object.entries(SECRETS)) process.env[name] = value;
    process.env.ANTHROPIC_API_KEY = ambientAnthropic;
    process.env.APPS_SESSION_ALIAS = "ambient-session-alias";
    process.env.SECURITY_SCREEN_PROXY_TOKEN = "ambient-screen-alias";
    process.env.UNRELATED_DUPLICATE_SECRET = SECRETS.CORE_SIGNING_SECRET;
    for (const [name, value] of Object.entries(awsContainerCredentials)) {
      process.env[name] = `ambient-${value}`;
    }
    console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    const overriddenConfig: typeof config = {
      ...config,
      env: {
        ...config.env,
        core: {
          ...config.env.core,
          AWS_CONTAINER_CREDENTIALS_FULL_URI: awsContainerCredentials.AWS_CONTAINER_CREDENTIALS_FULL_URI,
        },
      },
      secretEnv: {
        ...config.secretEnv,
        core: {
          ...config.secretEnv?.core,
          AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "CORE_AWS_CONTAINER_RELATIVE_URI_SECRET",
        },
      },
      plugins: [
        ...config.plugins.map((plugin) => ({
          ...plugin,
          env: {
            ...plugin.env,
            NODE_ENV: "development",
            AWS_CONTAINER_AUTHORIZATION_TOKEN: awsContainerCredentials.AWS_CONTAINER_AUTHORIZATION_TOKEN,
          },
          secrets: [...(plugin.secrets ?? []), { name: "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE" }],
        })),
        { name: "notion", image: "ghcr.io/x:1", env: {}, secrets: [{ name: "NODE_ENV" }] },
      ],
    };
    writeFileSync(
      join(dir, ".env"),
      `${readFileSync(join(dir, ".env"), "utf8")}\nCORE_AWS_CONTAINER_RELATIVE_URI_SECRET=${awsContainerCredentials.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}\nNODE_ENV=${pluginNodeEnvSecret}\nAWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=${awsContainerCredentials.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE}\n`,
    );
    await dockerUp(overriddenConfig, environmentSource, {});

    const argv = readFileSync(fake.argvLog, "utf8");
    assert.equal(existsSync(fake.statLog), false);
    assert.match(argv, /--group-add/);
    for (const value of Object.values(SECRETS)) {
      assert.ok(!argv.includes(value), `secret value must not reach the docker argv: ${value}`);
    }
    assert.ok(
      !argv.includes("postgres://external/db"),
      "a BYO DATABASE_URL (it embeds a password) must not reach the docker argv",
    );
    assert.ok(argv.includes("--env-file"), "secrets travel via --env-file");
    assert.ok(argv.includes("SANDBOX_BACKEND=local"));
    assert.ok(argv.includes("LOCAL_SANDBOX_IMAGE=qm-sekrit-sandbox-local:latest"));
    const agent = readFileSync(new URL("../templates/aws/microvm-agent/agent.mjs", import.meta.url));
    const wrapperSource = createHash("sha256").update(sandboxBaseRef()).update("\0").update(agent).digest("hex");
    assert.ok(argv.includes(`qm.local-sandbox-source=${wrapperSource}`));
    assert.ok(argv.includes("LINEAR_REGION=us"), "undeclared plugin env still flows as -e");
    assert.ok(argv.includes("SECURITY_SCREEN_BACKEND=proxy"));
    assert.ok(argv.includes("SECURITY_SCREEN_PROXY_PROVIDER=example-screen"));
    assert.ok(argv.includes("SECURITY_SCREEN_PROXY_ENDPOINT=https://screen.example.test/classify"));
    assert.ok(argv.includes("SECURITY_SCREEN_PROXY_ROLLOUT=enforce"));
    const calls = argv
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    const linear = calls.find((args) => ["run", "create"].includes(args[0]!) && args.includes("qm-sekrit-linear"));
    const notion = calls.find((args) => ["run", "create"].includes(args[0]!) && args.includes("qm-sekrit-notion"));
    assert.ok(linear?.includes("NODE_ENV=production"));
    assert.ok(notion?.includes("--env-file"));

    const envFiles = readFileSync(fake.envCopy, "utf8");
    for (const [name, value] of Object.entries(awsContainerCredentials)) {
      assert.ok(!argv.includes(name));
      assert.ok(!argv.includes(value));
      assert.ok(!envFiles.includes(name));
      assert.ok(!envFiles.includes(value));
    }
    assert.match(envFiles, /^NODE_ENV=production$/m);
    assert.ok(!argv.includes("NODE_ENV=development"));
    assert.ok(!envFiles.includes("NODE_ENV=development"));
    assert.ok(!argv.includes(pluginNodeEnvSecret));
    assert.ok(!envFiles.includes(pluginNodeEnvSecret));
    assert.ok(
      `${argv}\n${envFiles}`.includes("WEB_UI_PUBLIC_URL=https://folded.example.com"),
      "virtual-service env folds into the core env",
    );
    assert.ok(
      lines.some((l) => /\.env keys not forwarded/.test(l) && l.includes("HARNESS")),
      "unforwarded .env keys are warned about",
    );
    assert.ok(envFiles.includes(`CORE_SIGNING_SECRET=${SECRETS.CORE_SIGNING_SECRET}`));
    assert.ok(envFiles.includes("DATABASE_URL=postgres://external/db"), "DATABASE_URL routes through the env-file");
    assert.ok(envFiles.includes(`PLUG_TOKEN=${SECRETS.PLUG_TOKEN}`), "plugin secrets route through the file");
    assert.match(
      envFiles,
      new RegExp(`^ANTHROPIC_API_KEY=${ambientAnthropic}$`, "m"),
      "a blank scaffold entry falls back to the ambient secret",
    );
    assert.doesNotMatch(envFiles, /^EMPTY_TOKEN=/m, "a blank optional secret with no ambient value remains unset");
    assert.ok(
      envFiles.includes(`PUBLIC_API_URL=${SECRETS.PUBLIC_API_URL}`),
      "the sandbox-reachable self-API URL reaches core",
    );
    assert.match(
      envFiles,
      new RegExp(`^SLACK_BOT_TOKEN=${SECRETS.SLACK_BOT_TOKEN}$`, "m"),
      "the in-process slack surface receives its plain secret name",
    );
    assert.match(
      envFiles,
      new RegExp(`^EXTRA_API_KEY=${SECRETS.EXTRA_API_KEY}$`, "m"),
      "config secretEnv extras route through the file",
    );
    assert.match(
      envFiles,
      new RegExp(`^APPS_SESSION_ALIAS=${SECRETS.APPS_SESSION_SECRET}$`, "m"),
      "a secretEnv alias delivers the stored value under its declared env name",
    );
    assert.match(envFiles, new RegExp(`^SECURITY_SCREEN_PROXY_TOKEN=${SECRETS.EXAMPLE_SCREEN_TOKEN}$`, "m"));
    assert.match(envFiles, new RegExp(`^DOCKER_CONFIG=${SECRETS.CONTAINER_DOCKER_CONFIG_SECRET}$`, "m"));
    for (const mode of envFiles.match(/^mode=.*$/gm) ?? []) assert.equal(mode, "mode=600");

    const childEntries = readFileSync(fake.envLog, "utf8")
      .split("\n")
      .filter(Boolean)
      .map(
        (line) =>
          JSON.parse(line) as {
            controls: Record<string, string | null>;
            keys: string[];
            valueHashes: string[];
          },
      );
    const strippedNames = [
      ...Object.keys(SECRETS),
      "APPS_SESSION_ALIAS",
      "DATABASE_CA_CERT_FILE",
      "DATABASE_URL",
      "SECURITY_SCREEN_PROXY_TOKEN",
      "UNRELATED_DUPLICATE_SECRET",
      ...Object.keys(awsContainerCredentials),
    ].filter((name) => name !== "DOCKER_CONFIG");
    const strippedValueHashes = [
      ...Object.values(SECRETS),
      "ambient-session-alias",
      "ambient-screen-alias",
      "postgres://external/db",
      pluginNodeEnvSecret,
      ...Object.values(awsContainerCredentials).flatMap((value) => [value, `ambient-${value}`]),
    ].map((value) => createHash("sha256").update(value).digest("hex"));
    for (const entry of childEntries) {
      for (const name of strippedNames) assert.ok(!entry.keys.includes(name), `${name} leaked to the Docker child`);
      for (const hash of strippedValueHashes) assert.ok(!entry.valueHashes.includes(hash));
      assert.equal(entry.controls.BUILDKIT_HOST, `unix://${fake.socket}`);
      assert.equal(entry.controls.DOCKER_CLI_PLUGIN_EXTRA_DIRS, join(dir, "docker-plugins"));
      assert.equal(entry.controls.DOCKER_CONFIG, join(dir, "provider-docker-config"));
      assert.equal(entry.controls.KUBECONFIG, join(dir, "kubeconfig"));
    }

    for (const line of readFileSync(fake.argvLog, "utf8").split("\n").filter(Boolean)) {
      const args = JSON.parse(line) as string[];
      const index = args.indexOf("--env-file");
      if (index !== -1)
        assert.ok(!existsSync(args[index + 1]!), "the env-file is removed once the container is created");
    }
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDb === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = priorDb;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
    else process.env.DOCKER_CONFIG = priorDockerConfig;
    for (const [name, value] of priorProviderControls) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    if (priorDatabaseCaFile === undefined) delete process.env.DATABASE_CA_CERT_FILE;
    else process.env.DATABASE_CA_CERT_FILE = priorDatabaseCaFile;
    for (const [name, value] of priorSecrets) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    for (const [name, value] of priorAliases) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    for (const [name, value] of priorAwsContainerCredentials) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker uses one deployment environment snapshot across preflight and launch", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-env-snapshot-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDuplicate = process.env.UNRELATED_SNAPSHOT_SECRET;
  const originalSigning = "snapshot-core-signing-secret-value";
  const replacementSigning = "post-preflight-signing-placeholder";
  const originalDatabase = "postgres://snapshot/database";
  const replacementDatabase = "postgres://post-preflight/database";
  const log = console.log,
    warn = console.warn;
  try {
    writeCoreDeployment(dir);
    const envPath = join(dir, ".env");
    const initial = readFileSync(envPath, "utf8")
      .replace("CORE_SIGNING_SECRET=" + "core".repeat(8), `CORE_SIGNING_SECRET=${originalSigning}`)
      .replace("DATABASE_URL=postgres://external/db", `DATABASE_URL=${originalDatabase}`);
    writeFileSync(envPath, initial);
    const replacement = initial
      .replace(originalSigning, replacementSigning)
      .replace(originalDatabase, replacementDatabase);
    const fake = fakeDocker(dir, { replaceEnv: { path: envPath, contents: replacement } });
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.UNRELATED_SNAPSHOT_SECRET = originalSigning;
    console.log = (): void => {};
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await dockerUp(config, environmentSource, {});
    const envFiles = readFileSync(fake.envCopy, "utf8");
    assert.ok(envFiles.includes(`CORE_SIGNING_SECRET=${originalSigning}`));
    assert.ok(envFiles.includes(`DATABASE_URL=${originalDatabase}`));
    assert.ok(!envFiles.includes(replacementSigning));
    assert.ok(!envFiles.includes(replacementDatabase));
    const originalHash = createHash("sha256").update(originalSigning).digest("hex");
    for (const line of readFileSync(fake.envLog, "utf8").split("\n").filter(Boolean)) {
      const entry = JSON.parse(line) as { keys: string[]; valueHashes: string[] };
      assert.ok(!entry.keys.includes("UNRELATED_SNAPSHOT_SECRET"));
      assert.ok(!entry.valueHashes.includes(originalHash));
    }
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDuplicate === undefined) delete process.env.UNRELATED_SNAPSHOT_SECRET;
    else process.env.UNRELATED_SNAPSHOT_SECRET = priorDuplicate;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker selects ambient values only for first-party secret stores", async (t) => {
  for (const customFileValue of [true, false]) {
    await t.test(
      customFileValue ? "first-party ambient and custom file values" : "custom ambient-only value",
      async () => {
        const dir = mkdtempSync(join(tmpdir(), "qm-docker-store-selection-"));
        const priorPath = process.env.PATH;
        const priorDockerHost = process.env.DOCKER_HOST;
        const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
        const priorSigning = process.env.CORE_SIGNING_SECRET;
        const priorCustom = process.env.CUSTOM_STORE_TOKEN;
        const log = console.log,
          warn = console.warn;
        const catalogAmbient = "ambient-catalog-signing-secret".repeat(2);
        const customAmbient = "ambient-custom-store-secret";
        const customFile = "file-custom-store-secret";
        try {
          writeCoreDeployment(dir, {
            sandbox: { backend: "sprites" },
            secretEnv: { core: { CUSTOM_RUNTIME_TOKEN: "CUSTOM_STORE_TOKEN" } },
          });
          const fake = fakeDocker(dir);
          const { config, environmentSource } = loadDockerDeployment(dir);
          writeCompleteDockerEnvironment(dir, config, { CUSTOM_STORE_TOKEN: customFile });
          const omitted = customFileValue ? "CORE_SIGNING_SECRET=" : "CUSTOM_STORE_TOKEN=";
          writeFileSync(
            join(dir, ".env"),
            `${readFileSync(join(dir, ".env"), "utf8")
              .split("\n")
              .filter((line) => !line.startsWith(omitted))
              .join("\n")}\n`,
          );
          process.env.PATH = `${dir}:${priorPath}`;
          delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
          process.env.CORE_SIGNING_SECRET = catalogAmbient;
          process.env.CUSTOM_STORE_TOKEN = customAmbient;
          if (!customFileValue) {
            await assert.rejects(dockerUp(config, environmentSource), /CUSTOM_STORE_TOKEN/);
            assert.equal(readFileSync(fake.argvLog, "utf8"), "");
            assert.equal(readFileSync(fake.envCopy, "utf8"), "");
            assert.equal(readFileSync(fake.envLog, "utf8"), "");
            return;
          }
          console.log = (): void => {};
          console.warn = console.log;
          await dockerUp(config, environmentSource);
          const argv = readFileSync(fake.argvLog, "utf8");
          const envFiles = readFileSync(fake.envCopy, "utf8");
          assert.match(envFiles, new RegExp(`^CORE_SIGNING_SECRET=${catalogAmbient}$`, "m"));
          assert.match(envFiles, new RegExp(`^CUSTOM_RUNTIME_TOKEN=${customFile}$`, "m"));
          assert.ok(!argv.includes(catalogAmbient));
          assert.ok(!argv.includes(customFile));
          assert.ok(!argv.includes(customAmbient));
          assert.ok(!envFiles.includes(customAmbient));
        } finally {
          console.log = log;
          console.warn = warn;
          process.env.PATH = priorPath;
          if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
          else process.env.DOCKER_HOST = priorDockerHost;
          if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
          else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
          if (priorSigning === undefined) delete process.env.CORE_SIGNING_SECRET;
          else process.env.CORE_SIGNING_SECRET = priorSigning;
          if (priorCustom === undefined) delete process.env.CUSTOM_STORE_TOKEN;
          else process.env.CUSTOM_STORE_TOKEN = priorCustom;
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );
  }
});

test("Docker file-only mode rejects ambient-only deployment secrets before Docker", async (t) => {
  for (const name of ["DATABASE_URL", "DATABASE_CA_CERT"] as const) {
    await t.test(name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-file-only-"));
      const priorPath = process.env.PATH;
      const priorValue = process.env[name];
      const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
      const priorDockerHost = process.env.DOCKER_HOST;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "fileonly",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\n`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        process.env[name] = "ambient-only";
        process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(
          dockerUp(config, environmentSource, {}),
          new RegExp(`ambient-only deployment secrets .*${name}`),
        );
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorValue === undefined) delete process.env[name];
        else process.env[name] = priorValue;
        if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker operations reject a missing explicit deployment environment at their direct boundary", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-missing-env-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  try {
    writeCoreDeployment(dir);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const missingEnvironment = join(dir, "missing.env");
    const { config, environmentSource } = loadDockerDeployment(dir, missingEnvironment);
    for (const [label, operation] of [
      ["up", () => dockerUp(config, environmentSource)],
      ["status", () => dockerStatus(config, environmentSource)],
      ["logs", () => dockerLogs(config, environmentSource, undefined)],
      ["down", () => dockerDown(config, environmentSource)],
    ] as const) {
      await t.test(label, async () => {
        await assert.rejects(Promise.resolve().then(operation), /--env-file not found/);
      });
    }
    assert.throws(
      () => dockerStatus(config, { ...environmentSource, envFile: "" }),
      /--env-file needs a non-empty path/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
    assert.equal(readFileSync(fake.envCopy, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker accepts disjoint deployment environment symlink and hardlink aliases", async (t) => {
  for (const kind of ["symlink", "hardlink"] as const) {
    await t.test(kind, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-env-alias-"));
      const selectedEnvironment = join(dir, "selected.env");
      const storedEnvironment = join(dir, "stored.env");
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const log = console.log,
        warn = console.warn;
      try {
        writeCoreDeployment(dir);
        renameSync(join(dir, ".env"), storedEnvironment);
        if (kind === "symlink") symlinkSync(storedEnvironment, selectedEnvironment);
        else linkSync(storedEnvironment, selectedEnvironment);
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir, selectedEnvironment);
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(config, environmentSource, { dryRun: true });
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(readFileSync(fake.envLog, "utf8"), "");
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker rejects an environment swapped to the loaded config identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-env-config-swap-"));
  const selectedEnvironment = join(dir, "selected.env");
  const loadedConfig = join(dir, "loaded-config.jsonc");
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  try {
    writeCoreDeployment(dir);
    writeFileSync(selectedEnvironment, readFileSync(join(dir, ".env")));
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const { config, environmentSource } = loadDockerDeployment(dir, selectedEnvironment);
    renameSync(environmentSource.configPath, loadedConfig);
    writeFileSync(environmentSource.configPath, readFileSync(loadedConfig));
    rmSync(selectedEnvironment);
    symlinkSync(loadedConfig, selectedEnvironment);
    await assert.rejects(
      dockerUp(config, environmentSource),
      /deployment environment file must be separate from the deployment config/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
    assert.equal(readFileSync(fake.envCopy, "utf8"), "");
    assert.equal(readFileSync(fake.envLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects non-Unix endpoints before mutation or temporary files", async (t) => {
  for (const endpoint of [
    "tcp://remote.example:2376",
    "ssh://operator@remote.example",
    "https://remote.example",
    "unix:/tmp/docker.sock",
  ]) {
    await t.test(endpoint, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-remote-endpoint-"));
      const temp = join(dir, "tmp");
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorDockerContext = process.env.DOCKER_CONTEXT;
      const priorTmpdir = process.env.TMPDIR;
      try {
        mkdirSync(temp);
        writeCoreDeployment(dir);
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        process.env.DOCKER_HOST = endpoint;
        delete process.env.DOCKER_CONTEXT;
        process.env.TMPDIR = temp;
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(dockerUp(config, environmentSource, {}), /requires a Unix Docker socket/);
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.deepEqual(readdirSync(temp), []);
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
        else process.env.DOCKER_CONTEXT = priorDockerContext;
        if (priorTmpdir === undefined) delete process.env.TMPDIR;
        else process.env.TMPDIR = priorTmpdir;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("DOCKER_CONTEXT overrides DOCKER_HOST and rejects a remote context before mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-remote-context-"));
  const temp = join(dir, "tmp");
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDockerContext = process.env.DOCKER_CONTEXT;
  const priorEndpoint = process.env.QM_TEST_DOCKER_ENDPOINT;
  const priorTmpdir = process.env.TMPDIR;
  try {
    mkdirSync(temp);
    writeCoreDeployment(dir, { sandbox: { backend: "local" } });
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.DOCKER_HOST = `unix://${fake.socket}`;
    process.env.DOCKER_CONTEXT = "remote-context";
    process.env.QM_TEST_DOCKER_ENDPOINT = "ssh://operator@remote.example";
    process.env.TMPDIR = temp;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(dockerUp(config, environmentSource, {}), /requires a Unix Docker socket/);
    const calls = readFileSync(fake.argvLog, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    assert.deepEqual(calls, [
      ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}", "--", "remote-context"],
    ]);
    assert.deepEqual(readdirSync(temp), []);
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
    else process.env.DOCKER_CONTEXT = priorDockerContext;
    if (priorEndpoint === undefined) delete process.env.QM_TEST_DOCKER_ENDPOINT;
    else process.env.QM_TEST_DOCKER_ENDPOINT = priorEndpoint;
    if (priorTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = priorTmpdir;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker down purge rejects a remote endpoint before any Docker call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-remote-down-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDockerContext = process.env.DOCKER_CONTEXT;
  try {
    writeCoreDeployment(dir);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.DOCKER_HOST = "tcp://remote.example:2376";
    delete process.env.DOCKER_CONTEXT;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(dockerDown(config, environmentSource, { purge: true }), /requires a Unix Docker socket/);
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
    else process.env.DOCKER_CONTEXT = priorDockerContext;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker down sanitizes values from the deployment environment snapshot", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-down-secrets-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDuplicate = process.env.UNRELATED_DOWN_SECRET;
  const signingSecret = "core".repeat(8);
  const log = console.log,
    warn = console.warn;
  try {
    writeCoreDeployment(dir);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.UNRELATED_DOWN_SECRET = signingSecret;
    console.log = (): void => {};
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await dockerDown(config, environmentSource);
    const signingHash = createHash("sha256").update(signingSecret).digest("hex");
    for (const line of readFileSync(fake.envLog, "utf8").split("\n").filter(Boolean)) {
      const entry = JSON.parse(line) as { keys: string[]; valueHashes: string[] };
      assert.ok(!entry.keys.includes("UNRELATED_DOWN_SECRET"));
      assert.ok(!entry.valueHashes.includes(signingHash));
    }
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDuplicate === undefined) delete process.env.UNRELATED_DOWN_SECRET;
    else process.env.UNRELATED_DOWN_SECRET = priorDuplicate;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker down rejects a provider control equal to a file-selected secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-down-provider-collision-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorBuildkitHost = process.env.BUILDKIT_HOST;
  try {
    writeCoreDeployment(dir);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.BUILDKIT_HOST = "core".repeat(8);
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(
      dockerDown(config, environmentSource),
      /Docker provider control BUILDKIT_HOST must not equal a selected deployment secret/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorBuildkitHost === undefined) delete process.env.BUILDKIT_HOST;
    else process.env.BUILDKIT_HOST = priorBuildkitHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker local sandbox resolves active and named local Unix contexts", async (t) => {
  for (const [label, named] of [
    ["active context", false],
    ["named context", true],
  ] as const) {
    await t.test(label, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-local-context-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorDockerContext = process.env.DOCKER_CONTEXT;
      const priorDockerConfig = process.env.DOCKER_CONFIG;
      const priorEndpoint = process.env.QM_TEST_DOCKER_ENDPOINT;
      const log = console.log,
        warn = console.warn;
      try {
        writeCoreDeployment(dir, { sandbox: { backend: "local" } });
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        process.env.DOCKER_CONFIG = join(dir, "docker-config");
        process.env.QM_TEST_DOCKER_ENDPOINT = `unix://${fake.socket}`;
        if (named) {
          process.env.DOCKER_CONTEXT = "desktop-linux";
          process.env.DOCKER_HOST = "tcp://ignored.example:2376";
        } else {
          delete process.env.DOCKER_CONTEXT;
          delete process.env.DOCKER_HOST;
        }
        console.log = (): void => {};
        console.warn = console.log;
        const { config, environmentSource } = loadDockerDeployment(dir);
        await dockerUp(config, environmentSource, {});
        const calls = readFileSync(fake.argvLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as string[]);
        assert.deepEqual(calls[0], [
          "context",
          "inspect",
          "--format",
          "{{json .Endpoints.docker.Host}}",
          ...(named ? ["--", "desktop-linux"] : []),
        ]);
        const coreRun = calls.find((args) => args[0] === "run" && args.includes("qm-dockertest-core"));
        assert.ok(coreRun?.includes(`${fake.socket}:/var/run/docker.sock`));
        const envEntries = readFileSync(fake.envLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map(
            (line) =>
              JSON.parse(line) as {
                controls: Record<string, string | null>;
              },
          );
        assert.equal(envEntries[0]?.controls.DOCKER_CONTEXT, null);
        assert.equal(envEntries[0]?.controls.DOCKER_HOST, null);
        assert.equal(envEntries[0]?.controls.DOCKER_CONFIG, join(dir, "docker-config"));
        for (const entry of envEntries.slice(1)) {
          assert.equal(entry.controls.DOCKER_CONFIG, join(dir, "docker-config"));
          assert.equal(entry.controls.DOCKER_CONTEXT, null);
          assert.equal(entry.controls.DOCKER_HOST, `unix://${fake.socket}`);
        }
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
        else process.env.DOCKER_CONTEXT = priorDockerContext;
        if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
        else process.env.DOCKER_CONFIG = priorDockerConfig;
        if (priorEndpoint === undefined) delete process.env.QM_TEST_DOCKER_ENDPOINT;
        else process.env.QM_TEST_DOCKER_ENDPOINT = priorEndpoint;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker build-from omits source identity and sanitizes implicit Git discovery", async (t) => {
  for (const explicit of [true, false]) {
    await t.test(explicit ? "explicit source path" : "implicit source path", async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-build-source-env-"));
      const deployment = join(dir, "deployment");
      const source = join(dir, "source");
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorDockerContext = process.env.DOCKER_CONTEXT;
      const priorBuildx = process.env.DOCKER_BUILDX_BIN;
      const log = console.log,
        warn = console.warn;
      const priorEnv = new Map<string, string | undefined>();
      try {
        mkdirSync(deployment);
        mkdirSync(join(source, "deploy", "core"), { recursive: true });
        writeFileSync(join(source, "deploy", "core", "Dockerfile"), "FROM scratch\n");
        writeCoreDeployment(deployment, { secretEnv: { core: { GIT_ALIAS: "CUSTOM_SECRET" } } });
        const fake = fakeDocker(dir);
        const gitLog = fakeGit(dir, source);
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.DOCKER_CONTEXT;
        delete process.env.DOCKER_BUILDX_BIN;
        const { config, environmentSource } = loadDockerDeployment(deployment);
        const secrets = computedSecrets(config);
        const valueOf = (name: string): string => {
          if (name === "DATABASE_URL") return "postgres://source-build/db";
          if (name === "DATABASE_CA_CERT") return "certificate\nsource-build-private-body";
          if (["CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET", "SKILL_SIGNING_SECRET"].includes(name)) {
            return `${name.toLowerCase()}-${"x".repeat(40)}`;
          }
          return `source-build-value-${name.toLowerCase()}`;
        };
        const selected = new Map(secrets.map((secret) => [secret.name, valueOf(secret.name)]));
        selected.set("DATABASE_URL", valueOf("DATABASE_URL"));
        writeFileSync(
          join(deployment, ".env"),
          `${[...selected]
            .map(([name, value]) => `${name}=${/[\r\n]/.test(value) ? JSON.stringify(value) : value}`)
            .join("\n")}\n`,
        );
        const ambient = new Map(selected);
        ambient.set("GIT_ALIAS", selected.get("CUSTOM_SECRET")!);
        ambient.set("DATABASE_CA_CERT_FILE", "source-build-host-ca-file");
        ambient.set("GIT_CONFIG_GLOBAL", "source-build-git-config");
        for (const [name, value] of ambient) {
          priorEnv.set(name, process.env[name]);
          process.env[name] = value;
        }
        for (const name of ["BUILDX_GIT_INFO", "BUILDX_GIT_LABELS"]) {
          priorEnv.set(name, process.env[name]);
          process.env[name] = "true";
        }
        console.log = (): void => {};
        console.warn = console.log;
        await dockerUp(config, environmentSource, {
          buildFrom: true,
          ...(explicit ? { buildFromPath: source } : {}),
        });
        const gitEntries = readFileSync(gitLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map(
            (line) =>
              JSON.parse(line) as {
                args: string[];
                keys: string[];
                valueHashes: string[];
              },
          );
        const hiddenNames = new Set([
          ...secrets.map((secret) => secret.name),
          ...secrets.flatMap((secret) => (secret.aliases ?? []).map((alias) => alias.name)),
          "DATABASE_CA_CERT_FILE",
          "DATABASE_URL",
          "GIT_CONFIG_GLOBAL",
        ]);
        const hiddenHashes = [...ambient.values()].map((value) => createHash("sha256").update(value).digest("hex"));
        if (explicit) {
          assert.deepEqual(gitEntries, []);
        } else {
          assert.deepEqual(
            gitEntries.map((entry) => entry.args),
            [["--no-optional-locks", "rev-parse", "--show-toplevel"]],
          );
          for (const entry of gitEntries) {
            for (const name of hiddenNames) assert.ok(!entry.keys.includes(name), `${name} leaked to Git`);
            for (const hash of hiddenHashes) assert.ok(!entry.valueHashes.includes(hash));
          }
        }
        const dockerCalls = readFileSync(fake.argvLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as string[]);
        const builds = dockerCalls.filter((args) => args[0] === "build");
        assert.ok(builds.some((args) => args.includes(source)));
        assert.ok(builds.every((args) => args.includes("--provenance=false")));
        assert.ok(!dockerCalls.some((args) => args.some((arg) => arg.includes("GIT_SHA"))));
        const dockerEntries = readFileSync(fake.envLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map(
            (line) =>
              JSON.parse(line) as {
                controls: Record<string, string | null>;
                keys: string[];
                valueHashes: string[];
              },
          );
        for (const entry of dockerEntries) {
          for (const name of hiddenNames) assert.ok(!entry.keys.includes(name), `${name} leaked to Docker`);
          for (const name of entry.keys) assert.ok(!name.startsWith("GIT_"), `${name} leaked to Docker`);
          for (const hash of hiddenHashes) assert.ok(!entry.valueHashes.includes(hash));
          assert.equal(entry.controls.BUILDX_GIT_INFO, "false");
          assert.equal(entry.controls.BUILDX_GIT_LABELS, "false");
        }
      } finally {
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
        else process.env.DOCKER_CONTEXT = priorDockerContext;
        if (priorBuildx === undefined) delete process.env.DOCKER_BUILDX_BIN;
        else process.env.DOCKER_BUILDX_BIN = priorBuildx;
        for (const [name, value] of priorEnv) {
          if (value === undefined) delete process.env[name];
          else process.env[name] = value;
        }
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker source builds keep the captured Buildx override and fallback after global changes", async (t) => {
  for (const capturedOverride of [true, false]) {
    await t.test(capturedOverride ? "standalone override" : "Docker fallback", async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-buildx-snapshot-"));
      const deployment = join(dir, "deployment");
      const source = join(dir, "source");
      const state = join(dir, "state");
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorDockerContext = process.env.DOCKER_CONTEXT;
      const priorBuildx = process.env.DOCKER_BUILDX_BIN;
      const priorDatabase = process.env.DATABASE_URL;
      const priorState = process.env.XDG_CONFIG_HOME;
      const priorDuplicate = process.env.UNRELATED_FUTURE_DUPLICATE;
      const priorUnknown = process.env.FUTURE_VENDOR_BUILD_CONTROL;
      const log = console.log,
        warn = console.warn;
      let mutation: ReturnType<typeof setTimeout> | undefined;
      const futureValue = "future-deployment-secret-value";
      try {
        mkdirSync(deployment);
        mkdirSync(state);
        mkdirSync(join(source, "deploy", "core"), { recursive: true });
        writeFileSync(join(source, "deploy", "core", "Dockerfile"), "FROM scratch\n");
        writeCoreDeployment(deployment, {
          secretEnv: { core: { FUTURE_RUNTIME_TOKEN: "FUTURE_DEPLOYMENT_SECRET" } },
        });
        const envPath = join(deployment, ".env");
        writeFileSync(
          envPath,
          `${readFileSync(envPath, "utf8")
            .split("\n")
            .filter((line) => !line.startsWith("DATABASE_URL="))
            .join("\n")}FUTURE_DEPLOYMENT_SECRET=${futureValue}\n`,
        );
        const fake = fakeDocker(dir, { waitPostgresOnce: true });
        const initial = fakeBuildx(dir, "captured-buildx");
        const late = fakeBuildx(dir, "late-buildx");
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.DOCKER_CONTEXT;
        delete process.env.DATABASE_URL;
        process.env.XDG_CONFIG_HOME = state;
        process.env.UNRELATED_FUTURE_DUPLICATE = futureValue;
        process.env.FUTURE_VENDOR_BUILD_CONTROL = "unknown-provider-control";
        if (capturedOverride) process.env.DOCKER_BUILDX_BIN = initial.bin;
        else delete process.env.DOCKER_BUILDX_BIN;
        const { config, environmentSource } = loadDockerDeployment(deployment);
        console.log = (): void => {};
        console.warn = console.log;
        mutation = setTimeout(() => {
          process.env.DOCKER_BUILDX_BIN = late.bin;
        }, 100);
        await dockerUp(config, environmentSource, { buildFrom: true, buildFromPath: source });
        assert.ok(existsSync(join(dir, "postgres-waited")));
        assert.equal(readFileSync(late.log, "utf8"), "");
        const selectedNames = new Set([
          ...computedSecrets(config).flatMap((secret) => [
            secret.name,
            ...(secret.aliases ?? []).map((alias) => alias.name),
          ]),
          "DATABASE_URL",
          "POSTGRES_PASSWORD",
        ]);
        const selectedHashes = [
          VALID_CAPABILITY_SECRET,
          "connector".repeat(4),
          "core".repeat(8),
          VALID_PORTAL_IDENTITY_SECRET,
          "skill".repeat(8),
          futureValue,
        ].map((value) => createHash("sha256").update(value).digest("hex"));
        const sourceDockerEnvironments = readFileSync(fake.envLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map(
            (line) =>
              JSON.parse(line) as {
                command: string;
                controls: Record<string, string | null>;
                keys: string[];
                valueHashes: string[];
              },
          )
          .filter((entry) => entry.command === "image" || entry.command === "build");
        assert.ok(sourceDockerEnvironments.some((entry) => entry.command === "image"));
        for (const entry of sourceDockerEnvironments) {
          for (const name of selectedNames) assert.ok(!entry.keys.includes(name));
          assert.ok(!entry.keys.includes("UNRELATED_FUTURE_DUPLICATE"));
          assert.ok(!entry.keys.includes("FUTURE_VENDOR_BUILD_CONTROL"));
          for (const name of entry.keys) assert.ok(!name.startsWith("GIT_"));
          for (const hash of selectedHashes) assert.ok(!entry.valueHashes.includes(hash));
          assert.equal(entry.controls.BUILDX_GIT_INFO, "false");
          assert.equal(entry.controls.BUILDX_GIT_LABELS, "false");
        }
        if (capturedOverride) {
          const entries = readFileSync(initial.log, "utf8")
            .split("\n")
            .filter(Boolean)
            .map(
              (line) =>
                JSON.parse(line) as {
                  args: string[];
                  keys: string[];
                  valueHashes: string[];
                  override: string | null;
                  metadata: { info: string | null; labels: string | null };
                },
            );
          assert.ok(entries.some((entry) => entry.args.includes(source)));
          for (const entry of entries) {
            assert.equal(entry.override, initial.bin);
            assert.ok(entry.args.includes("--provenance=false"));
            for (const name of selectedNames) assert.ok(!entry.keys.includes(name));
            assert.ok(!entry.keys.includes("UNRELATED_FUTURE_DUPLICATE"));
            assert.ok(!entry.keys.includes("FUTURE_VENDOR_BUILD_CONTROL"));
            for (const name of entry.keys) assert.ok(!name.startsWith("GIT_"));
            for (const hash of selectedHashes) assert.ok(!entry.valueHashes.includes(hash));
            assert.deepEqual(entry.metadata, { info: "false", labels: "false" });
          }
        } else {
          assert.equal(readFileSync(initial.log, "utf8"), "");
          const builds = readFileSync(fake.argvLog, "utf8")
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line) as string[])
            .filter((args) => args[0] === "build");
          assert.ok(builds.some((args) => args.includes(source)));
          assert.ok(builds.every((args) => args.includes("--provenance=false")));
          assert.ok(sourceDockerEnvironments.some((entry) => entry.command === "build"));
        }
      } finally {
        if (mutation) clearTimeout(mutation);
        console.log = log;
        console.warn = warn;
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorDockerContext === undefined) delete process.env.DOCKER_CONTEXT;
        else process.env.DOCKER_CONTEXT = priorDockerContext;
        if (priorBuildx === undefined) delete process.env.DOCKER_BUILDX_BIN;
        else process.env.DOCKER_BUILDX_BIN = priorBuildx;
        if (priorDatabase === undefined) delete process.env.DATABASE_URL;
        else process.env.DATABASE_URL = priorDatabase;
        if (priorState === undefined) delete process.env.XDG_CONFIG_HOME;
        else process.env.XDG_CONFIG_HOME = priorState;
        if (priorDuplicate === undefined) delete process.env.UNRELATED_FUTURE_DUPLICATE;
        else process.env.UNRELATED_FUTURE_DUPLICATE = priorDuplicate;
        if (priorUnknown === undefined) delete process.env.FUTURE_VENDOR_BUILD_CONTROL;
        else process.env.FUTURE_VENDOR_BUILD_CONTROL = priorUnknown;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test(
  "managed Postgres: the generated password and DATABASE_URL never reach the docker argv; state.json is 0600",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-pg-"));
    const xdg = mkdtempSync(join(tmpdir(), "qm-docker-secrets-xdg-"));
    const priorPath = process.env.PATH;
    const priorDb = process.env.DATABASE_URL;
    const priorDockerHost = process.env.DOCKER_HOST;
    const priorXdg = process.env.XDG_CONFIG_HOME;
    const priorPgPassword = process.env.POSTGRES_PASSWORD;
    const priorPgDuplicate = process.env.UNRELATED_POSTGRES_VALUE;
    const log = console.log,
      warn = console.warn;
    try {
      writeFileSync(
        join(dir, CONFIG_FILENAME),
        JSON.stringify({
          contract: 1,
          orgId: "sekritpg",
          publicUrl: "http://localhost:8080",
          target: "docker",
          services: ["core"],
        }),
      );
      writeFileSync(
        join(dir, ".env"),
        `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector-key".repeat(3)}\nCORE_SIGNING_SECRET=${"core-sign".repeat(4)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill-sign".repeat(4)}\n`,
      );
      const fake = fakeDocker(dir);
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.XDG_CONFIG_HOME = xdg;
      delete process.env.DATABASE_URL;
      process.env.POSTGRES_PASSWORD = "ambient-postgres-secret";
      process.env.UNRELATED_POSTGRES_VALUE = process.env.POSTGRES_PASSWORD;
      console.log = (): void => {};
      console.warn = console.log;
      const { config, environmentSource } = loadDockerDeployment(dir);
      await dockerUp(config, environmentSource, {});

      const statePath = join(xdg, "qm", "deployments", "sekritpg", "state.json");
      const password = (JSON.parse(readFileSync(statePath, "utf8")) as { pgPassword?: string }).pgPassword;
      assert.ok(password, "the generated pg password is recorded in deployment state");
      assert.equal(statSync(statePath).mode & 0o777, 0o600, "state.json holds the pg password and must be 0600");

      const argv = readFileSync(fake.argvLog, "utf8");
      assert.ok(!argv.includes(password), "the pg password must not reach the docker argv");
      assert.ok(!argv.includes("POSTGRES_PASSWORD"), "POSTGRES_PASSWORD travels via the env-file, not -e");
      assert.ok(!argv.includes("postgres://"), "the derived DATABASE_URL must not reach the docker argv");

      const envFiles = readFileSync(fake.envCopy, "utf8");
      assert.ok(envFiles.includes(`POSTGRES_PASSWORD=${password}`), "pg gets its password via the env-file");
      assert.ok(
        envFiles.includes(`DATABASE_URL=postgres://postgres:${password}@pg:5432/qm`),
        "the core gets DATABASE_URL via the env-file",
      );
      const ambientPasswordHash = createHash("sha256").update("ambient-postgres-secret").digest("hex");
      for (const line of readFileSync(fake.envLog, "utf8").split("\n").filter(Boolean)) {
        const entry = JSON.parse(line) as { keys: string[]; valueHashes: string[] };
        assert.ok(!entry.keys.includes("POSTGRES_PASSWORD"));
        assert.ok(!entry.keys.includes("UNRELATED_POSTGRES_VALUE"));
        assert.ok(!entry.valueHashes.includes(ambientPasswordHash));
      }
    } finally {
      console.log = log;
      console.warn = warn;
      process.env.PATH = priorPath;
      if (priorDb === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = priorDb;
      if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
      else process.env.DOCKER_HOST = priorDockerHost;
      if (priorXdg === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = priorXdg;
      if (priorPgPassword === undefined) delete process.env.POSTGRES_PASSWORD;
      else process.env.POSTGRES_PASSWORD = priorPgPassword;
      if (priorPgDuplicate === undefined) delete process.env.UNRELATED_POSTGRES_VALUE;
      else process.env.UNRELATED_POSTGRES_VALUE = priorPgDuplicate;
      rmSync(dir, { recursive: true, force: true });
      rmSync(xdg, { recursive: true, force: true });
    }
  },
);

test("Docker removes a managed Postgres container when docker run fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-postgres-launch-failure-"));
  const xdg = mkdtempSync(join(tmpdir(), "qm-docker-postgres-launch-xdg-"));
  const priorPath = process.env.PATH;
  const priorDb = process.env.DATABASE_URL;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorFailure = process.env.QM_TEST_DOCKER_FAIL;
  const priorXdg = process.env.XDG_CONFIG_HOME;
  const log = console.log,
    warn = console.warn;
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "pgcleanup",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
      }),
    );
    writeFileSync(
      join(dir, ".env"),
      `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector-key".repeat(3)}\nCORE_SIGNING_SECRET=${"core-sign".repeat(4)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill-sign".repeat(4)}\n`,
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.XDG_CONFIG_HOME = xdg;
    process.env.QM_TEST_DOCKER_FAIL = "postgres-run";
    delete process.env.DATABASE_URL;
    console.log = (): void => {};
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(dockerUp(config, environmentSource, {}), /docker run -d/);
    const calls = readFileSync(fake.argvLog, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    assert.ok(calls.some((args) => args[0] === "run" && args.includes("postgres:16")));
    assert.deepEqual(calls.at(-1)?.slice(0, 3), ["rm", "-f", "qm-pgcleanup-pg"]);
    for (const args of calls) {
      const index = args.indexOf("--env-file");
      if (index !== -1) assert.equal(existsSync(args[index + 1]!), false);
    }
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDb === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = priorDb;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorFailure === undefined) delete process.env.QM_TEST_DOCKER_FAIL;
    else process.env.QM_TEST_DOCKER_FAIL = priorFailure;
    if (priorXdg === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = priorXdg;
    rmSync(dir, { recursive: true, force: true });
    rmSync(xdg, { recursive: true, force: true });
  }
});

test(
  "docker up gates missing required secrets before any container starts while Slack setup remains optional",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-gate-"));
    const priorPath = process.env.PATH;
    const priorDb = process.env.DATABASE_URL;
    const priorDockerHost = process.env.DOCKER_HOST;
    const priorBot = process.env.SLACK_BOT_TOKEN;
    const log = console.log,
      warn = console.warn;
    try {
      writeFileSync(
        join(dir, CONFIG_FILENAME),
        JSON.stringify({
          contract: 1,
          orgId: "sekritgate",
          publicUrl: "http://localhost:8080",
          target: "docker",
          services: ["core", "slack"],
        }),
      );
      writeFileSync(
        join(dir, ".env"),
        `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"a".repeat(32)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSLACK_APP_TOKEN=app\n`,
      );
      const fake = fakeDocker(dir);
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.DATABASE_URL = "postgres://external/db";
      delete process.env.SLACK_BOT_TOKEN;
      console.log = (): void => {};
      console.warn = console.log;
      const { config, environmentSource } = loadDockerDeployment(dir);
      await assert.rejects(dockerUp(config, environmentSource, {}), /Docker deployment secrets.*SKILL_SIGNING_SECRET/);
      assert.equal(readFileSync(fake.argvLog, "utf8"), "");
    } finally {
      console.log = log;
      console.warn = warn;
      process.env.PATH = priorPath;
      if (priorDb === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = priorDb;
      if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
      else process.env.DOCKER_HOST = priorDockerHost;
      if (priorBot !== undefined) process.env.SLACK_BOT_TOKEN = priorBot;
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "Docker copies raw multiline PEM secrets into the container without argv exposure",
  { timeout: 60_000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-pem-"));
    const priorPath = process.env.PATH;
    const priorDockerHost = process.env.DOCKER_HOST;
    const priorCa = process.env.DATABASE_CA_CERT;
    const priorUmask = process.umask();
    const pem = "-----BEGIN CERTIFICATE-----\nraw-certificate-body\n-----END CERTIFICATE-----";
    const log = console.log,
      warn = console.warn;
    try {
      writeFileSync(
        join(dir, CONFIG_FILENAME),
        JSON.stringify({
          contract: 1,
          orgId: "sekritpem",
          publicUrl: "http://localhost:8080",
          target: "docker",
          services: ["core"],
          secretEnv: { core: { OTHER_SECRET: "OTHER_SECRET" } },
        }),
      );
      writeFileSync(
        join(dir, ".env"),
        `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\nDATABASE_CA_CERT="${pem.replaceAll("\n", "\\n")}"\nOTHER_SECRET=still-selected\n`,
      );
      const fake = fakeDocker(dir);
      process.env.PATH = `${dir}:${priorPath}`;
      process.env.DATABASE_CA_CERT = pem;
      process.umask(0o077);
      console.log = (): void => {};
      console.warn = console.log;
      const { config, environmentSource } = loadDockerDeployment(dir);
      await dockerUp(config, environmentSource, {});
      const calls = readFileSync(fake.argvLog, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as string[]);
      const coreRun = calls.find((args) => args[0] === "create" && args.includes("qm-sekritpem-core"));
      assert.ok(coreRun);
      assert.ok(coreRun.includes("DATABASE_CA_CERT_FILE=/app/.qm-database-ca-cert.pem"));
      assert.ok(!coreRun.includes("--env"));
      assert.ok(!coreRun.includes(`DATABASE_CA_CERT=${pem}`));
      assert.ok(!readFileSync(fake.argvLog, "utf8").includes("raw-certificate-body"));
      const copied = readFileSync(fake.envCopy, "utf8");
      assert.ok(copied.includes("copy-mode=444 dir-mode=700"));
      assert.ok(copied.includes("OTHER_SECRET=still-selected"));
      const copiedValue = copied.split("\n").find((line) => line.startsWith("copy="));
      assert.equal(JSON.parse(copiedValue!.slice("copy=".length)), pem);
      const pemHash = createHash("sha256").update(pem).digest("hex");
      for (const line of readFileSync(fake.envLog, "utf8").split("\n").filter(Boolean)) {
        const entry = JSON.parse(line) as { keys: string[]; valueHashes: string[] };
        assert.ok(!entry.keys.includes("DATABASE_CA_CERT"));
        assert.ok(!entry.keys.includes("DATABASE_CA_CERT_FILE"));
        assert.ok(!entry.valueHashes.includes(pemHash));
      }
      writeFileSync(
        join(dir, ".env"),
        `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\nOTHER_SECRET=still-selected\n`,
      );
      delete process.env.DATABASE_CA_CERT;
      await dockerUp(config, environmentSource, {});
      const replacementCalls = readFileSync(fake.argvLog, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as string[]);
      const replacement = replacementCalls
        .filter((args) => args[0] === "run" && args.includes("qm-sekritpem-core"))
        .at(-1);
      assert.ok(replacement);
      assert.ok(!replacement.some((arg) => arg.startsWith("DATABASE_CA_CERT")));
    } finally {
      console.log = log;
      console.warn = warn;
      process.env.PATH = priorPath;
      if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
      else process.env.DOCKER_HOST = priorDockerHost;
      if (priorCa === undefined) delete process.env.DATABASE_CA_CERT;
      else process.env.DATABASE_CA_CERT = priorCa;
      process.umask(priorUmask);
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("Docker rejects placeholder database and optional secret values before any Docker call", async (t) => {
  for (const [label, name, value, expected] of [
    ["DATABASE_URL placeholder", "DATABASE_URL", "replace-me", /Docker deployment secrets.*DATABASE_URL/],
    ["optional secret placeholder", "FUTURE_TOKEN", "replace-me", /Docker deployment secrets.*FUTURE_TOKEN/],
  ] as const) {
    await t.test(label, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-preflight-nl-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
      const priorValue = process.env[name];
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "sekritpreflightnl",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
            plugins: [
              {
                name: "future",
                image: "ghcr.io/acme/future:1",
                secrets: [{ name: "FUTURE_TOKEN", required: false }],
              },
            ],
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\n${name === "FUTURE_TOKEN" ? `${name}=${value}\n` : ""}`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        if (name !== "FUTURE_TOKEN") process.env[name] = value;
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(dockerUp(config, environmentSource, {}), expected);
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
        if (priorValue === undefined) delete process.env[name];
        else process.env[name] = priorValue;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker rejects malformed aliased portal trust secrets before any provider call", async (t) => {
  for (const testCase of [
    {
      name: "external OIDC allowlist during a dry run",
      fields: {
        services: ["core", "portal"],
        env: { core: { HARNESS: "mock" }, portal: { OIDC_CLIENT_ID: "oidc-client-id" } },
        secretEnv: { portal: { OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE" } },
      },
      overrides: { PORTAL_ALLOWLIST_STORE: "not-an-email" },
      dryRun: true,
      expected: /Docker deployment secrets.*OIDC_ALLOWED_EMAILS/,
    },
    {
      name: "built-in auth allowlist during an apply",
      fields: {
        services: ["core", "portal", "auth"],
        env: {
          core: { HARNESS: "mock" },
          auth: { AUTH_EMAIL_TRANSPORT: "resend", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
        },
        secretEnv: { auth: { AUTH_ALLOWED_EMAILS: "BROKER_ALLOWLIST_STORE" } },
      },
      overrides: { BROKER_ALLOWLIST_STORE: "not-an-email" },
      dryRun: false,
      expected: /Docker deployment secrets.*BROKER_ALLOWLIST_STORE/,
    },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-aliased-trust-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "aliasedtrust",
            publicUrl: "http://localhost:8080",
            target: "docker",
            ...testCase.fields,
          }),
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        const { config, environmentSource } = loadDockerDeployment(dir);
        writeCompleteDockerEnvironment(dir, config, testCase.overrides);
        await assert.rejects(dockerUp(config, environmentSource, { dryRun: testCase.dryRun }), testCase.expected);
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(readFileSync(fake.envLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker binds materialized self-API origins before any provider call", async (t) => {
  for (const testCase of ["PUBLIC_API_URL", "AGENT_API_URL"] as const) {
    await t.test(testCase, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-public-api-binding-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      try {
        writeCoreDeployment(dir, {
          apiUrl: "https://api.example.com",
          publicUrl: "https://portal.example.com",
          env: { core: { HARNESS: "pi" } },
          sandbox: { backend: "sprites" },
        });
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        const overriddenConfig: typeof config =
          testCase === "AGENT_API_URL"
            ? { ...config, secretEnv: { core: { AGENT_API_URL: "LEGACY_AGENT_API_URL_SECRET" } } }
            : config;
        writeCompleteDockerEnvironment(dir, overriddenConfig, {
          PUBLIC_API_URL: testCase === "PUBLIC_API_URL" ? "https://attacker.example.com" : "https://api.example.com",
          LEGACY_AGENT_API_URL_SECRET: "https://attacker.example.com",
        });
        await assert.rejects(
          dockerUp(overriddenConfig, environmentSource),
          new RegExp(testCase === "PUBLIC_API_URL" ? "PUBLIC_API_URL" : "LEGACY_AGENT_API_URL_SECRET"),
        );
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(readFileSync(fake.envLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker always renders the canonical self-API origin without a selected local value", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-canonical-public-api-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorPublicApiUrl = process.env.PUBLIC_API_URL;
  const log = console.log,
    warn = console.warn;
  const canonicalApiUrl = "https://api.example.com";
  const attackerApiUrl = "https://attacker.example.com";
  try {
    writeCoreDeployment(dir, {
      apiUrl: canonicalApiUrl,
      publicUrl: "https://portal.example.com",
      env: { core: { HARNESS: "pi" } },
      sandbox: { backend: "sprites" },
    });
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const { config, environmentSource } = loadDockerDeployment(dir);
    const overriddenConfig: typeof config = {
      ...config,
      env: { ...config.env, core: { ...config.env.core, AGENT_API_URL: attackerApiUrl } },
    };
    writeCompleteDockerEnvironment(dir, overriddenConfig);
    writeFileSync(
      join(dir, ".env"),
      `${readFileSync(join(dir, ".env"), "utf8")
        .split("\n")
        .filter((line) => !line.startsWith("PUBLIC_API_URL="))
        .join("\n")}\n`,
    );
    delete process.env.PUBLIC_API_URL;
    assert.doesNotMatch(readFileSync(join(dir, ".env"), "utf8"), /^PUBLIC_API_URL=/m);
    console.log = (): void => {};
    console.warn = console.log;
    await dockerUp(overriddenConfig, environmentSource);
    const launchedEnvironment = `${readFileSync(fake.argvLog, "utf8")}\n${readFileSync(fake.envCopy, "utf8")}`;
    assert.ok(launchedEnvironment.includes(`PUBLIC_API_URL=${canonicalApiUrl}`));
    assert.doesNotMatch(launchedEnvironment, /AGENT_API_URL=/);
    assert.ok(!launchedEnvironment.includes(attackerApiUrl));
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorPublicApiUrl === undefined) delete process.env.PUBLIC_API_URL;
    else process.env.PUBLIC_API_URL = priorPublicApiUrl;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects individually valid secrets that must be distinct before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-secret-equality-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  try {
    writeCoreDeployment(dir);
    const duplicate = "same-secret-value-that-is-long-enough";
    writeFileSync(
      join(dir, ".env"),
      `CAPABILITY_SECRET=${duplicate}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${duplicate}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n`,
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(
      dockerUp(config, environmentSource, {}),
      /Docker deployment secrets.*CAPABILITY_SECRET.*CORE_SIGNING_SECRET/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker reserves DATABASE_CA_CERT_FILE before any provider call", async (t) => {
  for (const [label, fields] of [
    ["ordinary environment", { env: { core: { DATABASE_CA_CERT_FILE: "/tmp/host-secret" } } }],
    ["secret alias", { secretEnv: { core: { DATABASE_CA_CERT_FILE: "CA_FILE_SECRET" } } }],
  ] as const) {
    await t.test(label, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-ca-file-reserved-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "careserved",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
            ...fields,
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCA_FILE_SECRET=value\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        assert.throws(() => loadDockerDeployment(dir), /DATABASE_CA_CERT_FILE.*managed by the core runtime/);
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker rejects a provider control used as a secret-store entry before any provider call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-provider-secret-collision-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorDockerConfig = process.env.DOCKER_CONFIG;
  try {
    writeCoreDeployment(dir, { secretEnv: { core: { WORKLOAD_TOKEN: "DOCKER_CONFIG" } } });
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.DOCKER_CONFIG = join(dir, "provider-config");
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(
      dockerUp(config, environmentSource, {}),
      /DOCKER_CONFIG cannot be used as a Docker secret-store entry/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorDockerConfig === undefined) delete process.env.DOCKER_CONFIG;
    else process.env.DOCKER_CONFIG = priorDockerConfig;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects a provider control whose value equals a selected workload secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-provider-value-collision-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorBuildkitHost = process.env.BUILDKIT_HOST;
  try {
    writeCoreDeployment(dir, { secretEnv: { core: { WORKLOAD_TOKEN: "CUSTOM_SECRET" } } });
    writeFileSync(join(dir, ".env"), `${readFileSync(join(dir, ".env"), "utf8")}CUSTOM_SECRET=provider-collision\n`);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.BUILDKIT_HOST = "provider-collision";
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(
      dockerUp(config, environmentSource, {}),
      /Docker provider control BUILDKIT_HOST must not equal a selected deployment secret/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorBuildkitHost === undefined) delete process.env.BUILDKIT_HOST;
    else process.env.BUILDKIT_HOST = priorBuildkitHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects a provider control whose value equals ambient POSTGRES_PASSWORD", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-provider-postgres-collision-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorBuildkitHost = process.env.BUILDKIT_HOST;
  const priorPgPassword = process.env.POSTGRES_PASSWORD;
  try {
    writeCoreDeployment(dir);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.POSTGRES_PASSWORD = "ambient-postgres-provider-collision";
    process.env.BUILDKIT_HOST = process.env.POSTGRES_PASSWORD;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(
      dockerUp(config, environmentSource, {}),
      /Docker provider control BUILDKIT_HOST must not equal a selected deployment secret/,
    );
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorBuildkitHost === undefined) delete process.env.BUILDKIT_HOST;
    else process.env.BUILDKIT_HOST = priorBuildkitHost;
    if (priorPgPassword === undefined) delete process.env.POSTGRES_PASSWORD;
    else process.env.POSTGRES_PASSWORD = priorPgPassword;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects plaintext config fallbacks for deployment secrets before provider calls", async (t) => {
  const value = "plaintext-config-secret";
  for (const testCase of [
    { name: "core secret", fields: { env: { core: { DATABASE_CA_CERT: value } } } },
    {
      name: "optional plugin secret",
      fields: {
        plugins: [
          {
            name: "future",
            image: "ghcr.io/acme/future:1",
            env: { FUTURE_TOKEN: value },
            secrets: [{ name: "FUTURE_TOKEN", required: false }],
          },
        ],
      },
    },
  ] as const) {
    await t.test(testCase.name, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-plaintext-secret-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      try {
        writeCoreDeployment(dir, testCase.fields);
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(dockerUp(config, environmentSource, {}), /configured as plaintext/);
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(readFileSync(fake.envLog, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker removes a multiline-CA container when create, copy, or start fails", async (t) => {
  for (const stage of ["create", "cp", "start"] as const) {
    await t.test(stage, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-ca-launch-failure-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorFailure = process.env.QM_TEST_DOCKER_FAIL;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "cafailure",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\nDATABASE_CA_CERT="certificate\\nbody"\n`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        process.env.QM_TEST_DOCKER_FAIL = stage;
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(dockerUp(config, environmentSource, {}), new RegExp(`docker ${stage}`));
        const calls = readFileSync(fake.argvLog, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line) as string[]);
        assert.ok(calls.some((args) => args[0] === "create" && args.includes("qm-cafailure-core")));
        assert.ok(calls.some((args) => args[0] === stage));
        assert.deepEqual(calls.at(-1)?.slice(0, 4), ["rm", "-f", "qm-cafailure-core"]);
        for (const args of calls) {
          const envFile = args[args.indexOf("--env-file") + 1];
          if (args.includes("--env-file")) assert.equal(existsSync(envFile!), false);
          if (args[0] === "cp") assert.equal(existsSync(args[1]!), false);
        }
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorFailure === undefined) delete process.env.QM_TEST_DOCKER_FAIL;
        else process.env.QM_TEST_DOCKER_FAIL = priorFailure;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker reports both launch and cleanup failure without exposing the copied secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-ca-cleanup-failure-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorFailure = process.env.QM_TEST_DOCKER_FAIL;
  const pem = "certificate\nprivate-body";
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "cacleanupfailure",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
      }),
    );
    writeFileSync(
      join(dir, ".env"),
      `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\nDATABASE_CA_CERT="${pem.replaceAll("\n", "\\n")}"\n`,
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    process.env.QM_TEST_DOCKER_FAIL = "create-cleanup";
    const { config, environmentSource } = loadDockerDeployment(dir);
    let message = "";
    try {
      await dockerUp(config, environmentSource, {});
      assert.fail("Docker launch should fail");
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    assert.match(message, /launch failed.*cleanup also failed/s);
    assert.ok(!message.includes(pem));
    const calls = readFileSync(fake.argvLog, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
    assert.deepEqual(calls.at(-1)?.slice(0, 3), ["rm", "-f", "qm-cacleanupfailure-core"]);
    for (const args of calls) {
      const index = args.indexOf("--env-file");
      if (index !== -1) assert.equal(existsSync(args[index + 1]!), false);
    }
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorFailure === undefined) delete process.env.QM_TEST_DOCKER_FAIL;
    else process.env.QM_TEST_DOCKER_FAIL = priorFailure;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker rejects NUL in single-line and multiline secrets before any Docker call", async (t) => {
  for (const [label, name, value] of [
    ["single-line future token", "FUTURE_TOKEN", "left\0right"],
    [
      "multiline database CA",
      "DATABASE_CA_CERT",
      "-----BEGIN CERTIFICATE-----\nleft\0right\n-----END CERTIFICATE-----",
    ],
  ] as const) {
    await t.test(label, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-preflight-nul-"));
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
      const priorValue = process.env[name];
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "sekritpreflightnul",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
            plugins: [
              {
                name: "future",
                image: "ghcr.io/acme/future:1",
                secrets: [{ name: "FUTURE_TOKEN", required: false }],
              },
            ],
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n${name}=${name === "DATABASE_CA_CERT" ? `"${value.replaceAll("\n", "\\n")}"` : value}\n`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        delete process.env[name];
        const { config, environmentSource } = loadDockerDeployment(dir);
        await assert.rejects(dockerUp(config, environmentSource, {}), new RegExp(`${name} contains a NUL byte`));
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
        if (priorValue === undefined) delete process.env[name];
        else process.env[name] = priorValue;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker rejects multiline provider-control runtime aliases before any hook or Docker execution", async (t) => {
  for (const runtimeName of [
    "PATH",
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "BASH_ENV",
    "DOCKER_CONFIG",
  ] as const) {
    await t.test(runtimeName, async () => {
      const dir = mkdtempSync(join(tmpdir(), "qm-docker-provider-env-hook-"));
      const attackBin = join(dir, "attack-bin");
      const hook = join(dir, "hook.js");
      const sentinel = join(dir, "hook-ran");
      const sourceName = `WORKLOAD_${runtimeName}`;
      const priorPath = process.env.PATH;
      const priorDockerHost = process.env.DOCKER_HOST;
      const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
      mkdirSync(attackBin);
      writeFileSync(join(attackBin, "docker"), `#!/bin/sh\nprintf invoked > ${JSON.stringify(sentinel)}\nexit 99\n`);
      chmodSync(join(attackBin, "docker"), 0o755);
      writeFileSync(hook, `require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "invoked")\n`);
      let value = `${hook}\nignored`;
      if (runtimeName === "PATH") value = `${attackBin}:${priorPath}\nignored`;
      if (runtimeName === "NODE_OPTIONS") value = `--require=${hook}\n--trace-warnings`;
      try {
        writeFileSync(
          join(dir, CONFIG_FILENAME),
          JSON.stringify({
            contract: 1,
            orgId: "providerhook",
            publicUrl: "http://localhost:8080",
            target: "docker",
            services: ["core"],
            secretEnv: { core: { [runtimeName]: sourceName } },
          }),
        );
        writeFileSync(
          join(dir, ".env"),
          `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n${sourceName}="${value.replaceAll("\n", "\\n")}"\n`,
        );
        const fake = fakeDocker(dir);
        process.env.PATH = `${dir}:${priorPath}`;
        delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        await assert.rejects(
          async () => {
            const { config, environmentSource } = loadDockerDeployment(dir);
            await dockerUp(config, environmentSource, {});
          },
          runtimeName === "PATH" || runtimeName === "DOCKER_CONFIG"
            ? new RegExp(`${sourceName} cannot contain CR or LF`)
            : new RegExp(`${runtimeName}.*managed by the core runtime`),
        );
        assert.equal(readFileSync(fake.argvLog, "utf8"), "");
        assert.equal(readFileSync(fake.envCopy, "utf8"), "");
        assert.equal(existsSync(sentinel), false);
      } finally {
        process.env.PATH = priorPath;
        if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
        else process.env.DOCKER_HOST = priorDockerHost;
        if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
        else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});

test("Docker validates colliding per-workload secret values before any Docker call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-secrets-collision-nl-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const priorMode = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  const priorCoreValue = process.env.CORE_COLLISION_SECRET;
  const priorPluginValue = process.env.COLLISION_TOKEN;
  try {
    writeFileSync(
      join(dir, CONFIG_FILENAME),
      JSON.stringify({
        contract: 1,
        orgId: "sekritcollisionnl",
        publicUrl: "http://localhost:8080",
        target: "docker",
        services: ["core"],
        plugins: [
          {
            name: "collision",
            image: "ghcr.io/acme/collision:1",
            secrets: [{ name: "COLLISION_TOKEN" }],
          },
        ],
        secretEnv: { core: { COLLISION_TOKEN: "CORE_COLLISION_SECRET" } },
      }),
    );
    writeFileSync(
      join(dir, ".env"),
      `CAPABILITY_SECRET=${VALID_CAPABILITY_SECRET}\nCONNECTOR_SECRET_KEY=${"connector".repeat(4)}\nCORE_SIGNING_SECRET=${"core".repeat(8)}\nPORTAL_IDENTITY_SECRET=${VALID_PORTAL_IDENTITY_SECRET}\nSKILL_SIGNING_SECRET=${"skill".repeat(8)}\nDATABASE_URL=postgres://external/db\n`,
    );
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    process.env.CORE_COLLISION_SECRET = "replace-me";
    process.env.COLLISION_TOKEN = "good-plugin-value";
    const { config, environmentSource } = loadDockerDeployment(dir);
    await assert.rejects(dockerUp(config, environmentSource, {}), /Docker deployment secrets.*CORE_COLLISION_SECRET/);
    assert.equal(readFileSync(fake.argvLog, "utf8"), "");
    assert.equal(readFileSync(fake.envCopy, "utf8"), "");
  } finally {
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    if (priorMode === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorMode;
    if (priorCoreValue === undefined) delete process.env.CORE_COLLISION_SECRET;
    else process.env.CORE_COLLISION_SECRET = priorCoreValue;
    if (priorPluginValue === undefined) delete process.env.COLLISION_TOKEN;
    else process.env.COLLISION_TOKEN = priorPluginValue;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker preserves __proto__ as a literal secret environment name", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-proto-secret-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const log = console.log,
    warn = console.warn;
  try {
    writeCoreDeployment(dir, {
      secretEnv: { core: Object.fromEntries([["__proto__", "PROTO_SECRET"]]) },
    });
    writeFileSync(join(dir, ".env"), `${readFileSync(join(dir, ".env"), "utf8")}PROTO_SECRET=literal-proto-value\n`);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    console.log = (): void => {};
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await dockerUp(config, environmentSource, {});
    assert.match(readFileSync(fake.envCopy, "utf8"), /^__proto__=literal-proto-value$/m);
    assert.ok(!readFileSync(fake.argvLog, "utf8").includes("literal-proto-value"));
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker keeps equal-valued managed and configured environment out of argv", { timeout: 60_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-docker-secret-value-argv-"));
  const priorPath = process.env.PATH;
  const priorDockerHost = process.env.DOCKER_HOST;
  const log = console.log,
    warn = console.warn;
  try {
    writeCoreDeployment(dir, {
      env: { core: { VISIBLE_COLLISION: "production" } },
      plugins: [
        {
          name: "collision",
          image: "ghcr.io/acme/collision:1",
          env: { PLUGIN_VISIBLE_COLLISION: "production" },
          secrets: [{ name: "PLUGIN_SECRET" }],
        },
      ],
    });
    writeFileSync(join(dir, ".env"), `${readFileSync(join(dir, ".env"), "utf8")}PLUGIN_SECRET=production\n`);
    const fake = fakeDocker(dir);
    process.env.PATH = `${dir}:${priorPath}`;
    console.log = (): void => {};
    console.warn = console.log;
    const { config, environmentSource } = loadDockerDeployment(dir);
    await dockerUp(config, environmentSource);
    assert.ok(!readFileSync(fake.argvLog, "utf8").includes("production"));
    const envFiles = readFileSync(fake.envCopy, "utf8");
    assert.match(envFiles, /^NODE_ENV=production$/m);
    assert.match(envFiles, /^VISIBLE_COLLISION=production$/m);
    assert.match(envFiles, /^PLUGIN_VISIBLE_COLLISION=production$/m);
    assert.match(envFiles, /^PLUGIN_SECRET=production$/m);
  } finally {
    console.log = log;
    console.warn = warn;
    process.env.PATH = priorPath;
    if (priorDockerHost === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = priorDockerHost;
    rmSync(dir, { recursive: true, force: true });
  }
});
