import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  doctorCommon,
  localDoctorSecrets,
  requiredSlackScopes,
  slackManifestBotScopes,
} from "../src/backends/doctor.ts";
import { flyDoctor, verifyLocalFlyTokens } from "../src/backends/fly.ts";
import { validatePortalTrust, type QmConfig } from "../src/config.ts";
import { computedSecrets } from "../src/secrets.ts";

const TEST_CONFIG_IDENTITY = { dev: -1n, ino: -1n };

const config: QmConfig = {
  contract: 1,
  orgId: "acme",
  publicUrl: "http://localhost:8080",
  target: "docker",
  services: ["core"],
  plugins: [],
  skills: [],
  env: { core: { HARNESS: "pi" } },
  imageOverrides: {},
  sandbox: { backend: "local" },
};

const flyConfig: QmConfig = {
  ...config,
  target: "fly",
  appPrefix: "acme",
  region: "sjc",
  flyOrg: "personal",
  sandbox: { backend: "sprites", namePrefix: "acme-sandboxes" },
};

function requiredDoctorSecrets(config: QmConfig, overrides: Record<string, string> = {}): Map<string, string> {
  const values = new Map(
    computedSecrets(config)
      .filter((secret) => secret.required)
      .map((secret, index) => [secret.name, `${secret.name}-${index}-`.repeat(4)]),
  );
  if (values.has("AUTH_SIGNING_JWK")) {
    values.set(
      "AUTH_SIGNING_JWK",
      JSON.stringify(generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" })),
    );
  }
  if (values.has("AUTH_EMAIL_FROM")) values.set("AUTH_EMAIL_FROM", "Acme <sender@example.com>");
  if (values.has("AUTH_ALLOWED_EMAILS")) values.set("AUTH_ALLOWED_EMAILS", "user@example.com");
  if (values.has("PUBLIC_API_URL")) values.set("PUBLIC_API_URL", config.apiUrl ?? config.publicUrl);
  for (const [name, value] of Object.entries(overrides)) values.set(name, value);
  return values;
}

test("Docker doctor rejects missing and placeholder required secrets before external probes", async () => {
  const prior = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = "";
  try {
    await assert.rejects(
      doctorCommon(config, new Map([["CORE_SIGNING_SECRET", "replace-me"]]), { requiredSecretValues: true }),
      /CAPABILITY_SECRET, CONNECTOR_SECRET_KEY, CORE_SIGNING_SECRET, PORTAL_IDENTITY_SECRET, PUBLIC_API_URL, SKILL_SIGNING_SECRET/,
    );
  } finally {
    if (prior === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prior;
  }
});

test("doctor allows deferred Slack setup but rejects a partial token pair", async () => {
  const { sandbox: _sandbox, ...withoutSandbox } = config;
  void _sandbox;
  const deferredConfig: QmConfig = {
    ...withoutSandbox,
    services: ["core", "slack"],
    env: { core: { HARNESS: "mock" } },
  };
  const required = new Map([
    ["CAPABILITY_SECRET", "a".repeat(64)],
    ["CONNECTOR_SECRET_KEY", "b".repeat(64)],
    ["CORE_SIGNING_SECRET", "c".repeat(64)],
    ["PORTAL_IDENTITY_SECRET", "d".repeat(64)],
    ["SKILL_SIGNING_SECRET", "e".repeat(64)],
  ]);
  await assert.doesNotReject(doctorCommon(deferredConfig, required, { requiredSecretValues: true }));
  await assert.rejects(
    doctorCommon(deferredConfig, new Map([...required, ["SLACK_BOT_TOKEN", "xoxb-only"]]), {
      requiredSecretValues: true,
    }),
    /both SLACK_BOT_TOKEN and SLACK_APP_TOKEN/,
  );
});

test("doctor rejects security keys that the runtime requires to be distinct", async () => {
  const runtimeConfig: QmConfig = { ...config, env: { core: { HARNESS: "mock" } } };
  const required = new Map(
    computedSecrets(runtimeConfig)
      .filter((secret) => secret.required)
      .map((secret, index) => [secret.name, `${secret.name}-${index}`.repeat(4)]),
  );
  required.set("CAPABILITY_SECRET", required.get("CORE_SIGNING_SECRET")!);
  await assert.rejects(
    doctorCommon(runtimeConfig, required, { requiredSecretValues: true }),
    /CAPABILITY_SECRET.*CORE_SIGNING_SECRET|CORE_SIGNING_SECRET.*CAPABILITY_SECRET/,
  );
});

test("doctor rejects missing and placeholder portal OIDC client ids and tenant gates", async () => {
  const { sandbox: _sandbox, ...withoutSandbox } = config;
  void _sandbox;
  const portalConfig: QmConfig = {
    ...withoutSandbox,
    services: ["core", "portal"],
    env: { portal: { OIDC_CLIENT_ID: "replace-me" } },
  };
  for (const oidcClientId of ["", "   "]) {
    await assert.rejects(
      doctorCommon({ ...portalConfig, env: { portal: { OIDC_CLIENT_ID: oidcClientId } } }, new Map()),
      /would receive secret env OIDC_CLIENT_ID.*configured as plaintext/,
    );
  }
  for (const oidcClientId of ["replace-me", " replace-me "]) {
    await assert.rejects(
      doctorCommon({ ...portalConfig, env: { portal: { OIDC_CLIENT_ID: oidcClientId } } }, new Map()),
      /OIDC_CLIENT_ID may not be a placeholder/,
    );
  }
  await assert.rejects(
    doctorCommon(
      { ...portalConfig, env: { portal: { OIDC_CLIENT_ID: "real-client-id", PORTAL_EXPECTED_TEAM_ID: " " } } },
      new Map(),
    ),
    /would receive secret env PORTAL_EXPECTED_TEAM_ID.*configured as plaintext/,
  );
  const rejectedGates: Array<Record<string, string>> = [
    { PORTAL_EXPECTED_TEAM_ID: "replace-me", OIDC_ALLOWED_EMAIL_DOMAIN: "todo" },
  ];
  for (const gate of rejectedGates) {
    await assert.rejects(
      doctorCommon({ ...portalConfig, env: { portal: { OIDC_CLIENT_ID: "real-client-id", ...gate } } }, new Map()),
      /must be a valid, non-placeholder email domain|may not be a placeholder/,
    );
  }
  const acceptedGates: Array<Record<string, string>> = [
    { OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
    { PORTAL_EXPECTED_TEAM_ID: "T123" },
    { OIDC_ALLOWED_EMAIL_DOMAIN: "example.com", PORTAL_EXPECTED_TEAM_ID: "T123" },
  ];
  for (const gate of acceptedGates) {
    await assert.doesNotReject(
      doctorCommon({ ...portalConfig, env: { portal: { OIDC_CLIENT_ID: "real-client-id", ...gate } } }, new Map()),
    );
  }
  assert.doesNotThrow(() =>
    validatePortalTrust(
      { ...portalConfig, env: { portal: {} } },
      "config",
      new Map([
        ["OIDC_CLIENT_ID", "secret-client"],
        ["PORTAL_EXPECTED_TEAM_ID", "T123"],
      ]),
    ),
  );
  assert.throws(
    () => validatePortalTrust({ ...portalConfig, env: { portal: {} } }, "config", new Map()),
    /OIDC_CLIENT_ID in env\.portal or the target secret store/,
  );
});

test("doctor resolves portal trust from unaliased and aliased deployment secrets", async () => {
  const unaliased: QmConfig = {
    ...config,
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
  };
  const aliased: QmConfig = {
    ...unaliased,
    secretEnv: {
      portal: {
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
        PORTAL_EXPECTED_TEAM_ID: "PORTAL_TEAM_STORE",
      },
    },
  };
  await assert.doesNotReject(
    doctorCommon(
      unaliased,
      requiredDoctorSecrets(unaliased, { OIDC_CLIENT_ID: "client-id", PORTAL_EXPECTED_TEAM_ID: "T123" }),
      { requiredSecretValues: true },
    ),
  );
  await assert.doesNotReject(
    doctorCommon(
      aliased,
      requiredDoctorSecrets(aliased, { PORTAL_CLIENT_STORE: "client-id", PORTAL_TEAM_STORE: "T123" }),
      { requiredSecretValues: true },
    ),
  );
});

test("doctor validates locally available aliased portal trust without authoritative secret values", async () => {
  const aliased: QmConfig = {
    ...config,
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
    secretEnv: {
      portal: {
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
        PORTAL_EXPECTED_TEAM_ID: "PORTAL_TEAM_STORE",
      },
    },
  };
  const logged: string[] = [];
  const warned: string[] = [];
  const priorLog = console.log;
  const priorWarn = console.warn;
  console.log = (...parts: unknown[]): void => void logged.push(parts.join(" "));
  console.warn = (...parts: unknown[]): void => void warned.push(parts.join(" "));
  try {
    await doctorCommon(
      aliased,
      new Map([
        ["PORTAL_CLIENT_STORE", "client-id"],
        ["PORTAL_TEAM_STORE", "T123"],
      ]),
    );
    assert.ok(logged.some((line) => line.includes("portal OIDC client and tenant trust boundary: ok")));
    assert.ok(!warned.some((line) => line.includes("unverified/write-only")));
  } finally {
    console.log = priorLog;
    console.warn = priorWarn;
  }
});

test("doctor reports unavailable required portal trust values as unverified and never ok", async () => {
  const aliased: QmConfig = {
    ...config,
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
    secretEnv: {
      portal: {
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
        PORTAL_EXPECTED_TEAM_ID: "PORTAL_TEAM_STORE",
      },
    },
  };
  const logged: string[] = [];
  const warned: string[] = [];
  const priorLog = console.log;
  const priorWarn = console.warn;
  console.log = (...parts: unknown[]): void => void logged.push(parts.join(" "));
  console.warn = (...parts: unknown[]): void => void warned.push(parts.join(" "));
  try {
    await doctorCommon(aliased, new Map([["PORTAL_CLIENT_STORE", "client-id"]]));
    assert.ok(
      warned.some(
        (line) =>
          line.includes("unverified/write-only") &&
          line.includes("PORTAL_TEAM_STORE") &&
          line.includes("portal.PORTAL_EXPECTED_TEAM_ID"),
      ),
      `warned: ${warned.join(" | ")}`,
    );
    assert.ok(!logged.some((line) => line.includes("trust boundary: ok")), `logged: ${logged.join(" | ")}`);
  } finally {
    console.log = priorLog;
    console.warn = priorWarn;
  }
});

test("doctor rejects any locally available aliased trust value before external probes", async () => {
  const aliased: QmConfig = {
    ...config,
    modelProvider: "openrouter",
    services: ["core", "portal", "slack"],
    env: { core: { HARNESS: "pi" } },
    secretEnv: {
      portal: {
        OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE",
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
      },
    },
  };
  const priorFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      doctorCommon(
        aliased,
        new Map([
          ["OPENROUTER_API_KEY", "openrouter-key"],
          ["PORTAL_ALLOWLIST_STORE", "not-an-email"],
          ["PORTAL_CLIENT_STORE", "client-id"],
          ["SLACK_APP_TOKEN", "xapp-test"],
          ["SLACK_BOT_TOKEN", "xoxb-test"],
        ]),
      ),
      /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = priorFetch;
  }
});

test("doctor validates aliased portal trust values before Slack or model provider probes", async () => {
  const aliased: QmConfig = {
    ...config,
    modelProvider: "openrouter",
    services: ["core", "portal", "slack"],
    env: { core: { HARNESS: "pi" } },
    secretEnv: {
      portal: {
        OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE",
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
      },
    },
  };
  const priorFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      doctorCommon(
        aliased,
        requiredDoctorSecrets(aliased, {
          OPENROUTER_API_KEY: "openrouter-key",
          PORTAL_ALLOWLIST_STORE: "not-an-email",
          PORTAL_CLIENT_STORE: "client-id",
          SLACK_APP_TOKEN: "xapp-test",
          SLACK_BOT_TOKEN: "xoxb-test",
        }),
        { requiredSecretValues: true },
      ),
      /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = priorFetch;
  }
});

test("doctor resolves an aliased broker trust domain before email-provider checks", async () => {
  const aliased: QmConfig = {
    ...config,
    services: ["core", "portal", "auth"],
    env: { core: { HARNESS: "mock" }, auth: { AUTH_EMAIL_TRANSPORT: "resend" } },
    secretEnv: { auth: { AUTH_ALLOWED_EMAIL_DOMAIN: "BROKER_DOMAIN_STORE" } },
  };
  const priorFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  try {
    await assert.rejects(
      doctorCommon(aliased, new Map([["BROKER_DOMAIN_STORE", "not a domain"]])),
      /AUTH_ALLOWED_EMAIL_DOMAIN must be a valid, non-placeholder email domain/,
    );
    await assert.rejects(
      doctorCommon(aliased, requiredDoctorSecrets(aliased, { BROKER_DOMAIN_STORE: "not a domain" }), {
        requiredSecretValues: true,
      }),
      /AUTH_ALLOWED_EMAIL_DOMAIN must be a valid, non-placeholder email domain/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = priorFetch;
  }
});

test("doctor reports an unavailable broker allowlist as unverified and never ok", async () => {
  const broker: QmConfig = {
    ...config,
    services: ["core", "portal", "auth"],
    env: { core: { HARNESS: "mock" }, auth: { AUTH_EMAIL_TRANSPORT: "resend" } },
  };
  const logged: string[] = [];
  const warned: string[] = [];
  const priorLog = console.log;
  const priorWarn = console.warn;
  console.log = (...parts: unknown[]): void => void logged.push(parts.join(" "));
  console.warn = (...parts: unknown[]): void => void warned.push(parts.join(" "));
  try {
    await doctorCommon(broker, new Map());
    assert.ok(
      warned.some(
        (line) =>
          line.includes("unverified/write-only") &&
          line.includes("AUTH_ALLOWED_EMAILS") &&
          line.includes("auth.AUTH_ALLOWED_EMAILS"),
      ),
      `warned: ${warned.join(" | ")}`,
    );
    assert.ok(!logged.some((line) => line.includes("trust boundary: ok")), `logged: ${logged.join(" | ")}`);
  } finally {
    console.log = priorLog;
    console.warn = priorWarn;
  }
});

test("doctor probes only the effective model provider override and key", async () => {
  const overridden: QmConfig = {
    ...config,
    modelProvider: "anthropic",
    env: { core: { HARNESS: "pi", MODEL_PROVIDER: "openrouter" } },
  };
  const priorFetch = globalThis.fetch;
  const seen: Array<{ url: string; authorization: string | null; anthropicKey: string | null }> = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    seen.push({
      url: String(input),
      authorization: headers.get("authorization"),
      anthropicKey: headers.get("x-api-key"),
    });
    return new Response(null, { status: 200 });
  }) as typeof fetch;
  try {
    await doctorCommon(
      overridden,
      new Map([
        ["ANTHROPIC_API_KEY", "anthropic-key"],
        ["OPENROUTER_API_KEY", "openrouter-key"],
      ]),
    );
    assert.deepEqual(seen, [
      {
        url: "https://openrouter.ai/api/v1/key",
        authorization: "Bearer openrouter-key",
        anthropicKey: null,
      },
    ]);
  } finally {
    globalThis.fetch = priorFetch;
  }
});

test("doctor rejects auth sender addresses with the runtime grammar without echoing them", async () => {
  const authConfig: QmConfig = {
    ...config,
    services: ["core", "portal", "auth"],
    env: {
      core: { HARNESS: "mock" },
      auth: { AUTH_EMAIL_TRANSPORT: "smtp", AUTH_ALLOWED_EMAIL_DOMAIN: "example.com" },
    },
  };
  const secrets = new Map(
    computedSecrets(authConfig)
      .filter((secret) => secret.required)
      .map((secret) => [secret.name, "x".repeat(64)]),
  );
  const value = "Private Name <not-an-address>";
  secrets.set("AUTH_EMAIL_FROM", value);
  await assert.rejects(doctorCommon(authConfig, secrets, { requiredSecretValues: true }), (error: unknown) => {
    assert.match((error as Error).message, /required secrets.*AUTH_EMAIL_FROM/);
    assert.doesNotMatch((error as Error).message, /Private Name/);
    return true;
  });
});

test("Fly doctor requires the signing secret for source plugins absent from config", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-doctor-"));
  const bin = join(dir, "fake-fly.cjs");
  const prior = process.env.FLY_BIN;
  mkdirSync(join(dir, "plugins", "linear"), { recursive: true });
  writeFileSync(join(dir, "plugins", "linear", "Dockerfile"), "FROM scratch\n");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
const app = args[args.indexOf("-a") + 1];
const names = app === "acme-core" ? ["CAPABILITY_SECRET", "CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET", "PORTAL_IDENTITY_SECRET", "SKILL_SIGNING_SECRET", "SPRITES_TOKEN"] : [];
process.stdout.write(JSON.stringify(names.map((Name) => ({ Name }))));
`,
  );
  chmodSync(bin, 0o755);
  process.env.FLY_BIN = bin;
  try {
    await assert.rejects(
      flyDoctor(flyConfig, dir, undefined, TEST_CONFIG_IDENTITY),
      /acme-linear: missing CORE_SIGNING_SECRET/,
    );
  } finally {
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly doctor requires the Sprites token on core", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-doctor-sprites-"));
  const bin = join(dir, "fake-fly.cjs");
  const prior = process.env.FLY_BIN;
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
const app = args[args.indexOf("-a") + 1];
const names = app === "acme-core" ? ["CAPABILITY_SECRET", "CONNECTOR_SECRET_KEY", "CORE_SIGNING_SECRET", "PORTAL_IDENTITY_SECRET", "PUBLIC_API_URL", "SKILL_SIGNING_SECRET"] : [];
process.stdout.write(JSON.stringify(names.map((Name) => ({ Name }))));
`,
  );
  chmodSync(bin, 0o755);
  process.env.FLY_BIN = bin;
  try {
    await assert.rejects(
      flyDoctor(flyConfig, dir, undefined, TEST_CONFIG_IDENTITY),
      /acme-core: missing SPRITES_TOKEN/,
    );
  } finally {
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly doctor reports apps that are not created yet as pending, not missing secrets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-fly-doctor-predeploy-"));
  const bin = join(dir, "fake-fly.cjs");
  const prior = process.env.FLY_BIN;
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "secrets" && args[1] === "list") {
  process.stderr.write("Error: app not found");
  process.exit(1);
}
process.exit(0);
`,
  );
  chmodSync(bin, 0o755);
  process.env.FLY_BIN = bin;
  const log = console.log;
  const lines: string[] = [];
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await assert.doesNotReject(flyDoctor(flyConfig, dir, undefined, TEST_CONFIG_IDENTITY));
    assert.ok(
      lines.some((line) => line.includes("acme-core: not created yet")),
      `printed: ${lines.join(" | ")}`,
    );
    assert.ok(!lines.some((line) => line.includes("missing")), `printed: ${lines.join(" | ")}`);
  } finally {
    console.log = log;
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("doctor reads the deployment's slack-app-manifest.yml scopes, falling back to the template", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-manifest-"));
  try {
    const templateScopes = requiredSlackScopes();
    assert.ok(templateScopes.includes("chat:write"), "template scopes parse");
    assert.deepEqual(requiredSlackScopes(dir), templateScopes, "no deployment manifest → template");
    writeFileSync(
      join(dir, "slack-app-manifest.yml"),
      [
        "display_information:",
        "  name: acme Agent",
        "oauth_config:",
        "  scopes:",
        "    bot:",
        "      - chat:write",
        "      - custom:scope",
        "settings:",
        "  socket_mode_enabled: true",
      ].join("\n"),
    );
    assert.deepEqual(requiredSlackScopes(dir), ["chat:write", "custom:scope"], "deployment manifest wins");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("requiredSlackScopes warns when the deployment manifest lags the template's scopes, and stays quiet on a superset", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-stale-"));
  const lines: string[] = [];
  const priorWarn = console.warn;
  console.warn = (...args: unknown[]): void => void lines.push(args.join(" "));
  try {
    const templateScopes = requiredSlackScopes();
    writeFileSync(join(dir, "slack-app-manifest.yml"), "oauth_config:\n  scopes:\n    bot:\n      - chat:write\n");
    requiredSlackScopes(dir);
    assert.equal(lines.length, 1, "a lagging manifest draws exactly one warning");
    for (const scope of templateScopes.filter((s) => s !== "chat:write")) {
      assert.ok(lines[0]!.includes(scope), `warning names missing scope ${scope}`);
    }
    lines.length = 0;
    writeFileSync(
      join(dir, "slack-app-manifest.yml"),
      JSON.stringify({ oauth_config: { scopes: { bot: [...templateScopes, "custom:extra"] } } }),
    );
    assert.deepEqual(requiredSlackScopes(dir), [...templateScopes, "custom:extra"]);
    assert.deepEqual(lines, [], "a superset manifest draws no warning");
  } finally {
    console.warn = priorWarn;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slackManifestBotScopes reads both YAML and JSON manifests", () => {
  assert.deepEqual(slackManifestBotScopes('{"oauth_config":{"scopes":{"bot":["a:b","c:d"]}}}'), ["a:b", "c:d"]);
  assert.deepEqual(slackManifestBotScopes('oauth_config:\n  scopes:\n    bot:\n      - a:b\n      - "c:d"\n'), [
    "a:b",
    "c:d",
  ]);
});

test("slackManifestBotScopes parses inline-flow lists, quoted or not", () => {
  assert.deepEqual(slackManifestBotScopes("oauth_config:\n  scopes:\n    bot: [a:b, \"c:d\", 'e:f']\n"), [
    "a:b",
    "c:d",
    "e:f",
  ]);
  assert.deepEqual(slackManifestBotScopes("oauth_config:\n  scopes:\n    bot: [chat:write]  # keep in sync\n"), [
    "chat:write",
  ]);
});

test("slackManifestBotScopes does not truncate on comments inside a block list", () => {
  const yaml = [
    "oauth_config:",
    "  scopes:",
    "    bot:",
    "      - chat:write",
    "      # socket mode needs this",
    "      - users:read  # directory sync",
    '      - "channels:history"',
    "settings:",
    "  socket_mode_enabled: true",
  ].join("\n");
  assert.deepEqual(slackManifestBotScopes(yaml), ["chat:write", "users:read", "channels:history"]);
});

test("requiredSlackScopes throws when a manifest exists but zero scopes parse", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-zeroscope-"));
  try {
    writeFileSync(join(dir, "slack-app-manifest.yml"), "display_information:\n  name: acme Agent\n");
    assert.throws(() => requiredSlackScopes(dir), /no bot scopes parse/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const SLACK_TOKENS = new Map([
  ["SLACK_BOT_TOKEN", "xoxb-test"],
  ["SLACK_APP_TOKEN", "xapp-test"],
]);

function slackConfig(): QmConfig {
  const { sandbox: _sandbox, ...rest } = config;
  void _sandbox;
  return { ...rest, services: ["core", "slack"], env: {} };
}

function manifestDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-fetch-"));
  writeFileSync(
    join(dir, "slack-app-manifest.yml"),
    "oauth_config:\n  scopes:\n    bot:\n      - chat:write\n      - users:read\n",
  );
  return dir;
}

async function withStubbedSlack<T>(responses: { auth: Response; socket?: Response }, fn: () => Promise<T>): Promise<T> {
  const priorFetch = globalThis.fetch;
  const priorBot = process.env.SLACK_BOT_TOKEN;
  const priorApp = process.env.SLACK_APP_TOKEN;
  delete process.env.SLACK_BOT_TOKEN;
  delete process.env.SLACK_APP_TOKEN;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === "https://slack.com/api/auth.test") return responses.auth;
    if (url === "https://slack.com/api/apps.connections.open") {
      return responses.socket ?? new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    return await fn();
  } finally {
    globalThis.fetch = priorFetch;
    if (priorBot !== undefined) process.env.SLACK_BOT_TOKEN = priorBot;
    if (priorApp !== undefined) process.env.SLACK_APP_TOKEN = priorApp;
  }
}

const authOk = (scopes?: string): Response =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: scopes === undefined ? {} : { "x-oauth-scopes": scopes },
  });

test("slackCheck passes when granted scopes are a superset of the manifest's", async () => {
  const dir = manifestDir();
  try {
    await withStubbedSlack({ auth: authOk("chat:write, users:read, extra:scope") }, () =>
      doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir }),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Slack HTTP mode validates the bot and scopes without an app token or Socket Mode call", async () => {
  const dir = manifestDir();
  const http: QmConfig = {
    ...slackConfig(),
    env: { slack: { SLACK_EVENTS_MODE: "http", SLACK_EVENTS_PORT: "3001" } },
  };
  const seen: string[] = [];
  const priorFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    seen.push(url);
    if (url === "https://slack.com/api/auth.test") return authOk("chat:write, users:read");
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    await doctorCommon(
      http,
      new Map([
        ["SLACK_BOT_TOKEN", "xoxb-test"],
        ["SLACK_SIGNING_SECRET", "signing-secret"],
      ]),
      { configDir: dir },
    );
    assert.deepEqual(seen, ["https://slack.com/api/auth.test"]);
  } finally {
    globalThis.fetch = priorFetch;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Slack HTTP mode requires an effective events port from 1 through 65535 before network access", async () => {
  const priorFetch = globalThis.fetch;
  const priorFileOnly = process.env.QM_DEPLOY_ENV_FILE_ONLY;
  process.env.QM_DEPLOY_ENV_FILE_ONLY = "1";
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return authOk("chat:write, users:read");
  }) as typeof fetch;
  try {
    for (const port of [undefined, "", "0", "-1", "1.5", "65536", "not-a-number"]) {
      const http: QmConfig = {
        ...slackConfig(),
        env: { slack: { SLACK_EVENTS_MODE: "http", ...(port === undefined ? {} : { SLACK_EVENTS_PORT: port }) } },
      };
      await assert.rejects(
        doctorCommon(
          http,
          new Map([
            ["SLACK_BOT_TOKEN", "xoxb-test"],
            ["SLACK_SIGNING_SECRET", "signing-secret"],
          ]),
        ),
        /SLACK_EVENTS_PORT to be an integer from 1 to 65535/,
      );
    }
    for (const port of ["1", "65535"]) {
      await assert.doesNotReject(
        doctorCommon(
          { ...slackConfig(), env: { slack: { SLACK_EVENTS_MODE: "http", SLACK_EVENTS_PORT: port } } },
          new Map(),
        ),
      );
    }
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = priorFetch;
    if (priorFileOnly === undefined) delete process.env.QM_DEPLOY_ENV_FILE_ONLY;
    else process.env.QM_DEPLOY_ENV_FILE_ONLY = priorFileOnly;
  }
});

test("core Slack events settings override folded virtual-service settings", async () => {
  const dir = manifestDir();
  const socket: QmConfig = {
    ...slackConfig(),
    env: {
      slack: { SLACK_EVENTS_MODE: "http", SLACK_EVENTS_PORT: "3001" },
      core: { SLACK_EVENTS_MODE: "socket" },
    },
  };
  const seen: string[] = [];
  const priorFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    seen.push(url);
    if (url === "https://slack.com/api/auth.test") return authOk("chat:write, users:read");
    if (url === "https://slack.com/api/apps.connections.open") {
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    await doctorCommon(socket, SLACK_TOKENS, { configDir: dir });
    assert.deepEqual(seen, ["https://slack.com/api/auth.test", "https://slack.com/api/apps.connections.open"]);
  } finally {
    globalThis.fetch = priorFetch;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Slack doctor validates deployment-file tokens before conflicting ambient tokens", async () => {
  const dir = manifestDir();
  const priorFetch = globalThis.fetch;
  const priorBot = process.env.SLACK_BOT_TOKEN;
  const priorApp = process.env.SLACK_APP_TOKEN;
  process.env.SLACK_BOT_TOKEN = "xoxb-ambient";
  process.env.SLACK_APP_TOKEN = "xapp-ambient";
  const seen: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    seen.push(new Headers(init?.headers).get("authorization") ?? "");
    const url = String(input);
    return url.endsWith("/auth.test")
      ? authOk("chat:write, users:read")
      : new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof fetch;
  try {
    await doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir });
    assert.deepEqual(seen, ["Bearer xoxb-test", "Bearer xapp-test"]);
  } finally {
    globalThis.fetch = priorFetch;
    if (priorBot === undefined) delete process.env.SLACK_BOT_TOKEN;
    else process.env.SLACK_BOT_TOKEN = priorBot;
    if (priorApp === undefined) delete process.env.SLACK_APP_TOKEN;
    else process.env.SLACK_APP_TOKEN = priorApp;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slackCheck fails naming each manifest scope the token lacks", async () => {
  const dir = manifestDir();
  try {
    await withStubbedSlack({ auth: authOk("chat:write") }, () =>
      assert.rejects(doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir }), /missing scopes: users:read/),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slackCheck surfaces a rejected bot token with Slack's error code", async () => {
  const dir = manifestDir();
  try {
    await withStubbedSlack(
      { auth: new Response(JSON.stringify({ ok: false, error: "invalid_auth" }), { status: 200 }) },
      () =>
        assert.rejects(
          doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir }),
          /bot token rejected \(invalid_auth\)/,
        ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slackCheck treats a missing x-oauth-scopes header as zero granted scopes, not a pass", async () => {
  const dir = manifestDir();
  try {
    await withStubbedSlack({ auth: authOk() }, () =>
      assert.rejects(
        doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir }),
        /missing scopes: chat:write, users:read/,
      ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("slackCheck rejects a bad Socket Mode app token even when the bot token passes", async () => {
  const dir = manifestDir();
  try {
    await withStubbedSlack(
      {
        auth: authOk("chat:write, users:read"),
        socket: new Response(JSON.stringify({ ok: false, error: "invalid_auth" }), { status: 200 }),
      },
      () =>
        assert.rejects(
          doctorCommon(slackConfig(), SLACK_TOKENS, { configDir: dir }),
          /app token rejected \(invalid_auth\)/,
        ),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Docker doctor treats a missing sandbox block as the local default", async () => {
  const { sandbox: _sandbox, ...rest } = config;
  void _sandbox;
  const noSandbox: QmConfig = { ...rest, env: {} };
  const priorFly = process.env.FLY_BIN;
  process.env.FLY_BIN = "/nonexistent/fly-should-never-run";
  const log = console.log;
  const lines: string[] = [];
  console.log = (...parts: unknown[]): void => void lines.push(parts.join(" "));
  try {
    await doctorCommon(
      noSandbox,
      new Map([
        ["CAPABILITY_SECRET", "capability-value".repeat(3)],
        ["CONNECTOR_SECRET_KEY", "connector-value".repeat(3)],
        ["CORE_SIGNING_SECRET", "source-value".repeat(4)],
        ["PORTAL_IDENTITY_SECRET", "identity-value".repeat(3)],
        ["SKILL_SIGNING_SECRET", "skill-value".repeat(4)],
      ]),
      { requiredSecretValues: true },
    );
    assert.ok(
      lines.some((line) => line.includes("local Docker sandbox: configured")),
      `printed: ${lines.join(" | ")}`,
    );
  } finally {
    console.log = log;
    if (priorFly === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = priorFly;
  }
});

test("an explicitly named --env-file that does not exist is a bad-path error, not 'secrets missing'", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-envfile-"));
  try {
    assert.throws(() => localDoctorSecrets(dir, join(dir, "nope.env"), TEST_CONFIG_IDENTITY), /--env-file not found/);
    assert.deepEqual(
      localDoctorSecrets(dir, undefined, TEST_CONFIG_IDENTITY),
      new Map(),
      "a missing default ./.env is still fine",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an explicit doctor env file is read from one descriptor across delete and replacement races", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-envfile-race-"));
  const path = join(dir, "secrets.env");
  const doctorUrl = new URL("../src/backends/doctor.ts", import.meta.url).href;
  try {
    for (const mode of ["delete", "swap"]) {
      writeFileSync(path, "CORE_SIGNING_SECRET=original\n");
      const result = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `const fs=(await import("node:fs")).default;const {syncBuiltinESMExports}=await import("node:module");const target=process.argv[1],mode=process.argv[2],exists=fs.existsSync,open=fs.openSync;let prechecked=false,changed=false;const change=()=>{changed=true;if(mode==="delete")fs.unlinkSync(target);else{fs.renameSync(target,target+".original");fs.writeFileSync(target,"CORE_SIGNING_SECRET=replacement\\n")}};fs.existsSync=function(path){const present=exists.call(this,path);if(path===target&&present&&!changed){prechecked=true;change()}return present};fs.openSync=function(path,...args){const descriptor=open.call(this,path,...args);if(path===target&&!prechecked&&!changed)change();return descriptor};syncBuiltinESMExports();const {localDoctorSecrets}=await import(${JSON.stringify(doctorUrl)});const values=localDoctorSecrets(process.cwd(),target,{dev:-1n,ino:-1n});if(values.get("CORE_SIGNING_SECRET")!=="original"||!changed)throw new Error("explicit env file was not descriptor-authoritative")`,
          path,
          mode,
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0, `${mode}: ${result.stderr || result.stdout}`);
      rmSync(`${path}.original`, { force: true });
      rmSync(path, { force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("fly doctor reports a missing flyctl before trying `fly secrets list`", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-nofly-"));
  const prior = process.env.FLY_BIN;
  process.env.FLY_BIN = "/nonexistent/flyctl";
  try {
    await assert.rejects(flyDoctor(flyConfig, dir, undefined, TEST_CONFIG_IDENTITY), /flyctl not found/);
  } finally {
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Fly doctor probes only the separate deploy-provider token", () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-fly-token-"));
  const bin = join(dir, "fake-fly.cjs");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
if (process.env.FLY_API_TOKEN === "FlyV1-good") process.exit(0);
process.stderr.write("unauthorized FlyV1-expired");
process.exit(1);
`,
  );
  chmodSync(bin, 0o755);
  const prior = process.env.FLY_BIN;
  process.env.FLY_BIN = bin;
  const flyConfig: QmConfig = {
    ...config,
    target: "fly",
    appPrefix: "acme",
    region: "sjc",
    flyOrg: "personal",
  };
  try {
    assert.doesNotThrow(() => verifyLocalFlyTokens(flyConfig, new Map([["SPRITES_TOKEN", "expired"]])));
    const publisher = {
      ...flyConfig,
      env: { ...flyConfig.env, core: { ...flyConfig.env.core, DEPLOY_PROVIDER: "fly" } },
    };
    assert.throws(
      () => verifyLocalFlyTokens(publisher, new Map([["FLY_DEPLOY_API_TOKEN", "FlyV1-expired"]])),
      /FLY_DEPLOY_API_TOKEN was rejected/,
    );
    assert.doesNotThrow(() => verifyLocalFlyTokens(publisher, new Map([["FLY_DEPLOY_API_TOKEN", "FlyV1-good"]])));
  } finally {
    if (prior === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("doctor without required local values warns-and-skips the live Slack check (fly path)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qm-doctor-skip-"));
  const bin = join(dir, "fake-fly.cjs");
  writeFileSync(bin, "#!/usr/bin/env node\nprocess.exit(0);\n");
  chmodSync(bin, 0o755);
  const priorFly = process.env.FLY_BIN;
  const priorBot = process.env.SLACK_BOT_TOKEN;
  const priorApp = process.env.SLACK_APP_TOKEN;
  process.env.FLY_BIN = bin;
  delete process.env.SLACK_BOT_TOKEN;
  delete process.env.SLACK_APP_TOKEN;
  const warnLog = console.warn;
  const warned: string[] = [];
  console.warn = (...parts: unknown[]): void => void warned.push(parts.join(" "));
  try {
    await doctorCommon({ ...config, services: ["core", "slack"] }, new Map(), { configDir: dir });
    assert.ok(
      warned.some((line) => line.includes("skipping the live Slack check")),
      `warned: ${warned.join(" | ")}`,
    );
    await assert.rejects(
      doctorCommon({ ...config, services: ["core", "slack"] }, new Map(), {
        requiredSecretValues: true,
        configDir: dir,
      }),
      /required secrets are missing/,
    );
  } finally {
    console.warn = warnLog;
    if (priorFly === undefined) delete process.env.FLY_BIN;
    else process.env.FLY_BIN = priorFly;
    if (priorBot !== undefined) process.env.SLACK_BOT_TOKEN = priorBot;
    if (priorApp !== undefined) process.env.SLACK_APP_TOKEN = priorApp;
    rmSync(dir, { recursive: true, force: true });
  }
});
