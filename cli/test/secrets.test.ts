import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sandboxCoreEnv, type QmConfig } from "../src/config.ts";
import { FLY_TEMPLATE_ENV_DEFAULTS } from "../src/target-env-defaults.ts";
import {
  computedSecrets,
  materializeSecretValues,
  renderEnvExample,
  runtimeSecretNames,
  secretConditionSelectors,
  secretDestinations,
  secretsForService,
  validateCompleteSecretValues,
  type ComputedSecret,
} from "../src/secrets.ts";
import { isReservedContainerName, pluginNameError, SERVICE_NAMES } from "../src/services.ts";

function makeConfig(overrides: Partial<QmConfig> = {}): QmConfig {
  return {
    contract: 1,
    orgId: "acme",
    publicUrl: "http://localhost:8080",
    target: "docker",
    services: ["core"],
    plugins: [],
    skills: [],
    env: {},
    imageOverrides: {},
    ...overrides,
  };
}

function secretByName(config: QmConfig, name: string): ComputedSecret {
  const secret = computedSecrets(config).find((s) => s.name === name);
  assert.ok(secret, `computed secret ${name} exists`);
  return secret;
}

function completeOperatorValues(config: QmConfig, overrides: Record<string, string> = {}): Map<string, string> {
  const values = new Map(
    computedSecrets(config)
      .filter((secret) => secret.required && secret.managedBy === "operator")
      .map((secret, index) => [secret.name, `${secret.name}-${index}-`.repeat(4)]),
  );
  for (const [name, value] of Object.entries(overrides)) values.set(name, value);
  return values;
}

test("every conditional secret selector has an explicit comparison mode", () => {
  assert.deepEqual(secretConditionSelectors(), [
    { service: "auth", name: "AUTH_ALLOWED_EMAIL_DOMAIN", mode: "presence-only" },
    { service: "auth", name: "AUTH_EMAIL_TRANSPORT", mode: "value-inspected" },
    { service: "core", name: "AWS_DEPLOY_APPS_DOMAIN", mode: "presence-only" },
    { service: "core", name: "CODEX_AUTH_CREDENTIAL", mode: "presence-only" },
    { service: "core", name: "DEPLOY_APPS_DOMAIN", mode: "presence-only" },
    { service: "core", name: "DEPLOY_PROVIDER", mode: "value-inspected" },
    { service: "core", name: "DROPBOX_OAUTH_CLIENT_ID", mode: "presence-only" },
    { service: "core", name: "GOOGLE_OAUTH_CLIENT_ID", mode: "presence-only" },
    { service: "core", name: "HARNESS", mode: "value-inspected" },
    { service: "core", name: "LINEAR_OAUTH_CLIENT_ID", mode: "presence-only" },
    { service: "core", name: "MODEL_PROVIDER", mode: "value-inspected" },
    { service: "core", name: "SANDBOX_BACKEND", mode: "value-inspected" },
    { service: "core", name: "SANDBOX_SECONDARY_BACKEND", mode: "value-inspected" },
    { service: "portal", name: "OIDC_ALLOWED_EMAIL_DOMAIN", mode: "presence-only" },
    { service: "portal", name: "OIDC_ALLOWED_EMAILS", mode: "presence-only" },
    { service: "portal", name: "OIDC_CLIENT_ID", mode: "presence-only" },
    { service: "portal", name: "PORTAL_EXPECTED_TEAM_ID", mode: "presence-only" },
    { service: "slack", name: "SLACK_EVENTS_MODE", mode: "value-inspected" },
  ]);
});

test("a virtual-only secret keeps its plain name on core (the virtual service runs in-process)", () => {
  const config = makeConfig({ services: ["core", "slack"] });
  const secret = secretByName(config, "SLACK_APP_TOKEN");
  assert.deepEqual(runtimeSecretNames("core", secret), ["SLACK_APP_TOKEN"]);
  assert.ok(secretsForService(config, "core").some((s) => s.name === "SLACK_APP_TOKEN"));
});

test("secretEnv aliases follow enabled virtual services to their runtime workload", () => {
  const enabled = makeConfig({
    services: ["core", "slack"],
    secretEnv: { slack: { FLY_API_TOKEN: "CURRENT_FLY_TOKEN" } },
  });
  assert.deepEqual(runtimeSecretNames("core", secretByName(enabled, "CURRENT_FLY_TOKEN")), ["FLY_API_TOKEN"]);

  const disabled = makeConfig({ secretEnv: { slack: { FLY_API_TOKEN: "DISABLED_FLY_TOKEN" } } });
  assert.ok(!computedSecrets(disabled).some((secret) => secret.name === "DISABLED_FLY_TOKEN"));

  const nonCore = makeConfig({
    services: ["core", "admin"],
    secretEnv: { admin: { FLY_API_TOKEN: "ADMIN_FLY_TOKEN" } },
  });
  const adminSecret = secretByName(nonCore, "ADMIN_FLY_TOKEN");
  assert.deepEqual(runtimeSecretNames("admin", adminSecret), ["FLY_API_TOKEN"]);
  assert.deepEqual(runtimeSecretNames("core", adminSecret), []);
});

test("split security keys are required and routed only to their trust boundary", () => {
  const config = makeConfig({ services: ["core", "portal"] });
  for (const name of ["CAPABILITY_SECRET", "CONNECTOR_SECRET_KEY"] as const) {
    const secret = secretByName(config, name);
    assert.equal(secret.required, true);
    assert.deepEqual([...secretDestinations(secret).keys()], ["core"]);
  }
  const identity = secretByName(config, "PORTAL_IDENTITY_SECRET");
  assert.equal(identity.required, true);
  assert.deepEqual([...secretDestinations(identity).keys()].sort(), ["core", "portal"]);
  const example = renderEnvExample(config);
  for (const name of ["CORE_SIGNING_SECRET", "CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET", "CONNECTOR_SECRET_KEY"]) {
    assert.match(example, new RegExp(`^${name}=$`, "m"));
  }
});

test("portal deployment coordinates can come from the target secret store", () => {
  const secretBacked = makeConfig({ services: ["core", "portal"], env: { portal: { OIDC_PRINCIPAL_CLAIM: "email" } } });
  for (const name of ["OIDC_CLIENT_ID", "PORTAL_EXPECTED_TEAM_ID"]) {
    const secret = secretByName(secretBacked, name);
    assert.equal(secret.required, true);
    assert.deepEqual(runtimeSecretNames("portal", secret), [name]);
  }

  const configured = makeConfig({
    services: ["core", "portal"],
    env: { portal: { OIDC_CLIENT_ID: "client", OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" } },
  });
  assert.ok(!computedSecrets(configured).some((secret) => secret.name === "OIDC_CLIENT_ID"));
  assert.ok(!computedSecrets(configured).some((secret) => secret.name === "PORTAL_EXPECTED_TEAM_ID"));
});

test("portal deployments require a real initial administrator seed", () => {
  const hosted = makeConfig({
    services: ["core", "portal"],
    secretEnv: { core: { ADMIN_GRANTS: "ADMIN_GRANTS" } },
  });
  const secret = secretByName(hosted, "ADMIN_GRANTS");
  assert.equal(secret.required, true);
  assert.deepEqual(runtimeSecretNames("core", secret), ["ADMIN_GRANTS"]);
  assert.ok(!computedSecrets(makeConfig()).some((item) => item.name === "ADMIN_GRANTS"));
});

test("a plugin secret lands plain on the plugin's own workload, nowhere else", () => {
  const config = makeConfig({
    plugins: [{ name: "linear", image: "ghcr.io/x:1", secrets: [{ name: "PLUG_TOKEN" }] }],
  });
  const secret = secretByName(config, "PLUG_TOKEN");
  assert.deepEqual(runtimeSecretNames("linear", secret), ["PLUG_TOKEN"]);
  assert.deepEqual(runtimeSecretNames("core", secret), []);
  assert.deepEqual([...secretDestinations(secret).keys()], ["linear"]);
});

test("discovered source plugins (absent from config.plugins) get CORE_SIGNING_SECRET routed to them", () => {
  const config = makeConfig();
  const signing = secretByName(config, "CORE_SIGNING_SECRET");
  assert.deepEqual(runtimeSecretNames("srcplug", signing), [], "not routed without discovery");
  assert.deepEqual(runtimeSecretNames("srcplug", signing, ["srcplug"]), ["CORE_SIGNING_SECRET"]);
  assert.ok(secretsForService(config, "srcplug", ["srcplug"]).some((s) => s.name === "CORE_SIGNING_SECRET"));
  const other = secretByName(config, "SKILL_SIGNING_SECRET");
  assert.deepEqual(
    runtimeSecretNames("srcplug", other, ["srcplug"]),
    [],
    "only the signing secret fans out to plugins",
  );
});

test("SLACK_SIGNING_SECRET joins the secret set only in HTTP events mode (socket mode never verifies request signatures)", () => {
  const socket = makeConfig({ services: ["core", "slack"] });
  assert.ok(
    !computedSecrets(socket).some((s) => s.name === "SLACK_SIGNING_SECRET"),
    "absent in the default socket mode",
  );
  const http = makeConfig({ services: ["core", "slack"], env: { slack: { SLACK_EVENTS_MODE: "http" } } });
  assert.ok(secretByName(http, "SLACK_SIGNING_SECRET").required);
});

test('"sandbox" is a reserved name — a plugin may not shadow the sandbox pseudo-service', () => {
  assert.ok(isReservedContainerName("sandbox"));
  assert.match(pluginNameError("sandbox") ?? "", /reserved/);
});

test("model credentials are optional at deploy time because Admin onboarding can configure them", () => {
  const fly = makeConfig({ target: "fly" });
  assert.equal(secretByName(fly, "ANTHROPIC_API_KEY").required, false);
  const flyMock = makeConfig({ target: "fly", env: { core: { HARNESS: "mock" } } });
  assert.equal(secretByName(flyMock, "ANTHROPIC_API_KEY").required, false);
  const docker = makeConfig();
  assert.equal(secretByName(docker, "ANTHROPIC_API_KEY").required, false);
});

test("Fly requires the Sprites token without translating it to Fly Machines credentials", () => {
  const sprites = secretByName(makeConfig({ target: "fly" }), "SPRITES_TOKEN");
  assert.ok(sprites.required);
  assert.deepEqual(runtimeSecretNames("core", sprites), ["SPRITES_TOKEN"]);
  assert.ok(!computedSecrets(makeConfig({ target: "fly" })).some((secret) => secret.name === "FLY_API_TOKEN"));
});

test("the Fly publisher token appears only for the separate Fly deploy provider", () => {
  assert.ok(!computedSecrets(makeConfig({ target: "fly" })).some((secret) => secret.name === "FLY_DEPLOY_API_TOKEN"));
  assert.ok(
    secretByName(makeConfig({ target: "fly", env: { core: { DEPLOY_PROVIDER: "fly" } } }), "FLY_DEPLOY_API_TOKEN")
      .required,
  );
  for (const config of [makeConfig(), makeConfig({ target: "aws" })]) {
    assert.ok(!computedSecrets(config).some((secret) => secret.name === "FLY_DEPLOY_API_TOKEN"));
  }
});

test("the sprites token is a catalog secret when the sandbox backend is sprites", () => {
  assert.ok(
    secretByName(makeConfig({ sandbox: { backend: "sprites", namePrefix: "acme-sb" } }), "SPRITES_TOKEN").required,
  );
  assert.ok(
    secretByName(makeConfig({ target: "aws", sandbox: { backend: "sprites", namePrefix: "acme-sb" } }), "SPRITES_TOKEN")
      .required,
  );
  assert.ok(
    !computedSecrets(makeConfig({ target: "aws", sandbox: { backend: "aws" } })).some(
      (secret) => secret.name === "SPRITES_TOKEN",
    ),
  );
});

test("Porter and smolmachines runtime selections require their own substrate token", () => {
  const porter = makeConfig({ env: { core: { SANDBOX_BACKEND: "porter" } } });
  assert.ok(secretByName(porter, "PORTER_DEPLOY_API_TOKEN").required);
  assert.ok(!computedSecrets(porter).some((secret) => secret.name === "SPRITES_TOKEN"));
  const smolmachines = makeConfig({ env: { core: { SANDBOX_BACKEND: "smolmachines" } } });
  assert.ok(secretByName(smolmachines, "SMOLMACHINES_TOKEN").required);
  assert.ok(!computedSecrets(smolmachines).some((secret) => secret.name === "SPRITES_TOKEN"));
});

test("secondary sandbox backends require only their own substrate token", () => {
  const cases = [
    ["sprites", "SPRITES_TOKEN"],
    ["smolmachines", "SMOLMACHINES_TOKEN"],
    ["porter", "PORTER_DEPLOY_API_TOKEN"],
  ] as const;
  const substrateTokens = cases.map(([, name]) => name);

  for (const [backend, expected] of cases) {
    const config = makeConfig({ env: { core: { SANDBOX_SECONDARY_BACKEND: backend } } });
    const selected = computedSecrets(config)
      .filter((secret) => secret.required && substrateTokens.includes(secret.name as (typeof substrateTokens)[number]))
      .map((secret) => secret.name);
    assert.deepEqual(selected, [expected], `${backend} selects ${expected}`);
  }
});

test("naming a base model provider makes that provider's key a required deployment secret", () => {
  for (const [provider, key] of [
    ["anthropic", "ANTHROPIC_API_KEY"],
    ["openai", "OPENAI_API_KEY"],
    ["openrouter", "OPENROUTER_API_KEY"],
  ] as const) {
    const config = makeConfig({ modelProvider: provider });
    assert.equal(secretByName(config, key).required, true, `${provider} requires ${key}`);
    assert.match(
      renderEnvExample(config),
      new RegExp(`^${key}=$`, "m"),
      `${key} is uncommented in .env.example so setup collects it`,
    );
  }
});

test("the providers a deployment did not select stay optional", () => {
  const anthropic = makeConfig({ modelProvider: "anthropic" });
  assert.equal(secretByName(anthropic, "OPENROUTER_API_KEY").required, false);
  // OPENAI_API_KEY keeps its own Codex rule, so it is absent rather than optional here.
  assert.ok(!computedSecrets(anthropic).some((secret) => secret.name === "OPENAI_API_KEY"));
});

test("an OpenAI base model and the Codex harness agree on one required key", () => {
  const both = makeConfig({ modelProvider: "openai", env: { core: { HARNESS: "codex" } } });
  const matches = computedSecrets(both).filter((secret) => secret.name === "OPENAI_API_KEY");
  assert.equal(matches.length, 1, "overlapping rules collapse to a single secret");
  assert.equal(matches[0]!.required, true);
});

test("only secret-backed Codex credentials waive the OpenAI API key", () => {
  const credential = makeConfig({
    modelProvider: "openai",
    env: { core: { HARNESS: "codex" } },
    secretEnv: { core: { CODEX_AUTH_CREDENTIAL: "CODEX_AUTH_CREDENTIAL" } },
  });
  assert.ok(!computedSecrets(credential).some((secret) => secret.name === "OPENAI_API_KEY"));
  assert.ok(secretByName(credential, "CODEX_AUTH_CREDENTIAL").required);

  const file = makeConfig({
    modelProvider: "openai",
    env: { core: { HARNESS: "codex", CODEX_AUTH_FILE: "/run/secrets/codex-auth.json" } },
  });
  assert.ok(secretByName(file, "OPENAI_API_KEY").required);
});

test("omitting modelProvider preserves the pre-existing deferred-to-Admin behavior", () => {
  const deferred = makeConfig();
  assert.equal(secretByName(deferred, "ANTHROPIC_API_KEY").required, false);
  assert.equal(secretByName(deferred, "OPENROUTER_API_KEY").required, false);
});

test("model credentials follow the trimmed runtime provider override", () => {
  const cases = [
    ["unset", makeConfig(), []],
    ["top-level", makeConfig({ modelProvider: "anthropic" }), ["ANTHROPIC_API_KEY"]],
    [
      "overridden",
      makeConfig({ modelProvider: "anthropic", env: { core: { MODEL_PROVIDER: "  openrouter  " } } }),
      ["OPENROUTER_API_KEY"],
    ],
  ] as const;
  const providerKeys = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"];

  for (const [label, config, expected] of cases) {
    const selected = computedSecrets(config)
      .filter((secret) => secret.required && providerKeys.includes(secret.name))
      .map((secret) => secret.name);
    assert.deepEqual(selected, expected, label);
  }
});

test("conditional secret values use the runtime's trimmed enum semantics", () => {
  const pi = makeConfig({ env: { core: { HARNESS: "  pi  " } } });
  assert.equal(secretByName(pi, "ANTHROPIC_API_KEY").required, false);
  assert.ok(secretByName(pi, "PUBLIC_API_URL").required);

  const slack = makeConfig({ services: ["core", "slack"], env: { slack: { SLACK_EVENTS_MODE: "  http  " } } });
  assert.ok(secretByName(slack, "SLACK_SIGNING_SECRET").required);
});

test("only virtual service selectors fold into core secret conditions", () => {
  const cases = [
    ["MODEL_PROVIDER", "openrouter", "OPENROUTER_API_KEY"],
    ["HARNESS", "codex", "OPENAI_API_KEY"],
    ["SANDBOX_SECONDARY_BACKEND", "porter", "PORTER_DEPLOY_API_TOKEN"],
    ["GOOGLE_OAUTH_CLIENT_ID", "client-id", "GOOGLE_OAUTH_CLIENT_SECRET"],
  ] as const;
  for (const service of ["slack", "web-ui", "admin"] as const) {
    for (const [selector, value, dependent] of cases) {
      const config = makeConfig({
        services: ["core", service],
        env: { [service]: { [selector]: value } },
      });
      assert.equal(
        computedSecrets(config).some((secret) => secret.name === dependent && secret.required),
        service === "slack",
        `${service}.${selector}`,
      );
    }
  }
});

test("core selector values override folded virtual values", () => {
  const provider = makeConfig({
    services: ["core", "slack"],
    modelProvider: "openai",
    env: { core: { MODEL_PROVIDER: "anthropic" }, slack: { MODEL_PROVIDER: "openrouter" } },
  });
  const requiredProviderKeys = computedSecrets(provider)
    .filter(
      (secret) =>
        secret.required && ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"].includes(secret.name),
    )
    .map((secret) => secret.name);
  assert.deepEqual(requiredProviderKeys, ["ANTHROPIC_API_KEY"]);

  const sandbox = makeConfig({
    services: ["core", "slack"],
    env: {
      core: { SANDBOX_SECONDARY_BACKEND: "sprites" },
      slack: { SANDBOX_SECONDARY_BACKEND: "porter" },
    },
  });
  assert.ok(secretByName(sandbox, "SPRITES_TOKEN").required);
  assert.ok(!computedSecrets(sandbox).some((secret) => secret.name === "PORTER_DEPLOY_API_TOKEN"));

  const harness = makeConfig({
    services: ["core", "slack"],
    env: {
      core: { HARNESS: "mock", SLACK_EVENTS_MODE: "socket" },
      slack: { HARNESS: "codex", SLACK_EVENTS_MODE: "http" },
    },
  });
  assert.ok(!computedSecrets(harness).some((secret) => secret.name === "OPENAI_API_KEY"));
  assert.ok(!computedSecrets(harness).some((secret) => secret.name === "SLACK_SIGNING_SECRET"));
});

test("AWS public app domains require and route their gate secret to core", () => {
  const disabled = makeConfig({ target: "aws" });
  assert.ok(!computedSecrets(disabled).some((secret) => secret.name === "AWS_DEPLOY_GATE_SECRET"));

  const enabled = makeConfig({ target: "aws", env: { core: { AWS_DEPLOY_APPS_DOMAIN: "apps.example.com" } } });
  const gate = secretByName(enabled, "AWS_DEPLOY_GATE_SECRET");
  assert.equal(gate.required, true);
  assert.deepEqual(runtimeSecretNames("core", gate), ["AWS_DEPLOY_GATE_SECRET"]);
  assert.ok(renderEnvExample(enabled).includes("AWS_DEPLOY_GATE_SECRET="));
});

test("gated portal apps share one strong session secret with core", () => {
  for (const domainName of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    const config = makeConfig({
      publicUrl: "https://portal.example.com",
      services: ["core", "portal", "auth"],
      env: {
        core: { [domainName]: "apps.portal.example.com" },
        auth: { AUTH_ALLOWED_EMAIL_DOMAIN: "example.com", AUTH_EMAIL_TRANSPORT: "resend" },
      },
    });
    const session = secretByName(config, "PORTAL_SESSION_SECRET");
    assert.deepEqual(runtimeSecretNames("core", session), ["DEPLOY_APPS_SESSION_SECRET"]);
    assert.deepEqual(runtimeSecretNames("portal", session), ["PORTAL_SESSION_SECRET"]);
    const value = "s".repeat(32);
    const materialized = materializeSecretValues(config, new Map([["PORTAL_SESSION_SECRET", value]]), {
      completeness: "partial",
      managedBy: "operator",
    });
    assert.equal(materialized.runtimeValues.get("core")?.get("DEPLOY_APPS_SESSION_SECRET"), value);
    assert.equal(materialized.runtimeValues.get("portal")?.get("PORTAL_SESSION_SECRET"), value);
  }

  const porterOnly = makeConfig({
    services: ["core", "portal"],
    env: { core: { PORTER_DEPLOY_APPS_DOMAIN: "apps.porter.example.com" } },
  });
  assert.deepEqual(runtimeSecretNames("core", secretByName(porterOnly, "PORTAL_SESSION_SECRET")), []);

  const customAlias = makeConfig({ secretEnv: { core: { DEPLOY_APPS_SESSION_SECRET: "CUSTOM_SESSION" } } });
  assert.throws(
    () =>
      materializeSecretValues(customAlias, new Map([["CUSTOM_SESSION", "short"]]), {
        completeness: "partial",
        managedBy: "operator",
      }),
    /CUSTOM_SESSION for core\.DEPLOY_APPS_SESSION_SECRET/,
  );

  const collision = makeConfig({
    services: ["core", "portal"],
    env: { core: { DEPLOY_APPS_DOMAIN: "apps.portal.example.com" } },
    secretEnv: { core: { DEPLOY_APPS_SESSION_SECRET: "OTHER_SESSION" } },
  });
  assert.throws(
    () => computedSecrets(collision),
    /core would receive env DEPLOY_APPS_SESSION_SECRET from both OTHER_SESSION and PORTAL_SESSION_SECRET|from both PORTAL_SESSION_SECRET and OTHER_SESSION/,
  );
});

test("secret-backed presence selectors require their dependent secrets", () => {
  const cases = [
    ["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"],
    ["AWS_DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_GATE_SECRET"],
  ] as const;
  for (const [selector, dependent] of cases) {
    const config = makeConfig({ secretEnv: { core: { [selector]: `STORED_${selector}` } } });
    assert.ok(secretByName(config, dependent).required, selector);
  }
});

test("only virtual secret aliases fold into core presence conditions", () => {
  const cases = [
    ["GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET"],
    ["AWS_DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_GATE_SECRET"],
  ] as const;
  for (const service of ["slack", "web-ui", "admin"] as const) {
    for (const [selector, dependent] of cases) {
      const storeName = `${service.toUpperCase().replace("-", "_")}_${selector}`;
      const config = makeConfig({
        services: ["core", service],
        secretEnv: { [service]: { [selector]: storeName } },
      });
      assert.equal(
        computedSecrets(config).some((secret) => secret.name === dependent && secret.required),
        service === "slack",
        `${service}.${selector}`,
      );
    }
  }

  const codex = makeConfig({
    services: ["core", "slack"],
    env: { slack: { HARNESS: "codex" } },
    secretEnv: { slack: { CODEX_AUTH_CREDENTIAL: "SLACK_CODEX_AUTH" } },
  });
  assert.ok(!computedSecrets(codex).some((secret) => secret.name === "OPENAI_API_KEY"));
  assert.deepEqual(runtimeSecretNames("core", secretByName(codex, "SLACK_CODEX_AUTH")), ["CODEX_AUTH_CREDENTIAL"]);
});

test("real harnesses require and route the sandbox-reachable PUBLIC_API_URL to core", () => {
  for (const harness of ["pi", "opencode", "codex", "claude"]) {
    const real = makeConfig({ env: { core: { HARNESS: harness } } });
    const publicApi = secretByName(real, "PUBLIC_API_URL");
    assert.equal(publicApi.required, true);
    assert.deepEqual(runtimeSecretNames("core", publicApi), ["PUBLIC_API_URL"]);
    assert.ok(renderEnvExample(real).includes("PUBLIC_API_URL="));
  }
  assert.ok(
    !computedSecrets(makeConfig({ env: { core: { HARNESS: "mock" } } })).some((s) => s.name === "PUBLIC_API_URL"),
  );
  const real = makeConfig({ publicUrl: "https://api.example.com", env: { core: { HARNESS: "pi" } } });
  const materialized = materializeSecretValues(real, new Map([["PUBLIC_API_URL", "HTTPS://API.EXAMPLE.COM:443/"]]), {
    completeness: "partial",
    managedBy: "operator",
  });
  assert.equal(materialized.runtimeValues.get("core")?.get("PUBLIC_API_URL"), "https://api.example.com");
  const aliased = makeConfig({ secretEnv: { core: { PUBLIC_API_URL: "CUSTOM_PUBLIC_API_URL" } } });
  assert.throws(
    () =>
      materializeSecretValues(aliased, new Map([["CUSTOM_PUBLIC_API_URL", "https://@api.example.com"]]), {
        completeness: "partial",
        managedBy: "operator",
      }),
    /CUSTOM_PUBLIC_API_URL for core\.PUBLIC_API_URL/,
  );
});

test("FLY_TEMPLATE_ENV_DEFAULTS stays in sync with deploy/core/fly.toml", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const toml = readFileSync(join(root, "deploy", "core", "fly.toml"), "utf8");
  const packaged = readFileSync(join(root, "cli", "templates", "fly", "core.toml"), "utf8");
  for (const [name, value] of Object.entries(FLY_TEMPLATE_ENV_DEFAULTS.core ?? {})) {
    assert.match(
      toml,
      new RegExp(`^\\s*${name}\\s*=\\s*"${value}"`, "m"),
      `deploy/core/fly.toml sets ${name}="${value}"`,
    );
  }
  assert.doesNotMatch(toml, /^\s*DEPLOY_PROVIDER\s*=/m);
  assert.doesNotMatch(packaged, /^\s*DEPLOY_PROVIDER\s*=/m);
});

test("config secretEnv extras enter the computed set as required operator secrets, virtual services folding onto core", () => {
  const config = makeConfig({
    services: ["core", "slack"],
    secretEnv: {
      core: { CUSTOM_API_KEY: "CUSTOM_API_KEY" },
      slack: { SLACK_AUX_BOT_TOKEN: "SLACK_AUX_BOT_TOKEN" },
    },
  });
  const custom = secretByName(config, "CUSTOM_API_KEY");
  assert.equal(custom.required, true);
  assert.equal(custom.managedBy, "operator");
  assert.deepEqual(runtimeSecretNames("core", custom), ["CUSTOM_API_KEY"]);
  const auxiliary = secretByName(config, "SLACK_AUX_BOT_TOKEN");
  assert.deepEqual(
    [...secretDestinations(auxiliary).keys()],
    ["core"],
    "a virtual service's extra folds onto the core",
  );
  assert.match(renderEnvExample(config), /^CUSTOM_API_KEY=$/m);
});

test("a secretEnv alias delivers the stored secret under its declared env name only", () => {
  const config = makeConfig({
    services: ["core", "web-ui", "portal"],
    env: { core: { DEPLOY_APPS_DOMAIN: "apps.example.com" } },
    secretEnv: { core: { DEPLOY_APPS_SESSION_SECRET: "PORTAL_SESSION_SECRET" } },
  });
  const secret = secretByName(config, "PORTAL_SESSION_SECRET");
  assert.deepEqual(secret.services, ["portal"], "the alias adds no plain-name claim");
  assert.deepEqual(runtimeSecretNames("core", secret), ["DEPLOY_APPS_SESSION_SECRET"]);
  assert.deepEqual(runtimeSecretNames("portal", secret), ["PORTAL_SESSION_SECRET"]);
  assert.ok(secretsForService(config, "core").some((s) => s.name === "PORTAL_SESSION_SECRET"));
  assert.ok(
    !computedSecrets(config).some((s) => s.name === "DEPLOY_APPS_SESSION_SECRET"),
    "the alias env name is delivery, not a second stored secret",
  );
});

test("secret values materialize identically from canonical and aliased store names", () => {
  const unaliased = makeConfig({
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
  });
  const aliased = makeConfig({
    ...unaliased,
    secretEnv: {
      portal: {
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
        PORTAL_EXPECTED_TEAM_ID: "PORTAL_TEAM_STORE",
      },
    },
  });
  const direct = materializeSecretValues(
    unaliased,
    new Map([
      ["OIDC_CLIENT_ID", "client-id"],
      ["PORTAL_EXPECTED_TEAM_ID", "T123"],
    ]),
    { completeness: "partial", managedBy: "all" },
  );
  const remapped = materializeSecretValues(
    aliased,
    new Map([
      ["PORTAL_CLIENT_STORE", "client-id"],
      ["PORTAL_TEAM_STORE", "T123"],
    ]),
    { completeness: "partial", managedBy: "all" },
  );
  assert.deepEqual(direct.runtimeValues.get("portal"), remapped.runtimeValues.get("portal"));
});

test("partial secret materialization validates every available aliased trust value and reports missing ones", () => {
  const config = makeConfig({
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
    secretEnv: {
      portal: {
        OIDC_ALLOWED_EMAILS: "PORTAL_ALLOWLIST_STORE",
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
      },
    },
  });
  assert.throws(
    () =>
      materializeSecretValues(
        config,
        new Map([
          ["PORTAL_ALLOWLIST_STORE", "not-an-email"],
          ["PORTAL_CLIENT_STORE", "client-id"],
        ]),
        { completeness: "partial", managedBy: "all" },
      ),
    /OIDC_ALLOWED_EMAILS must contain valid, non-placeholder email addresses/,
  );
  const partial = materializeSecretValues(config, new Map([["PORTAL_CLIENT_STORE", "client-id"]]), {
    completeness: "partial",
    managedBy: "all",
  });
  assert.deepEqual(
    partial.missingRequiredDestinations.filter(({ storeName }) => storeName === "PORTAL_ALLOWLIST_STORE"),
    [{ storeName: "PORTAL_ALLOWLIST_STORE", workload: "portal", name: "OIDC_ALLOWED_EMAILS" }],
  );
});

test("complete secret validation rejects missing aliases and accepts a complete operator set", () => {
  const config = makeConfig({
    services: ["core", "portal"],
    env: { core: { HARNESS: "mock" } },
    secretEnv: {
      portal: {
        OIDC_CLIENT_ID: "PORTAL_CLIENT_STORE",
        PORTAL_EXPECTED_TEAM_ID: "PORTAL_TEAM_STORE",
      },
    },
  });
  const incomplete = completeOperatorValues(config);
  incomplete.delete("PORTAL_TEAM_STORE");
  assert.throws(() => validateCompleteSecretValues(config, incomplete), /PORTAL_TEAM_STORE/);
  assert.doesNotThrow(() =>
    validateCompleteSecretValues(
      config,
      completeOperatorValues(config, { PORTAL_CLIENT_STORE: "client-id", PORTAL_TEAM_STORE: "T123" }),
    ),
  );
});

test("complete operator validation excludes Terraform requirements while partial all-scope validates supplied values", () => {
  const config = makeConfig({ target: "aws", env: { core: { HARNESS: "mock" } } });
  assert.doesNotThrow(() => validateCompleteSecretValues(config, completeOperatorValues(config)));
  assert.throws(
    () =>
      materializeSecretValues(config, new Map([["DATABASE_URL", "replace-me"]]), {
        completeness: "partial",
        managedBy: "all",
      }),
    /DATABASE_URL/,
  );
});

test("secretEnv merges onto an existing computed secret instead of duplicating it", () => {
  const config = makeConfig({
    services: ["core", "web-ui", "portal"],
    secretEnv: { "web-ui": { PORTAL_IDENTITY_SECRET: "PORTAL_IDENTITY_SECRET" } },
  });
  const identity = secretByName(config, "PORTAL_IDENTITY_SECRET");
  assert.deepEqual(identity.services, ["core", "portal", "web-ui"]);
  assert.equal(computedSecrets(config).filter((s) => s.name === "PORTAL_IDENTITY_SECRET").length, 1);
});

test("secret aliases cannot shadow another store name on the same workload", () => {
  assert.throws(
    () => computedSecrets(makeConfig({ secretEnv: { core: { CORE_SIGNING_SECRET: "OTHER_SIGNING_SECRET" } } })),
    (error: unknown) =>
      error instanceof Error &&
      "clause" in error &&
      error.clause === "config.secretEnv" &&
      /core would receive env CORE_SIGNING_SECRET from both CORE_SIGNING_SECRET and OTHER_SIGNING_SECRET/.test(
        error.message,
      ),
  );
});

test("computed secret deliveries cannot collide with plaintext runtime destinations", () => {
  for (const config of [
    makeConfig({ env: { core: { CORE_SIGNING_SECRET: "plaintext" } } }),
    makeConfig({
      env: { core: { ALIAS_DESTINATION: "plaintext" } },
      secretEnv: { core: { ALIAS_DESTINATION: "STORE" } },
    }),
    makeConfig({ services: ["core", "slack"], env: { slack: { SLACK_APP_TOKEN: "plaintext" } } }),
    makeConfig({
      plugins: [
        {
          name: "linear",
          image: "ghcr.io/acme/linear:1",
          env: { PLUG_TOKEN: "plaintext" },
          secrets: [{ name: "PLUG_TOKEN" }],
        },
      ],
    }),
  ]) {
    assert.throws(() => computedSecrets(config), /would receive secret env .* while it is configured as plaintext/);
  }
});

test("virtual secret aliases cannot shadow another store name after folding onto core", () => {
  const config = makeConfig({
    services: ["core", "slack"],
    secretEnv: { core: { SHARED_NAME: "STORE_A" }, slack: { SHARED_NAME: "STORE_B" } },
  });
  assert.throws(() => computedSecrets(config), /core would receive env SHARED_NAME from both STORE_A and STORE_B/);
});

test("reusing one store name for the same delivery is benign", () => {
  const config = makeConfig({
    services: ["core", "slack"],
    secretEnv: { core: { SHARED_NAME: "SHARED_STORE" }, slack: { SHARED_NAME: "SHARED_STORE" } },
  });
  assert.deepEqual(runtimeSecretNames("core", secretByName(config, "SHARED_STORE")), ["SHARED_NAME"]);
});

test("configured plugin secrets collide only within their own workload", () => {
  const config = makeConfig({
    plugins: [{ name: "linear", image: "ghcr.io/acme/linear:1", secrets: [{ name: "SHARED_STORE" }] }],
    secretEnv: { core: { SHARED_NAME: "SHARED_STORE" } },
  });
  const secret = secretByName(config, "SHARED_STORE");
  assert.deepEqual(runtimeSecretNames("core", secret), ["SHARED_NAME"]);
  assert.deepEqual(runtimeSecretNames("linear", secret), ["SHARED_STORE"]);
});

test("secretEnv for a service the config does not enable is ignored", () => {
  const config = makeConfig({ secretEnv: { portal: { EXTRA_TOKEN: "EXTRA_TOKEN" } } });
  assert.ok(!computedSecrets(config).some((s) => s.name === "EXTRA_TOKEN"));
});

test("PORTAL_IDENTITY_SECRET reaches every service that signs or verifies a portal identity", () => {
  const config = makeConfig({ services: ["core", "web-ui", "admin", "portal"] });
  const secret = secretByName(config, "PORTAL_IDENTITY_SECRET");
  assert.deepEqual(
    [...secretDestinations(secret).keys()].sort(),
    ["admin", "core", "portal", "web-ui"],
    "core verifies with PORTAL_IDENTITY_SECRET, so a surface left without it signs with a different key and every request it makes is rejected",
  );
});

test("a fly deployment tells core which sandbox substrate to boot", () => {
  const config = makeConfig({
    target: "fly",
    sandbox: {
      backend: "sprites",
      namePrefix: "acme-sb",
    },
  });
  assert.equal(
    sandboxCoreEnv(config).env.SANDBOX_BACKEND,
    "sprites",
    "core refuses to boot in production unless SANDBOX_BACKEND is set explicitly",
  );
  assert.equal(sandboxCoreEnv(config).env.SPRITES_NAME_PREFIX, "acme-sb");
});

test("an explicit sandbox.backend wins, and Docker defaults to local", () => {
  const pinned = makeConfig({
    target: "fly",
    sandbox: {
      backend: "sprites",
      namePrefix: "acme-sb",
    },
  });
  assert.equal(sandboxCoreEnv(pinned).env.SANDBOX_BACKEND, "sprites");
  assert.equal(sandboxCoreEnv(makeConfig()).env.SANDBOX_BACKEND, "local");
});

test("the .env.example catalog names every secret exactly once", () => {
  for (const services of [["core"], ["core", "portal"], ["core", "portal", "auth"], SERVICE_NAMES] as const) {
    const rendered = renderEnvExample(makeConfig({ services: [...services] as QmConfig["services"] }));
    const declared = rendered
      .split("\n")
      .map((line) => /^#?\s*([A-Z0-9_]+)=/.exec(line)?.[1])
      .filter((name): name is string => Boolean(name));
    const duplicated = declared.filter((name, i) => declared.indexOf(name) !== i);
    assert.deepEqual(duplicated, [], `services=${services.join("+")} lists a secret twice`);
  }
});
