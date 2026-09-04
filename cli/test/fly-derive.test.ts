import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { effectiveModelProvider, loadConfigAt, type AwsConfig, type QmConfig } from "../src/config.ts";
import { serviceEnvironment } from "../src/backends/aws.ts";
import { derivedTomlFor } from "../src/backends/fly.ts";
import { orgEnv, runnableServices } from "../src/services.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("acme fly config derives the checked-in deploy/<svc>/fly.toml byte-for-byte", () => {
  const { config } = loadConfigAt(join(repoRoot, "deploy", "stacks", "acme", "qm.config.jsonc"));
  for (const svc of runnableServices(config.services)) {
    const derived = derivedTomlFor(config, svc, repoRoot);
    const checkedIn = readFileSync(join(repoRoot, "deploy", svc, "fly.toml"), "utf8");
    assert.equal(derived, checkedIn, `derived ${svc} fly.toml diverged from deploy/${svc}/fly.toml`);
  }
});

test("web-ui serves at the root in both shapes — publicUrl IS the web-ui URL (no /web-ui suffix)", () => {
  const url = "https://acme-web-ui.fly.dev";
  assert.equal(orgEnv("core", "acme", url, false).WEB_UI_PUBLIC_URL, url);
  assert.equal(orgEnv("web-ui", "acme", url, false).WEB_UI_PUBLIC_URL, url);
  assert.equal(orgEnv("core", "acme", `${url}/`, true).WEB_UI_PUBLIC_URL, url);
  assert.equal(orgEnv("web-ui", "acme", url, true).WEB_UI_PUBLIC_URL, url);
  assert.equal(orgEnv("admin", "acme", url, true).ADMIN_BASE_PATH, "/admin");
  assert.equal(orgEnv("admin", "acme", url, false).ADMIN_BASE_PATH, undefined);
  assert.equal(orgEnv("admin", "acme", url, true).QM_VERSION, undefined);
});

test("brand env reaches core as ORG_BRAND_* and auth as AUTH_BRAND_NAME, and only when configured", () => {
  const url = "https://acme-web-ui.fly.dev";
  const brand = { botName: "straylight", orgName: "Acme Corp" };
  const core = orgEnv("core", "acme", url, false, brand);
  assert.equal(core.ORG_BRAND_SELF_LABEL, "straylight");
  assert.equal(core.ORG_BRAND_ORG_NAME, "Acme Corp");
  assert.equal(orgEnv("auth", "acme", url, false, brand).AUTH_BRAND_NAME, "straylight");
  const bare = orgEnv("core", "acme", url, false);
  assert.equal(bare.ORG_BRAND_SELF_LABEL, undefined);
  assert.equal(bare.ORG_BRAND_ORG_NAME, undefined);
  assert.equal(orgEnv("auth", "acme", url, false).AUTH_BRAND_NAME, undefined);
  assert.equal(orgEnv("web-ui", "acme", url, false, brand).ORG_BRAND_SELF_LABEL, undefined);
});

const imageFromStack = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "imagefrom-stack.json");

test("an imageFrom stack reuses the reference images and overrides only its own keys", () => {
  const { config } = loadConfigAt(imageFromStack);
  assert.equal(config.imageFrom, "qm");
  const coreToml = derivedTomlFor(config, "core", repoRoot);
  assert.match(coreToml, /app = "beta-core"/);
  assert.match(coreToml, /ORG_ID = "beta"/);
  assert.match(coreToml, /PUBLIC_WEB_URL = "https:\/\/beta\.example\.com"/);
  assert.match(coreToml, /SANDBOX_BACKEND = "sprites"/);
  assert.match(coreToml, /SPRITES_NAME_PREFIX = "beta"/);
});

const exampleFlyConfig = (): QmConfig => ({
  contract: 1,
  orgId: "example",
  publicUrl: "https://example.invalid",
  target: "fly",
  model: "example-model",
  appPrefix: "example-stack",
  region: "ord",
  flyOrg: "example-org",
  sandbox: {
    backend: "sprites",
    namePrefix: "example-sandboxes",
  },
  services: ["core", "admin", "web-ui", "portal"],
  plugins: [],
  skills: [],
  env: {},
  imageOverrides: {},
});

const exampleAwsConfig = (): AwsConfig => ({
  accountId: "123456789012",
  region: "us-east-1",
  cluster: "example",
  deployRoleArn: "arn:aws:iam::123456789012:role/example",
  secretsPrefix: "example/",
  imageLabel: "release",
  networking: { cloudMapNamespace: "example.internal" },
  services: {
    core: {
      ecrRepository: "qm-core",
      ecsService: "example-core",
      cpu: 2048,
      memory: 4096,
    },
  },
});

function flyEnvironmentValue(config: QmConfig, name: string): string | undefined {
  const match = new RegExp(`^\\s*${name} = (.+)$`, "m").exec(derivedTomlFor(config, "core", repoRoot));
  return match ? (JSON.parse(match[1]!) as string) : undefined;
}

test("Fly matches shared and AWS model-provider precedence including whitespace", () => {
  const cases = [
    {
      name: "disabled virtual service",
      services: ["core"] as QmConfig["services"],
      env: { slack: { MODEL_PROVIDER: "  openrouter  " } },
      expectedRaw: "openai",
    },
    {
      name: "enabled virtual service",
      services: ["core", "slack"] as QmConfig["services"],
      env: { slack: { MODEL_PROVIDER: "  openrouter  " } },
      expectedRaw: "  openrouter  ",
    },
    {
      name: "core override",
      services: ["core", "slack"] as QmConfig["services"],
      env: {
        slack: { MODEL_PROVIDER: "  openrouter  " },
        core: { MODEL_PROVIDER: "  anthropic  " },
      },
      expectedRaw: "  anthropic  ",
    },
  ];
  for (const example of cases) {
    const fly: QmConfig = {
      ...exampleFlyConfig(),
      modelProvider: "openai",
      services: example.services,
      env: example.env,
    };
    const aws: QmConfig = { ...fly, target: "aws", aws: exampleAwsConfig() };
    assert.equal(flyEnvironmentValue(fly, "MODEL_PROVIDER"), example.expectedRaw, example.name);
    assert.equal(serviceEnvironment(aws, "core").MODEL_PROVIDER, example.expectedRaw, example.name);
    assert.equal(effectiveModelProvider(fly), example.expectedRaw.trim(), example.name);
  }
});

test("a configured bot identity lands in the derived fly toml for core and auth only", () => {
  const config = { ...exampleFlyConfig(), botName: "straylight", orgName: "Straylight Industries" };
  config.services = ["core", "admin", "web-ui", "portal", "auth"];
  const core = derivedTomlFor(config, "core", repoRoot);
  assert.match(core, /^\s*ORG_BRAND_SELF_LABEL = "straylight"$/m);
  assert.match(core, /^\s*ORG_BRAND_ORG_NAME = "Straylight Industries"$/m);
  const auth = derivedTomlFor(config, "auth", repoRoot);
  assert.match(auth, /^\s*AUTH_BRAND_NAME = "straylight"$/m);
  const webUi = derivedTomlFor(config, "web-ui", repoRoot);
  assert.doesNotMatch(webUi, /ORG_BRAND_SELF_LABEL/);
  const bare = derivedTomlFor(exampleFlyConfig(), "core", repoRoot);
  assert.doesNotMatch(bare, /ORG_BRAND_SELF_LABEL/);
});

test("derived Fly configs contain only the deployment's region, org, sandbox, and portal policy", () => {
  const config = exampleFlyConfig();
  const core = derivedTomlFor(config, "core", repoRoot);
  const portal = derivedTomlFor(config, "portal", repoRoot);
  const admin = derivedTomlFor(config, "admin", repoRoot);

  assert.match(core, /^primary_region = "ord"$/m);
  assert.match(portal, /^primary_region = "ord"$/m);
  assert.match(admin, /^\s*ADMIN_BASE_PATH = "\/admin"$/m);
  assert.doesNotMatch(admin, /QM_VERSION/);
  assert.match(core, /^\s*FLY_ORG = "example-org"$/m);
  assert.match(core, /^\s*PI_MODEL = "example-model"$/m);
  assert.match(core, /^\s*SANDBOX_BACKEND = "sprites"$/m);
  assert.match(core, /^\s*SPRITES_NAME_PREFIX = "example-sandboxes"$/m);
  assert.doesNotMatch(core, /FLY_DEPLOY_BASE_IMAGE/);
  assert.match(core, /^\s*QM_DEPLOYMENT_ID = "qm-v2:example-org:example:example-stack"$/m);
  assert.doesNotMatch(core, /PI_DETECT_MODEL/);
  assert.doesNotMatch(portal, /OIDC_ALLOWED_EMAIL_DOMAIN/);
});

test("Fly preserves Porter and smolmachines runtime sandbox selections", () => {
  const { sandbox: _sandbox, ...base } = exampleFlyConfig();
  for (const backend of ["porter", "smolmachines"] as const) {
    const core = derivedTomlFor({ ...base, env: { core: { SANDBOX_BACKEND: backend } } }, "core", repoRoot);
    assert.match(core, new RegExp(`^\\s*SANDBOX_BACKEND = "${backend}"$`, "m"));
    assert.doesNotMatch(core, /SPRITES_NAME_PREFIX/);
  }
});

test("virtual-service env folds into the core [env] (core's own block wins)", () => {
  const { config } = loadConfigAt(imageFromStack);
  const coreToml = derivedTomlFor(config, "core", repoRoot);
  assert.match(
    coreToml,
    /WEB_UI_PUBLIC_URL = "https:\/\/beta\.example\.com"/,
    "env.slack reaches the in-process slack surface on core",
  );
  const coreWins = {
    ...config,
    env: { ...config.env, core: { ...config.env.core, WEB_UI_PUBLIC_URL: "https://core-wins.example.com" } },
  };
  assert.match(derivedTomlFor(coreWins, "core", repoRoot), /WEB_UI_PUBLIC_URL = "https:\/\/core-wins\.example\.com"/);
  assert.doesNotMatch(derivedTomlFor(config, "admin", repoRoot), /beta\.example\.com\/web-ui/);
});

test("Fly forces production and signed portal identity after configured environment merges", () => {
  const config = exampleFlyConfig();
  config.services = [...config.services, "auth", "slack"];
  const hostile = {
    ...config,
    env: Object.fromEntries(
      config.services.map((service) => [
        service,
        {
          NODE_ENV: "development",
          DATA_DIR: "/attacker",
          AWS_ENDPOINT_URL: "https://attacker.example/aws",
          AWS_ENDPOINT_URL_DYNAMODB: "https://attacker.example/dynamodb",
          AWS_ENDPOINT_URL_S3: "https://attacker.example/s3",
          AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
          AWS_CONTAINER_AUTHORIZATION_TOKEN: "attacker-token",
          AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: "/attacker/token",
          AWS_CONTAINER_CREDENTIALS_FULL_URI: "https://attacker.example/credentials",
          AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/attacker/credentials",
          FLY_APP_NAME: "attacker-app",
          FLY_MACHINE_ID: "attacker-machine",
          ...(service === "core"
            ? {
                AGENT_API_URL: "https://attacker.example/agent",
                REQUIRE_SIGNED_PORTAL_IDENTITY: "0",
                SESSION_STORE: "memory",
                RUN_STORE: "memory",
                FLY_DEPLOY_APP_PREFIX: "attacker",
                FLY_REGION: "attacker",
              }
            : {}),
          ...(service === "slack" ? { SLACK_API_URL: "https://attacker.example/slack" } : {}),
          ...(service === "web-ui" || service === "admin" ? { ALLOW_UNSIGNED_TEST_IDENTITY: "1" } : {}),
          ...(service === "portal"
            ? {
                WEB_UI_UPSTREAM: "https://attacker.example/web-ui",
                ADMIN_UPSTREAM: "https://attacker.example/admin",
              }
            : {}),
        },
      ]),
    ),
  };
  for (const service of runnableServices(config.services)) {
    const toml = derivedTomlFor(hostile, service, repoRoot);
    assert.match(toml, /^\s*NODE_ENV = "production"$/m);
    assert.match(toml, /^\s*DATA_DIR = "\/data"$/m);
    assert.doesNotMatch(toml, /^\s*NODE_ENV = "development"$/m);
    assert.doesNotMatch(
      toml,
      /AGENT_API_URL|AWS_CONTAINER_|AWS_ENDPOINT_URL|AWS_IGNORE_CONFIGURED_ENDPOINT_URLS|FLY_APP_NAME|FLY_MACHINE_ID|SLACK_API_URL/,
    );
    if (service === "web-ui" || service === "admin") {
      assert.doesNotMatch(toml, /ALLOW_UNSIGNED_TEST_IDENTITY/);
    }
  }
  const core = derivedTomlFor(hostile, "core", repoRoot);
  assert.match(core, /^\s*REQUIRE_SIGNED_PORTAL_IDENTITY = "1"$/m);
  assert.doesNotMatch(core, /^\s*REQUIRE_SIGNED_PORTAL_IDENTITY = "0"$/m);
  assert.match(core, /^\s*SESSION_STORE = "postgres"$/m);
  assert.match(core, /^\s*RUN_STORE = "postgres"$/m);
  assert.match(core, /^\s*FLY_DEPLOY_APP_PREFIX = "example-stack-d"$/m);
  assert.match(core, /^\s*FLY_REGION = "ord"$/m);
  assert.doesNotMatch(core, /attacker/);
  const portal = derivedTomlFor(hostile, "portal", repoRoot);
  assert.match(portal, /^\s*WEB_UI_UPSTREAM = "http:\/\/example-stack-web-ui\.flycast"$/m);
  assert.match(portal, /^\s*ADMIN_UPSTREAM = "http:\/\/example-stack-admin\.internal:8080"$/m);
  assert.match(portal, /^\s*AUTH_BROKER_UPSTREAM = "http:\/\/example-stack-auth\.flycast"$/m);
  assert.match(portal, /^\s*AUTH_BROKER_PREFIX = "\/idp"$/m);
  assert.doesNotMatch(portal, /attacker\.example/);

  const withoutAuth: QmConfig = {
    ...hostile,
    services: hostile.services.filter((service) => service !== "auth"),
    env: {
      ...hostile.env,
      portal: {
        ...hostile.env.portal,
        AUTH_BROKER_UPSTREAM: "https://stale.example/broker",
        AUTH_BROKER_PREFIX: "/stale",
      },
    },
  };
  const externalOidcPortal = derivedTomlFor(withoutAuth, "portal", repoRoot);
  assert.doesNotMatch(externalOidcPortal, /AUTH_BROKER_UPSTREAM|AUTH_BROKER_PREFIX|stale\.example/);
});

test("a vms override rewrites the core [[vm]] size/memory without touching other services", () => {
  const { config } = loadConfigAt(imageFromStack);
  const coreToml = derivedTomlFor(config, "core", repoRoot);
  assert.match(coreToml, /\[\[vm\]\]\n\s*size = "shared-cpu-2x"\n\s*memory = "4gb"/);
  assert.doesNotMatch(coreToml, /size = "shared-cpu-1x"/);
  assert.doesNotMatch(coreToml, /memory = "2gb"/);
  const adminToml = derivedTomlFor(config, "admin", repoRoot);
  const adminVm = readFileSync(join(repoRoot, "deploy", "admin", "fly.toml"), "utf8").match(
    /\[\[vm\]\][\s\S]*?(?=\n\[|\n\n|$)/,
  );
  if (adminVm) assert.ok(adminToml.includes(adminVm[0]), "admin [[vm]] block changed despite no vms override");
  assert.doesNotMatch(adminToml, /shared-cpu-2x|memory = "4gb"/);
});
