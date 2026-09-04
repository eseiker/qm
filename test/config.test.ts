import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { baseModelProviders, boolEnv, imageBuildSha, loadConfig, numEnv, CONFIG_DEFAULTS } from "../src/config.ts";

const productionEnv = {
  NODE_ENV: "production",
  PUBLIC_API_URL: "https://core.example.test",
  CORE_SIGNING_SECRET: "core-signing-secret-0123456789abcdef",
  SKILL_SIGNING_SECRET: "skill-signing-secret-0123456789abcdef",
  CAPABILITY_SECRET: "c".repeat(32),
  PORTAL_IDENTITY_SECRET: "p".repeat(32),
  CONNECTOR_SECRET_KEY: "connector-secret-0123456789abcdef",
  SANDBOX_BACKEND: "local",
} as const;

const publicApiEnv = { PUBLIC_API_URL: "https://core.example.test" } as const;
const gatedAppsEnv = {
  AWS_DEPLOY_GATE_SECRET: "0123456789abcdef0123456789abcdef",
  DEPLOY_APPS_SESSION_SECRET: "d".repeat(32),
  DEPLOY_APPS_LOGIN_URL: "https://qm.example.test",
} as const;

function oauthIdToken(accountId: string): string {
  const payload = Buffer.from(
    JSON.stringify({ "https://api.openai.com/auth": { chatgpt_account_id: accountId } }),
  ).toString("base64url");
  return `header.${payload}.signature`;
}

test("image build identity prefers GIT_SHA and otherwise accepts only a baked SHA-256", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-build-sha-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, ".build-sha");
  const baked = "a".repeat(64);
  writeFileSync(path, `${baked}\n`);
  assert.equal(imageBuildSha({ GIT_SHA: " source-commit " }, path), "source-commit");
  assert.equal(imageBuildSha({}, path), baked);
  for (const malformed of ["", "A".repeat(64), "b".repeat(63), `${"c".repeat(64)} extra`]) {
    writeFileSync(path, malformed);
    assert.equal(imageBuildSha({}, path), undefined);
  }
  unlinkSync(path);
  assert.equal(imageBuildSha({}, path), undefined);
});

test("ORG_BRAND_* parses into a validated branding default", () => {
  assert.equal(loadConfig({}).brandingDefault, undefined);
  assert.deepEqual(
    loadConfig({ ORG_BRAND_ACCENT: "#6366f1", ORG_BRAND_MARK: "Q", ORG_BRAND_SELF_LABEL: "qm" }).brandingDefault,
    { accent: "#6366f1", mark: "Q", selfLabel: "qm" },
  );
  assert.equal(loadConfig({ ORG_BRAND_ACCENT: "#abcde" }).brandingDefault, undefined);
  assert.deepEqual(loadConfig({ ORG_BRAND_MARK: 'a"bc' }).brandingDefault, { mark: "ab" });
  assert.equal(loadConfig({ ORG_BRAND_SELF_LABEL: "x".repeat(80) }).brandingDefault?.selfLabel?.length, 40);
  assert.deepEqual(loadConfig({ ORG_BRAND_ORG_NAME: "Acme Corp" }).brandingDefault, { orgName: "Acme Corp" });
  assert.equal(loadConfig({ ORG_BRAND_ORG_NAME: "x".repeat(80) }).brandingDefault?.orgName?.length, 40);
  assert.deepEqual(loadConfig({ ORG_BRAND_SELF_LABEL: "{{straylight}}" }).brandingDefault, { selfLabel: "straylight" });
});

test("AUTH_ALLOWED_EMAILS becomes a normalized email-auth principal set", () => {
  assert.equal(loadConfig({}).emailAuthPrincipals, undefined);
  assert.deepEqual(
    loadConfig({ AUTH_ALLOWED_EMAILS: " New@Example.com,other@example.com,new@example.com " }).emailAuthPrincipals,
    ["new@example.com", "other@example.com"],
  );
});

test("store kinds default to memory and accept postgres", () => {
  const def = loadConfig({});
  assert.equal(def.sessionStore, "memory");
  assert.equal(def.runStore, "memory");

  const pg = loadConfig({ SESSION_STORE: "postgres", DATABASE_URL: "postgres://test" });
  assert.equal(pg.sessionStore, "postgres");
  assert.equal(pg.runStore, "postgres", "runStore mirrors sessionStore when unset");

  assert.equal(
    loadConfig({ SESSION_STORE: "postgres", RUN_STORE: "memory", DATABASE_URL: "postgres://test" }).runStore,
    "memory",
  );
  assert.throws(
    () => loadConfig({ SESSION_STORE: "postgres" }),
    /missing or insecure required core secrets: DATABASE_URL/,
  );
});

test("deploy provider defaults to docker and rejects unknown values", () => {
  assert.equal(loadConfig({}).deployProvider, "docker");
  assert.equal(loadConfig({ DEPLOY_PROVIDER: "fly", FLY_DEPLOY_API_TOKEN: "test-token" }).deployProvider, "fly");
  assert.throws(() => loadConfig({ DEPLOY_PROVIDER: "flly" }), /DEPLOY_PROVIDER="flly" is not recognized/);
});

test("production and unauthenticated-core escape hatch are parsed once", () => {
  assert.throws(() => loadConfig({ NODE_ENV: "production" }), /missing or insecure required core secrets/);
  assert.equal(loadConfig(productionEnv).production, true);
  assert.equal(loadConfig({}).production, false);
  assert.equal(loadConfig({ ALLOW_UNAUTHENTICATED_CORE: "yes" }).allowUnauthenticatedCore, true);
  assert.throws(() => loadConfig({ ALLOW_UNAUTHENTICATED_CORE: "sometimes" }), /not a recognized boolean/);
});

test("harness security posture defaults to auto and validates named modes", () => {
  assert.equal(loadConfig({}).securityPosture, "auto");
  assert.equal(loadConfig({}).securityScreenBackend, "model");
  assert.equal(loadConfig({}).securityScreenProxy, undefined);
  assert.equal(loadConfig({}).securityScreenTimeoutMs, 15_000);
  assert.equal(loadConfig({ SECURITY_SCREEN_TIMEOUT_MS: "25" }).securityScreenTimeoutMs, 25);
  assert.equal(loadConfig({ HARNESS_SECURITY_POSTURE: "Dangerous" }).securityPosture, "dangerous");
  assert.equal(loadConfig({ HARNESS_SECURITY_POSTURE: "strict" }).securityPosture, "strict");
  assert.throws(
    () => loadConfig({ HARNESS_SECURITY_POSTURE: "permissive" }),
    /HARNESS_SECURITY_POSTURE="permissive" is not recognized/,
  );
  assert.throws(
    () => loadConfig({ SECURITY_SCREEN_BACKEND: "proxy" }),
    /requires SECURITY_SCREEN_PROXY_PROVIDER, SECURITY_SCREEN_PROXY_ENDPOINT, SECURITY_SCREEN_PROXY_TOKEN, and SECURITY_SCREEN_PROXY_ROLLOUT/,
  );
  assert.deepEqual(
    loadConfig({
      SECURITY_SCREEN_BACKEND: "proxy",
      SECURITY_SCREEN_PROXY_PROVIDER: "example-screen",
      SECURITY_SCREEN_PROXY_ENDPOINT: "https://screen.example.test/classify",
      SECURITY_SCREEN_PROXY_TOKEN: "test-token",
      SECURITY_SCREEN_PROXY_ROLLOUT: "enforce",
    }).securityScreenProxy,
    {
      provider: "example-screen",
      endpoint: "https://screen.example.test/classify",
      token: "test-token",
      shadow: false,
    },
  );
  for (const timeout of ["0", "-1", "1.5", "2147483648"]) {
    assert.throws(
      () => loadConfig({ SECURITY_SCREEN_TIMEOUT_MS: timeout }),
      /SECURITY_SCREEN_TIMEOUT_MS must be a positive integer/,
    );
  }
  assert.throws(
    () => loadConfig({ SECURITY_SCREEN_PROXY_PROVIDER: "example-screen" }),
    /requires SECURITY_SCREEN_BACKEND=proxy/,
  );
  for (const provider of ["Bad Provider", "surface", "origin", "-leading", `${"x".repeat(64)}`]) {
    assert.throws(
      () =>
        loadConfig({
          SECURITY_SCREEN_BACKEND: "proxy",
          SECURITY_SCREEN_PROXY_PROVIDER: provider,
          SECURITY_SCREEN_PROXY_ENDPOINT: "https://screen.example.test/classify",
          SECURITY_SCREEN_PROXY_TOKEN: "test-token",
          SECURITY_SCREEN_PROXY_ROLLOUT: "shadow",
        }),
      /SECURITY_SCREEN_PROXY_PROVIDER/,
    );
  }
  for (const endpoint of [
    "http://screen.example.test/classify",
    "https://user:pass@screen.example.test/classify",
    "https://screen.example.test/classify#fragment",
    "https://screen.example.test./classify",
  ]) {
    assert.throws(
      () =>
        loadConfig({
          SECURITY_SCREEN_BACKEND: "proxy",
          SECURITY_SCREEN_PROXY_PROVIDER: "example-screen",
          SECURITY_SCREEN_PROXY_ENDPOINT: endpoint,
          SECURITY_SCREEN_PROXY_TOKEN: "test-token",
          SECURITY_SCREEN_PROXY_ROLLOUT: "shadow",
        }),
      /SECURITY_SCREEN_PROXY_ENDPOINT/,
    );
  }
  assert.throws(
    () =>
      loadConfig({
        SECURITY_SCREEN_BACKEND: "proxy",
        SECURITY_SCREEN_PROXY_PROVIDER: "example-screen",
        SECURITY_SCREEN_PROXY_ENDPOINT: "https://screen.example.test/classify",
        SECURITY_SCREEN_PROXY_TOKEN: "test-token",
        SECURITY_SCREEN_PROXY_ROLLOUT: "gradual",
      }),
    /SECURITY_SCREEN_PROXY_ROLLOUT/,
  );
});

test("production names a mock harness rather than letting it pass as a real deployment", () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (msg: unknown) => void warnings.push(String(msg));
  try {
    loadConfig(productionEnv);
    loadConfig({ ...productionEnv, HARNESS: "mock" });
    loadConfig({ ...productionEnv, HARNESS: "pi" });
    loadConfig({});
  } finally {
    console.warn = original;
  }
  const mock = warnings.filter((w) => w.includes("calls no model provider"));
  assert.equal(mock.length, 2, "production + unset and production + mock each warn once");
  assert.match(mock[0]!, /unset, which means mock/);
  assert.match(mock[1]!, /HARNESS is "mock"/);
});

test("a leftover *=sqlite env throws (no silent downgrade to ephemeral memory)", () => {
  assert.throws(() => loadConfig({ SESSION_STORE: "sqlite" }), /SESSION_STORE=sqlite is no longer supported/);
  assert.throws(() => loadConfig({ RUN_STORE: "sqlite" }), /RUN_STORE=sqlite is no longer supported/);
  assert.throws(() => loadConfig({ ARTIFACT_STORE: "sqlite" }), /ARTIFACT_STORE=sqlite is no longer supported/);
});

test("a harmless ARTIFACT_STORE=memory (now a dead knob) is ignored, not fatal", () => {
  assert.doesNotThrow(() => loadConfig({ ARTIFACT_STORE: "memory" }));
});

test("boolEnv: one vocabulary for every boolean env knob", () => {
  for (const v of ["1", "true", "yes", "on", "TRUE", " On "]) assert.equal(boolEnv(v), true, v);
  for (const v of ["0", "false", "no", "off", "none", "OFF"]) assert.equal(boolEnv(v), false, v);
  for (const v of [undefined, "", "2", "enabled"]) assert.equal(boolEnv(v), undefined, String(v));
});

test("every boolean knob accepts the shared vocabulary (off means off)", () => {
  const off = loadConfig({ SEED_SKILLS: "off", EXECUTE_SCRATCH: "off", REACH_EXEC: "off", PI_CAPTURE_REQUESTS: "off" });
  assert.equal(off.seedSkills, false);
  assert.equal(off.scratchExecEnabled, false);
  assert.equal(off.reachExecEnabled, false);
  assert.equal(off.sharedOwnerAuthIsolation, false);
  assert.equal(off.piCaptureRequests, false);

  const on = loadConfig({
    SEED_SKILLS: "yes",
    EXECUTE_SCRATCH: "on",
    REACH_EXEC: "1",
    SHARED_OWNER_AUTH_ISOLATION: "yes",
    PI_SYSTEM_CACHE_SPLIT: "on",
  });
  assert.equal(on.seedSkills, true);
  assert.equal(on.scratchExecEnabled, true);
  assert.equal(on.reachExecEnabled, true);
  assert.equal(on.sharedOwnerAuthIsolation, true);
  assert.equal(on.piSystemCacheSplit, true);

  const unset = loadConfig({});
  assert.equal(unset.piCaptureRequests, true, "capture defaults on");
  assert.equal(unset.piSystemCacheSplit, false, "cache split defaults off");
});

test("numEnv: empty and non-numeric values fall back instead of poisoning config with NaN", () => {
  assert.equal(numEnv(""), undefined);
  assert.equal(numEnv("abc"), undefined);
  assert.equal(numEnv("42"), 42);
  assert.equal(loadConfig({ PORT: "" }).port, CONFIG_DEFAULTS.port);
});

test("a set-but-unparseable env value refuses to boot instead of silently taking the default", () => {
  assert.throws(() => loadConfig({ WORKERS: "not-a-number" }), /WORKERS="not-a-number" is not a number/);
  assert.throws(() => loadConfig({ BUDGET_USD_PER_WINDOW: "10$" }), /BUDGET_USD_PER_WINDOW="10\$" is not a number/);
  assert.throws(() => loadConfig({ EXECUTE_SCRATCH: "2" }), /EXECUTE_SCRATCH="2" is not a recognized boolean/);
  assert.throws(() => loadConfig({ SANDBOX_BACKEND: "docker" }), /SANDBOX_BACKEND="docker" is not recognized/);
  assert.equal(loadConfig({ WORKERS: "  " }).workers, CONFIG_DEFAULTS.workers);
  assert.equal(loadConfig({ EXECUTE_SCRATCH: "" }).scratchExecEnabled, false);
});

test("sandbox backend is parsed once before production backend guards", () => {
  assert.equal(loadConfig({ SANDBOX_BACKEND: " aws " }).sandboxBackend, "aws");
  assert.throws(
    () => loadConfig({ ...productionEnv, SANDBOX_BACKEND: "bogus" }),
    /SANDBOX_BACKEND="bogus" is not recognized/,
  );
});

test("sandbox container settings stay in their backend-specific config", () => {
  const unset = loadConfig({});
  assert.equal(unset.localSandbox.coreContainer, undefined);
  assert.equal("coreContainer" in unset.awsSandbox, false);

  const local = loadConfig({
    SANDBOX_BACKEND: "local",
    QM_CORE_CONTAINER: "qm-test-core",
    LOCAL_SANDBOX_IMAGE: "qm-test-local",
  });
  assert.equal(local.sandboxBackend, "local");
  assert.equal(local.localSandbox.coreContainer, "qm-test-core");
  assert.equal(local.localSandbox.image, "qm-test-local");
  assert.equal("coreContainer" in local.awsSandbox, false);

  const aws = loadConfig({
    SANDBOX_BACKEND: "aws",
    QM_CORE_CONTAINER: "qm-test-core",
    LOCAL_SANDBOX_IMAGE: "qm-test-local",
    AWS_SANDBOX_IMAGE: "qm-test-microvm",
    AWS_SANDBOX_IMAGE_VERSION: "7",
  });
  assert.equal(aws.sandboxBackend, "aws");
  assert.equal(aws.awsSandbox.imageIdentifier, "qm-test-microvm");
  assert.equal(aws.awsSandbox.imageVersion, "7");
  assert.equal("coreContainer" in aws.awsSandbox, false);

  const secondaryLocal = loadConfig({
    SANDBOX_BACKEND: "aws",
    SANDBOX_SECONDARY_BACKEND: "local",
    QM_CORE_CONTAINER: "qm-test-core",
  });
  assert.equal(secondaryLocal.sandboxSecondaryBackend, "local");
  assert.equal(secondaryLocal.localSandbox.coreContainer, "qm-test-core");
});

test("production refuses missing, placeholder, or weak signing keys", () => {
  assert.throws(
    () => loadConfig({ NODE_ENV: "production" }),
    /CAPABILITY_SECRET, CONNECTOR_SECRET_KEY, CORE_SIGNING_SECRET, PORTAL_IDENTITY_SECRET, SKILL_SIGNING_SECRET/,
  );
  assert.throws(
    () => loadConfig({ ...productionEnv, CORE_SIGNING_SECRET: "short" }),
    /core secrets: CORE_SIGNING_SECRET$/,
  );
  assert.throws(
    () => loadConfig({ ...productionEnv, CONNECTOR_SECRET_KEY: "short" }),
    /core secrets: CONNECTOR_SECRET_KEY$/,
  );
  assert.throws(
    () => loadConfig({ ...productionEnv, CAPABILITY_SECRET: "replace-me" }),
    /core secrets: CAPABILITY_SECRET$/,
  );
});

test("explicit split secrets are strong before every runtime entrypoint", () => {
  for (const name of ["CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET"] as const) {
    assert.throws(() => loadConfig({ [name]: "x".repeat(31) }), new RegExp(`core secrets: ${name}$`));
    assert.throws(() => loadConfig({ [name]: `${"é".repeat(15)}x` }), new RegExp(`core secrets: ${name}$`));
    assert.equal(
      loadConfig({ [name]: "x".repeat(32) })[
        name === "CAPABILITY_SECRET" ? "capabilitySecret" : "portalIdentitySecret"
      ],
      "x".repeat(32),
    );
    assert.equal(
      loadConfig({ [name]: "é".repeat(16) })[
        name === "CAPABILITY_SECRET" ? "capabilitySecret" : "portalIdentitySecret"
      ],
      "é".repeat(16),
    );
  }
  assert.doesNotThrow(() => loadConfig({}));
  const fallbackSecret = "s".repeat(32);
  const fallback = loadConfig({ CORE_SIGNING_SECRET: fallbackSecret });
  assert.equal(fallback.capabilitySecret, fallbackSecret);
  assert.equal(fallback.portalIdentitySecret, fallbackSecret);
});

test("defaults come from CONFIG_DEFAULTS, set exactly once", () => {
  const def = loadConfig({});
  assert.equal(def.workers, CONFIG_DEFAULTS.workers);
  assert.equal(def.rateLimitPerWindow, CONFIG_DEFAULTS.rateLimitPerWindow);
  assert.equal(def.rateLimitWindowMs, CONFIG_DEFAULTS.rateLimitWindowMs);
  assert.equal(def.monitorPollMs, CONFIG_DEFAULTS.monitorPollMs);
  assert.equal(def.approvalSummaryTimeoutMs, CONFIG_DEFAULTS.approvalSummaryTimeoutMs);
  assert.equal(def.deployDialTimeoutMs, CONFIG_DEFAULTS.deployDialTimeoutMs);
  assert.equal(def.execTimeoutDefaultMs, CONFIG_DEFAULTS.execTimeoutDefaultSec * 1000);
  assert.equal(def.execTimeoutMaxMs, CONFIG_DEFAULTS.execTimeoutMaxSec * 1000);
  assert.equal(def.backgroundJobTtlMs, CONFIG_DEFAULTS.backgroundJobTtlSec * 1000);
  assert.equal(def.backgroundJobTtlMaxMs, CONFIG_DEFAULTS.backgroundJobTtlMaxSec * 1000);
  assert.equal(def.turnWallClockMs, CONFIG_DEFAULTS.turnWallClockSec * 1000);
  assert.equal(def.turnWallClockMs, 0);
  assert.equal(def.runMaxAgeMs, 24 * 60 * 60_000);
  assert.equal(def.runWaitMs, def.runMaxAgeMs + 60_000);
});

test("turn wall clock config drives run bounds only when capped", () => {
  const capped = loadConfig({ TURN_WALL_CLOCK_SEC: "120" });
  assert.equal(capped.turnWallClockMs, 120_000);
  assert.equal(capped.runMaxAgeMs, 240_000);
  assert.equal(capped.runWaitMs, 180_000);
  const explicit = loadConfig({ TURN_WALL_CLOCK_SEC: "120", RUN_MAX_AGE_MS: "999999" });
  assert.equal(explicit.runMaxAgeMs, 999_999);
});

test("APPROVAL_SUMMARY_TIMEOUT_MS overrides the approval-summary deadline; unset uses the 6s default", () => {
  assert.equal(loadConfig({ APPROVAL_SUMMARY_TIMEOUT_MS: "9000" }).approvalSummaryTimeoutMs, 9000);
  assert.equal(loadConfig({}).approvalSummaryTimeoutMs, 6_000);
});

test("deploy proxy dial timeout is parsed once from config", () => {
  assert.equal(loadConfig({ DEPLOY_DIAL_TIMEOUT_MS: "1234" }).deployDialTimeoutMs, 1234);
  assert.throws(() => loadConfig({ DEPLOY_DIAL_TIMEOUT_MS: "soon" }), /DEPLOY_DIAL_TIMEOUT_MS="soon" is not a number/);
});

test("PUBLIC_API_URL is not treated as the human-facing web URL", () => {
  const apiOnly = loadConfig({ PUBLIC_API_URL: "HTTPS://AGENT-API.EXAMPLE:443/" });
  assert.equal(apiOnly.apiBaseUrl, "https://agent-api.example");
  assert.equal(apiOnly.publicUrl, "https://agent-api.example");
  assert.equal(apiOnly.publicWebUrl, undefined);

  const web = loadConfig({
    PUBLIC_API_URL: "https://agent-api.example",
    PUBLIC_WEB_URL: "HTTPS://PORTAL.EXAMPLE:443/",
  });
  assert.equal(web.apiBaseUrl, "https://agent-api.example");
  assert.equal(web.publicUrl, "https://portal.example");
  assert.equal(web.publicWebUrl, "https://portal.example");

  const alias = loadConfig({ HARNESS: "pi", AGENT_API_URL: "HTTP://LEGACY-AGENT-API.EXAMPLE:80/" });
  assert.equal(alias.apiBaseUrl, "http://legacy-agent-api.example");
  for (const publicApiUrl of [" ", "placeholder"]) {
    assert.throws(
      () =>
        loadConfig({
          HARNESS: "pi",
          PUBLIC_API_URL: publicApiUrl,
          AGENT_API_URL: "https://legacy-agent-api.example",
        }),
      /required core secrets: PUBLIC_API_URL/,
    );
  }
});

test("runtime origins reject ambiguous or non-origin URL forms", () => {
  const malformed = [
    "not-a-URL",
    "ftp://example.com",
    "/relative",
    "javascript:alert(1)",
    "https://user:pass@example.com",
    "https://@example.com",
    "https://:@example.com",
    "https://example.com/path",
    "https://example.com?query=1",
    "https://example.com#fragment",
    "https:example.com",
    "https:/example.com",
    "https:///example.com",
    "https:\\\\example.com",
    "https://example.com\\path",
    "https://example.com:",
    "https://%65xample.com",
    "https://exa\nmple.com",
    "https://exa\tmple.com",
    "https://exa\rmple.com",
    " https://example.com",
    "https://example.com ",
  ];
  for (const value of malformed) {
    assert.throws(() => loadConfig({ HARNESS: "pi", PUBLIC_API_URL: value }), /PUBLIC_API_URL must be an HTTP/);
    assert.throws(() => loadConfig({ HARNESS: "pi", AGENT_API_URL: value }), /AGENT_API_URL must be an HTTP/);
    assert.throws(() => loadConfig({ PUBLIC_WEB_URL: value }), /PUBLIC_WEB_URL must be an HTTP/);
    assert.throws(
      () => loadConfig({ DEPLOY_APPS_SESSION_SECRET: "s".repeat(32), DEPLOY_APPS_LOGIN_URL: value }),
      /DEPLOY_APPS_LOGIN_URL must be an HTTP/,
    );
  }
  assert.throws(
    () =>
      loadConfig({
        HARNESS: "pi",
        PUBLIC_API_URL: "not-a-URL",
        AGENT_API_URL: "https://legacy-agent-api.example",
      }),
    /PUBLIC_API_URL must be an HTTP/,
  );
});

test("plugin skill directories can be overridden or disabled", () => {
  assert.deepEqual(loadConfig({ PLUGIN_SKILLS_DIRS: "plugins/onboarding/skills, custom/skills" }).pluginSkillDirs, [
    resolve("plugins/onboarding/skills"),
    resolve("custom/skills"),
  ]);
  assert.deepEqual(loadConfig({ PLUGIN_SKILLS_DIRS: "0" }).pluginSkillDirs, []);
  assert.deepEqual(loadConfig({}).pluginSkillDirs, [resolve("plugins/onboarding/skills")]);
});

test("HARNESS=pi can boot before an admin configures a model provider", () => {
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: "pi" }));
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: "pi", ANTHROPIC_API_KEY: "sk-ant" }));
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: " pi " }));
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: " pi ", ANTHROPIC_API_KEY: "sk-ant" }));
  assert.doesNotThrow(() => loadConfig({ HARNESS: "mock" }));
  assert.doesNotThrow(() => loadConfig({ ...productionEnv, HARNESS: "pi" }));
  assert.doesNotThrow(() => loadConfig({ ...productionEnv, HARNESS: "pi", ANTHROPIC_API_KEY: "sk-ant" }));
});

test("Codex auth files are local-only while deployable credentials waive OPENAI_API_KEY in production", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "qm-config-codex-auth-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const authFile = join(dir, "auth.json");
  writeFileSync(
    authFile,
    JSON.stringify({
      auth_mode: "chatgpt",
      tokens: {
        access_token: "access",
        refresh_token: "refresh",
        id_token: oauthIdToken("account"),
      },
    }),
  );
  chmodSync(authFile, 0o600);
  assert.throws(
    () => loadConfig({ ...publicApiEnv, HARNESS: "codex" }),
    /missing or insecure required core secrets: OPENAI_API_KEY/,
  );
  assert.throws(
    () => loadConfig({ ...publicApiEnv, HARNESS: " codex " }),
    /missing or insecure required core secrets: OPENAI_API_KEY/,
  );
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: "codex", OPENAI_API_KEY: "sk-openai" }));
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: "codex", CODEX_AUTH_FILE: authFile }));
  assert.throws(
    () => loadConfig({ ...productionEnv, HARNESS: "codex", CODEX_AUTH_FILE: authFile }),
    /missing or insecure required core secrets: OPENAI_API_KEY/,
  );
  assert.doesNotThrow(() =>
    loadConfig({ ...productionEnv, HARNESS: "codex", CODEX_AUTH_CREDENTIAL: "keychain-credential" }),
  );
  assert.doesNotThrow(() => loadConfig({ ...productionEnv, HARNESS: "codex", OPENAI_API_KEY: "sk-openai" }));
  assert.equal(
    loadConfig({ ...publicApiEnv, HARNESS: "codex", OPENAI_API_KEY: "sk-openai", CODEX_MODEL: "gpt-5.4" }).codexModel,
    "gpt-5.4",
  );
});

test("HARNESS=claude uses native Claude authentication and does not require an Anthropic key", () => {
  assert.doesNotThrow(() => loadConfig({ ...publicApiEnv, HARNESS: "claude" }));
  assert.equal(
    loadConfig({ ...publicApiEnv, HARNESS: "claude", CLAUDE_MODEL: "claude-opus-4-8" }).claudeModel,
    "claude-opus-4-8",
  );
});

test("SANDBOX_BACKEND: unset defaults to local (dev only); the secondary must be recognized and differ", () => {
  assert.equal(loadConfig({}).sandboxBackend, "local");
  assert.throws(
    () => loadConfig({ ...productionEnv, SANDBOX_BACKEND: undefined }),
    /SANDBOX_BACKEND must be set explicitly in production/,
  );
  assert.equal(loadConfig({}).sandboxSecondaryBackend, undefined);
  assert.equal(
    loadConfig({ SANDBOX_SECONDARY_BACKEND: "sprites", SPRITES_TOKEN: "tok" }).sandboxSecondaryBackend,
    "sprites",
  );
  assert.throws(() => loadConfig({ SANDBOX_BACKEND: "sprites" }), /SPRITES_TOKEN/);
  assert.throws(
    () => loadConfig({ SANDBOX_SECONDARY_BACKEND: "fly" }),
    /SANDBOX_SECONDARY_BACKEND="fly" is not recognized/,
  );
  assert.throws(
    () => loadConfig({ SANDBOX_BACKEND: "sprites", SANDBOX_SECONDARY_BACKEND: "sprites", SPRITES_TOKEN: "tok" }),
    /must differ/,
  );
});

test("padded sandbox selectors still require their credentials and Porter locator", () => {
  for (const selector of ["SANDBOX_BACKEND", "SANDBOX_SECONDARY_BACKEND"] as const) {
    for (const [backend, token] of [
      ["sprites", "SPRITES_TOKEN"],
      ["smolmachines", "SMOLMACHINES_TOKEN"],
      ["porter", "PORTER_DEPLOY_API_TOKEN"],
    ] as const) {
      assert.throws(() => loadConfig({ [selector]: ` ${backend} ` }), new RegExp(token));
      assert.throws(() => loadConfig({ [selector]: ` ${backend} `, [token]: " " }), new RegExp(token));
    }
    assert.throws(
      () => loadConfig({ [selector]: " porter ", PORTER_DEPLOY_API_TOKEN: "tok" }),
      /PORTER_DEPLOY_PROJECT_ID/,
    );
    assert.throws(
      () =>
        loadConfig({
          [selector]: " porter ",
          PORTER_DEPLOY_API_TOKEN: "tok",
          PORTER_SANDBOX_BASE_URL: " ",
          PORTER_CLUSTER_ID: " ",
          KUBERNETES_SERVICE_HOST: " ",
        }),
      /PORTER_DEPLOY_PROJECT_ID/,
    );
  }
});

test("Sprites egress warnings cover normalized primary and secondary selectors once", () => {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (message: unknown) => void warnings.push(String(message));
  try {
    loadConfig({ SANDBOX_SECONDARY_BACKEND: " sprites ", SPRITES_TOKEN: "tok" });
    assert.equal(warnings.filter((warning) => warning.includes("SPRITES_EGRESS_PROXY_URL")).length, 1);
    warnings.length = 0;
    assert.throws(
      () =>
        loadConfig({
          SANDBOX_BACKEND: "sprites",
          SANDBOX_SECONDARY_BACKEND: " sprites ",
          SPRITES_TOKEN: "tok",
        }),
      /must differ/,
    );
    assert.equal(warnings.filter((warning) => warning.includes("SPRITES_EGRESS_PROXY_URL")).length, 1);
  } finally {
    console.warn = original;
  }
});

test("Fly identity and Slack runtime settings are parsed once into Config", () => {
  const config = loadConfig({
    FLY_APP_NAME: "qm-core",
    SLACK_BOT_TOKEN: "xoxb-test",
    SLACK_APP_TOKEN: "xapp-test",
    SLACK_API_URL: "https://slack.example/api",
  });
  assert.equal(config.flyAppName, "qm-core");
  assert.deepEqual(config.slack, {
    botToken: "xoxb-test",
    appToken: "xapp-test",
    apiUrl: "https://slack.example/api",
  });
});

test("maxClaims defaults from CONFIG_DEFAULTS and MAX_CLAIMS overrides", () => {
  assert.equal(loadConfig({}).maxClaims, CONFIG_DEFAULTS.maxClaims);
  assert.equal(loadConfig({ MAX_CLAIMS: "5" }).maxClaims, 5);
  assert.throws(() => loadConfig({ MAX_CLAIMS: "lots" }), /MAX_CLAIMS="lots" is not a number/);
});

test("MODEL_PROVIDER declares the vendor that bills the base model", () => {
  assert.equal(loadConfig({}).modelProvider, undefined);
  assert.equal(loadConfig({ MODEL_PROVIDER: " openrouter ", OPENROUTER_API_KEY: "k" }).modelProvider, "openrouter");
  assert.throws(() => loadConfig({ MODEL_PROVIDER: "bedrock" }), /MODEL_PROVIDER.*not recognized/);
});

test("MODEL_PROVIDER is refused when the harness can never run that vendor's models", () => {
  assert.throws(
    () =>
      loadConfig({
        ...publicApiEnv,
        MODEL_PROVIDER: "openrouter",
        HARNESS: "codex",
        OPENROUTER_API_KEY: "k",
        OPENAI_API_KEY: "k",
      }),
    /cannot serve a base model on HARNESS=codex/,
  );
  assert.throws(
    () =>
      loadConfig({
        ...publicApiEnv,
        MODEL_PROVIDER: "anthropic",
        HARNESS: "codex",
        ANTHROPIC_API_KEY: "k",
        OPENAI_API_KEY: "k",
      }),
    /cannot serve a base model on HARNESS=codex/,
  );
  assert.throws(
    () => loadConfig({ ...publicApiEnv, MODEL_PROVIDER: "openrouter", HARNESS: "opencode", OPENROUTER_API_KEY: "k" }),
    /cannot serve a base model on HARNESS=opencode/,
    "opencode has no OpenRouter route",
  );
  assert.equal(
    loadConfig({ ...publicApiEnv, MODEL_PROVIDER: "openai", HARNESS: "codex", OPENAI_API_KEY: "k" }).modelProvider,
    "openai",
    "the one combination Codex can bill is accepted",
  );
});

test("baseModelProviders constrains the base model only when a provider is declared", () => {
  assert.deepEqual(
    baseModelProviders(loadConfig({ MODEL_PROVIDER: "openrouter", OPENROUTER_API_KEY: "k", ANTHROPIC_API_KEY: "k" })),
    { anthropic: false, openai: false, openrouter: true },
    "the declaration outranks a stray key from another vendor",
  );
  assert.equal(
    baseModelProviders(loadConfig({ OPENROUTER_API_KEY: "k" })),
    undefined,
    "with no declaration the shipped default stands, so upgrading never moves a deployment's model or its billing",
  );
});

test("DEPLOY_PROVIDER=porter selects the Porter deploy provider and reads its env", () => {
  const config = loadConfig({
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_APPS_DOMAIN: "Apps.Example.COM.",
    PORTER_DEPLOY_RUNNER_IMAGE: "ghcr.io/x/runner:1",
    PORTER_DEPLOY_VISIBILITY: "private",
    PORTER_DEPLOY_TTL_SEC: "3600",
  });
  assert.equal(config.deployProvider, "porter");
  assert.deepEqual(config.porterDeploy, {
    token: "tok",
    baseUrl: "https://dashboard.porter.run/api/v2/alpha/projects/7/clusters/9",
    runnerImage: "ghcr.io/x/runner:1",
    appsDomain: "apps.example.com",
    visibility: "private",
    ttlSec: 3600,
  });
});

test("the deploy runner image falls back to the sandbox image", () => {
  const config = loadConfig({
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_APPS_DOMAIN: "apps.example.com",
    PORTER_SANDBOX_IMAGE: "localhost:5000/qm-sandbox:latest",
  });
  assert.equal(config.porterDeploy.runnerImage, "localhost:5000/qm-sandbox:latest");
});

test("DEPLOY_PROVIDER=porter refuses to boot without a cluster and tolerates a missing apps domain", () => {
  assert.throws(
    () =>
      loadConfig({
        DEPLOY_PROVIDER: "porter",
        PORTER_DEPLOY_API_TOKEN: "tok",
        PORTER_DEPLOY_APPS_DOMAIN: "apps.example.com",
      }),
    /PORTER_DEPLOY_PROJECT_ID/,
  );
  assert.equal(
    loadConfig({
      DEPLOY_PROVIDER: "porter",
      PORTER_DEPLOY_API_TOKEN: "tok",
      PORTER_DEPLOY_PROJECT_ID: "7",
      PORTER_DEPLOY_CLUSTER_ID: "9",
    }).porterDeploy.appsDomain,
    undefined,
  );
  assert.throws(
    () =>
      loadConfig({
        DEPLOY_PROVIDER: "porter",
        PORTER_DEPLOY_API_TOKEN: "tok",
        PORTER_DEPLOY_PROJECT_ID: "7",
        PORTER_DEPLOY_CLUSTER_ID: "9",
        PORTER_DEPLOY_APPS_DOMAIN: "a.b",
        PORTER_DEPLOY_VISIBILITY: "hidden",
      }),
    /PORTER_DEPLOY_VISIBILITY/,
  );
});

test("SANDBOX_BACKEND=porter locates the API and shares the deploy provider's token", () => {
  assert.throws(
    () => loadConfig({ SANDBOX_BACKEND: "porter", PORTER_DEPLOY_API_TOKEN: "tok" }),
    /PORTER_DEPLOY_PROJECT_ID/,
  );
  const inCluster = loadConfig({
    SANDBOX_BACKEND: "porter",
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_CLUSTER_ID: "3",
    PORTER_SANDBOX_TTL_SEC: "120",
  });
  assert.equal(inCluster.porterSandbox.token, "tok");
  assert.equal(inCluster.porterSandbox.ttlSec, 120);
  assert.equal(inCluster.porterDeploy.token, "tok");
});

test("DEPLOY_APPS_DOMAIN is the one-var apps setup: it feeds the gate and defaults every provider's domain", () => {
  const config = loadConfig({
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
    DEPLOY_APPS_DOMAIN: "apps.example.com",
    ...gatedAppsEnv,
  });
  assert.equal(config.deployAppsDomain, "apps.example.com");
  assert.equal(
    config.porterDeploy.appsDomain,
    undefined,
    "the gate domain must not be registered on Porter ingress — that would bypass the gate or loop the proxy",
  );
  assert.equal(config.awsDeploy.appsDomain, "apps.example.com");
  const overridden = loadConfig({
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
    DEPLOY_APPS_DOMAIN: "apps.example.com",
    AWS_DEPLOY_APPS_DOMAIN: "aws.example.com",
    PORTER_DEPLOY_APPS_DOMAIN: "apps.other.example.com",
    ...gatedAppsEnv,
  });
  assert.equal(overridden.porterDeploy.appsDomain, "apps.other.example.com");
  assert.equal(overridden.deployAppsDomain, "apps.example.com");
  assert.equal(overridden.awsDeploy.appsDomain, "apps.example.com");
});

test("the gated apps domain falls back to normalized AWS configuration and never Porter ingress", () => {
  const porter = loadConfig({
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
    PORTER_DEPLOY_APPS_DOMAIN: "apps.example.com",
  });
  assert.equal(porter.deployAppsDomain, undefined);
  assert.equal(porter.awsDeploy.appsDomain, undefined);
  assert.equal(porter.porterDeploy.appsDomain, "apps.example.com");
  const aws = loadConfig({
    AWS_DEPLOY_APPS_DOMAIN: " Apps.Example.COM. ",
    ...gatedAppsEnv,
  });
  assert.equal(aws.deployAppsDomain, "apps.example.com");
  const whitespaceCommon = loadConfig({
    DEPLOY_APPS_DOMAIN: " ",
    AWS_DEPLOY_APPS_DOMAIN: " Aws.Example.COM. ",
    ...gatedAppsEnv,
  });
  assert.equal(whitespaceCommon.deployAppsDomain, "aws.example.com");
  for (const blank of [" ", "\t"]) {
    const config = loadConfig({
      AWS_DEPLOY_APPS_DOMAIN: blank,
    });
    assert.equal(config.deployAppsDomain, undefined);
    assert.equal(config.awsDeploy.appsDomain, undefined);
  }
  assert.equal(loadConfig({}).deployAppsDomain, undefined);
});

test("Porter direct app domains are canonical bare DNS names with room for a full slug", () => {
  assert.equal(
    loadConfig({ PORTER_DEPLOY_APPS_DOMAIN: "MyApp.OnPorter.Run." }).porterDeploy.appsDomain,
    "myapp.onporter.run",
  );
  const maximum = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(61)}`;
  const oversized = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(62)}`;
  assert.equal(maximum.length, 189);
  assert.equal(oversized.length, 190);
  assert.equal(loadConfig({ PORTER_DEPLOY_APPS_DOMAIN: maximum }).porterDeploy.appsDomain, maximum);
  assert.throws(() => loadConfig({ PORTER_DEPLOY_APPS_DOMAIN: oversized }), /at most 189 ASCII characters/);
  for (const malformed of [
    "",
    " ",
    "\t",
    " apps.example.com",
    "apps.example.com ",
    "apps",
    "https://apps.example.com",
    "apps.example.com:443",
    "apps.example.com/path",
    "apps.example.com?query",
    "apps.example.com#fragment",
    "*.apps.example.com",
    "apps example.com",
    "apps.\nexample.com",
    "apps.example.com\0",
    "[::1]",
    "127.0.0.1",
    "apps.127.0.0.1",
    "äpp.example.com",
    "apps..example.com",
    "-apps.example.com",
    "apps-.example.com",
    `${"a".repeat(64)}.example.com`,
  ]) {
    assert.throws(() => loadConfig({ PORTER_DEPLOY_APPS_DOMAIN: malformed }), /PORTER_DEPLOY_APPS_DOMAIN/);
  }
});

test("Porter direct ingress cannot equal the canonical gated apps domain", () => {
  const porter = {
    DEPLOY_PROVIDER: "porter",
    PORTER_DEPLOY_API_TOKEN: "tok",
    PORTER_DEPLOY_PROJECT_ID: "7",
    PORTER_DEPLOY_CLUSTER_ID: "9",
  } as const;
  const equivalent = [
    ["apps.example.com", "apps.example.com"],
    ["Apps.Example.COM", "apps.example.com"],
    ["apps.example.com.", "apps.example.com"],
    [" apps.example.com ", "apps.example.com"],
    ["apps.example.com", "Apps.Example.COM"],
    ["apps.example.com", "apps.example.com."],
  ] as const;
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    for (const [gated, direct] of equivalent) {
      assert.throws(
        () =>
          loadConfig({
            ...porter,
            ...gatedAppsEnv,
            [name]: gated,
            PORTER_DEPLOY_APPS_DOMAIN: direct,
          }),
        /must differ from PORTER_DEPLOY_APPS_DOMAIN/,
      );
    }
  }
  const distinct = loadConfig({
    ...porter,
    ...gatedAppsEnv,
    DEPLOY_APPS_DOMAIN: "gated.example.com",
    PORTER_DEPLOY_APPS_DOMAIN: "direct.example.com",
  });
  assert.equal(distinct.deployAppsDomain, "gated.example.com");
  assert.equal(distinct.porterDeploy.appsDomain, "direct.example.com");
  const distinctAwsFallback = loadConfig({
    ...porter,
    ...gatedAppsEnv,
    AWS_DEPLOY_APPS_DOMAIN: "aws-gated.example.com",
    PORTER_DEPLOY_APPS_DOMAIN: "direct.example.com",
  });
  assert.equal(distinctAwsFallback.deployAppsDomain, "aws-gated.example.com");
  assert.equal(distinctAwsFallback.porterDeploy.appsDomain, "direct.example.com");
  assert.equal(
    loadConfig({
      DEPLOY_APPS_DOMAIN: "apps.example.com",
      PORTER_DEPLOY_APPS_DOMAIN: "apps.example.com",
      ...gatedAppsEnv,
    }).porterDeploy.appsDomain,
    "apps.example.com",
  );
});

test("gated apps domains require a resolved session and login origin", () => {
  const domain = {
    DEPLOY_APPS_DOMAIN: "apps.example.com",
    AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
  };
  for (const session of [{ DEPLOY_APPS_SESSION_SECRET: "s".repeat(32) }, { PORTAL_SESSION_SECRET: "s".repeat(32) }]) {
    for (const origin of [{}, { DEPLOY_APPS_LOGIN_URL: " " }, { PUBLIC_WEB_URL: " " }]) {
      assert.throws(
        () => loadConfig({ ...domain, ...session, ...origin }),
        /must be an HTTP\(S\) origin|sign-in address|complete deploy-app session and login origin/,
      );
    }
    for (const origin of [
      { DEPLOY_APPS_LOGIN_URL: "http://portal.example.test" },
      { PUBLIC_WEB_URL: "http://portal.example.test" },
    ]) {
      assert.throws(() => loadConfig({ ...domain, ...session, ...origin }), /requires an HTTPS login origin/);
    }
  }
  assert.equal(
    loadConfig({
      ...domain,
      PORTAL_SESSION_SECRET: "s".repeat(32),
      PUBLIC_WEB_URL: "https://portal.example.test",
    }).deployAppsLoginUrl,
    "https://portal.example.test",
  );
  assert.equal(
    loadConfig({
      DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
      DEPLOY_APPS_LOGIN_URL: "http://localhost:8080",
    }).deployAppsLoginUrl,
    "http://localhost:8080",
  );
});

test("gated apps login matches an explicit public web origin without coupling to the API origin", () => {
  const base = {
    DEPLOY_APPS_DOMAIN: "apps.example.com",
    AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
    DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
  } as const;
  assert.throws(
    () =>
      loadConfig({
        ...base,
        PUBLIC_WEB_URL: "https://portal.example.test",
        DEPLOY_APPS_LOGIN_URL: "https://evil.example.test",
      }),
    /must equal PUBLIC_WEB_URL/,
  );
  const equivalent = loadConfig({
    ...base,
    PUBLIC_WEB_URL: "HTTPS://PORTAL.EXAMPLE.TEST:443/",
    DEPLOY_APPS_LOGIN_URL: "https://portal.example.test",
  });
  assert.equal(equivalent.publicWebUrl, "https://portal.example.test");
  assert.equal(equivalent.deployAppsLoginUrl, "https://portal.example.test");
  const split = loadConfig({
    ...base,
    PUBLIC_API_URL: "https://core.example.test",
    DEPLOY_APPS_LOGIN_URL: "https://portal.example.test",
  });
  assert.equal(split.apiBaseUrl, "https://core.example.test");
  assert.equal(split.deployAppsLoginUrl, "https://portal.example.test");
});

test("DEPLOY_APPS_DOMAIN refuses shared platform domains that cannot carry per-app subdomains", () => {
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "myapp.onporter.run" }), /shared platform domain/);
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "myapp.fly.dev" }), /shared platform domain/);
  const gate = { AWS_DEPLOY_GATE_SECRET: "0123456789abcdef0123456789abcdef" };
  for (const malformed of [
    "https://apps.example.com",
    "apps.example.com:443",
    "apps.example.com/path",
    "*.apps.example.com",
  ]) {
    assert.throws(() => loadConfig({ AWS_DEPLOY_APPS_DOMAIN: malformed, ...gate }), /bare domain/);
  }
  assert.throws(() => loadConfig({ AWS_DEPLOY_APPS_DOMAIN: "myapp.fly.dev", ...gate }), /shared platform domain/);
  assert.equal(
    loadConfig({ DEPLOY_APPS_DOMAIN: "apps.example.com", ...gatedAppsEnv }).deployAppsDomain,
    "apps.example.com",
  );
});

test("DEPLOY_APPS_DOMAIN must be a bare DNS name, normalized to lowercase without a trailing dot", () => {
  const gate = gatedAppsEnv;
  assert.equal(loadConfig({ DEPLOY_APPS_DOMAIN: "Apps.Example.COM.", ...gate }).deployAppsDomain, "apps.example.com");
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "https://apps.example.com", ...gate }), /bare domain/);
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "apps.example.com:443@evil.example", ...gate }), /bare domain/);
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "*.apps.example.com", ...gate }), /bare domain/);
  assert.throws(() => loadConfig({ DEPLOY_APPS_DOMAIN: "myapp.fly.dev.", ...gate }), /shared platform domain/);
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    for (const numeric of ["127.0.0.1", "apps.127.0.0.1"]) {
      assert.throws(() => loadConfig({ [name]: numeric, ...gate }), /IP address/);
    }
    for (const controlled of ["apps.example.com\n", "\rapps.example.com", "apps.\texample.com"]) {
      assert.throws(() => loadConfig({ [name]: controlled, ...gate }), /bare DNS name/);
    }
  }
  const maximum = `${"a".repeat(63)}.${"b".repeat(62)}`;
  const oversized = `${"a".repeat(63)}.${"b".repeat(63)}`;
  assert.equal(maximum.length, 126);
  assert.equal(oversized.length, 127);
  for (const name of ["DEPLOY_APPS_DOMAIN", "AWS_DEPLOY_APPS_DOMAIN"] as const) {
    const config = loadConfig({ [name]: maximum, ...gate });
    assert.equal(config.deployAppsDomain, maximum);
    assert.equal(config.awsDeploy.appsDomain, maximum);
    assert.throws(() => loadConfig({ [name]: oversized, ...gate }), /at most 126 ASCII characters/);
  }
});

test("the portal session secret doubles as the deploy-apps viewer secret when a login URL exists", () => {
  const shared = "s".repeat(32);
  const derived = loadConfig({ PORTAL_SESSION_SECRET: shared, PUBLIC_WEB_URL: "https://qm.example.com" });
  assert.equal(derived.deployAppsSessionSecret, shared);
  assert.equal(derived.deployAppsLoginUrl, "https://qm.example.com");
  const noUrl = loadConfig({ PORTAL_SESSION_SECRET: shared });
  assert.equal(
    noUrl.deployAppsSessionSecret,
    undefined,
    "no sign-in address means the fallback stays off, not a throw",
  );
  const explicit = loadConfig({
    PORTAL_SESSION_SECRET: shared,
    DEPLOY_APPS_SESSION_SECRET: "d".repeat(32),
    PUBLIC_WEB_URL: "https://qm.example.com",
  });
  assert.equal(explicit.deployAppsSessionSecret, "d".repeat(32));
  assert.equal(
    loadConfig({
      PORTAL_SESSION_SECRET: "weak",
      DEPLOY_APPS_SESSION_SECRET: "d".repeat(32),
      PUBLIC_WEB_URL: "https://qm.example.com",
    }).deployAppsSessionSecret,
    "d".repeat(32),
  );
});

test("portal session secret inputs are measured in UTF-8 bytes", () => {
  for (const name of ["PORTAL_SESSION_SECRET", "DEPLOY_APPS_SESSION_SECRET"] as const) {
    const config = (value: string) => ({ [name]: value, PUBLIC_WEB_URL: "https://qm.example.com" });
    assert.throws(() => loadConfig(config("x".repeat(31))), /at least 32 UTF-8 bytes/);
    assert.equal(loadConfig(config("x".repeat(32))).deployAppsSessionSecret, "x".repeat(32));
    assert.throws(() => loadConfig(config(`${"é".repeat(15)}x`)), /at least 32 UTF-8 bytes/);
    assert.equal(loadConfig(config("é".repeat(16))).deployAppsSessionSecret, "é".repeat(16));
  }
});

test("the deploy-apps sign-in address defaults to the public web URL", () => {
  const derived = loadConfig({
    DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
    PUBLIC_WEB_URL: "HTTPS://QM.EXAMPLE.COM:443/",
  });
  assert.equal(derived.deployAppsLoginUrl, "https://qm.example.com");
  assert.equal(derived.deployAppsSessionSecret, "s".repeat(32));
  const explicit = loadConfig({
    DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
    DEPLOY_APPS_LOGIN_URL: "HTTPS://PORTAL.EXAMPLE.COM:443/",
    PUBLIC_WEB_URL: "https://qm.example.com",
  });
  assert.equal(explicit.deployAppsLoginUrl, "https://portal.example.com");
  assert.throws(
    () => loadConfig({ DEPLOY_APPS_SESSION_SECRET: "s".repeat(32) }),
    /DEPLOY_APPS_LOGIN_URL or PUBLIC_WEB_URL/,
  );
  assert.throws(
    () => loadConfig({ DEPLOY_APPS_LOGIN_URL: "https://portal.example.com" }),
    /requires DEPLOY_APPS_SESSION_SECRET/,
  );
});
