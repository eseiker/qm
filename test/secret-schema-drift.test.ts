import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FIRST_PARTY_SECRET_SPECS } from "../cli/src/secrets.ts";
import { MODEL_PROVIDERS, MODEL_PROVIDER_HARNESSES } from "../cli/src/config.ts";
import { CORE_SECRET_SPECS, validateCoreSecretEnv } from "../src/deployment/secret-schema.ts";
import { HARNESS_IDS, defaultModelForProvider } from "../src/model/pi-models.ts";

test("the standalone CLI and core agree on runtime-enforced core secret names", () => {
  const cli = new Set(
    FIRST_PARTY_SECRET_SPECS.filter((secret) => secret.service === "core" && secret.required !== false).map(
      (secret) => secret.envName ?? secret.name,
    ),
  );
  const runtime = new Set(CORE_SECRET_SPECS.map((secret) => secret.name));
  assert.deepEqual([...runtime].sort(), [...cli].sort());
});

test("real harnesses require a sandbox-reachable public API URL with runtime alias precedence", () => {
  const publicApiUrl = "https://core.example.test";
  for (const harness of ["pi", "opencode", "codex", "claude"]) {
    const base = { HARNESS: ` ${harness} `, OPENAI_API_KEY: "real-key" } as NodeJS.ProcessEnv;
    assert.deepEqual(validateCoreSecretEnv(base), ["PUBLIC_API_URL"], harness);
    assert.deepEqual(validateCoreSecretEnv({ ...base, PUBLIC_API_URL: publicApiUrl }), [], harness);
    assert.deepEqual(validateCoreSecretEnv({ ...base, AGENT_API_URL: publicApiUrl }), [], harness);
    assert.deepEqual(
      validateCoreSecretEnv({ ...base, PUBLIC_API_URL: " ", AGENT_API_URL: publicApiUrl }),
      ["PUBLIC_API_URL"],
      harness,
    );
    assert.deepEqual(
      validateCoreSecretEnv({ ...base, PUBLIC_API_URL: "placeholder", AGENT_API_URL: publicApiUrl }),
      ["PUBLIC_API_URL"],
      harness,
    );
  }
  assert.deepEqual(validateCoreSecretEnv({ HARNESS: "mock" } as NodeJS.ProcessEnv), []);
  assert.deepEqual(validateCoreSecretEnv({} as NodeJS.ProcessEnv), []);
});

test('deploy/core/Dockerfile pins NODE_ENV=production — the "production" secret gate is load-bearing on that line', () => {
  const dockerfile = readFileSync(new URL("../deploy/core/Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /^ENV NODE_ENV=production$/m);
});

test("gated app domains require strong gate and session secrets", () => {
  assert.deepEqual(validateCoreSecretEnv({ AWS_DEPLOY_APPS_DOMAIN: " " } as NodeJS.ProcessEnv), []);
  assert.deepEqual(validateCoreSecretEnv({ DEPLOY_APPS_DOMAIN: " " } as NodeJS.ProcessEnv), []);
  const missing = ["DEPLOY_APPS_SESSION_SECRET", "AWS_DEPLOY_GATE_SECRET"];
  for (const name of ["AWS_DEPLOY_APPS_DOMAIN", "DEPLOY_APPS_DOMAIN"]) {
    assert.deepEqual(validateCoreSecretEnv({ [name]: "apps.example.com" } as NodeJS.ProcessEnv), missing);
  }
  assert.deepEqual(
    validateCoreSecretEnv({
      AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
      AWS_DEPLOY_GATE_SECRET: "replace-me",
      DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
    } as NodeJS.ProcessEnv),
    ["AWS_DEPLOY_GATE_SECRET"],
  );
  assert.deepEqual(
    validateCoreSecretEnv({
      AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
      AWS_DEPLOY_GATE_SECRET: "short",
      DEPLOY_APPS_SESSION_SECRET: "s".repeat(32),
    } as NodeJS.ProcessEnv),
    ["AWS_DEPLOY_GATE_SECRET"],
    "a guessable gate secret would let anyone forge owner tokens, so strength is enforced",
  );
  for (const sessionSecret of ["replace-me", "x".repeat(31), `${"é".repeat(15)}x`]) {
    assert.deepEqual(
      validateCoreSecretEnv({
        AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
        AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
        DEPLOY_APPS_SESSION_SECRET: sessionSecret,
      } as NodeJS.ProcessEnv),
      ["DEPLOY_APPS_SESSION_SECRET"],
    );
  }
  assert.deepEqual(
    validateCoreSecretEnv({
      AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
      AWS_DEPLOY_GATE_SECRET: "0123456789abcdef0123456789abcdef",
      DEPLOY_APPS_SESSION_SECRET: "é".repeat(16),
    } as NodeJS.ProcessEnv),
    [],
  );
  assert.deepEqual(
    validateCoreSecretEnv({
      AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
      AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
      PORTAL_SESSION_SECRET: "p".repeat(32),
    } as NodeJS.ProcessEnv),
    [],
  );
  assert.deepEqual(
    validateCoreSecretEnv({
      AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
      AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
      DEPLOY_APPS_SESSION_SECRET: "d".repeat(32),
      PORTAL_SESSION_SECRET: "weak",
    } as NodeJS.ProcessEnv),
    [],
  );
  for (const explicit of [" ", "short"]) {
    assert.deepEqual(
      validateCoreSecretEnv({
        AWS_DEPLOY_APPS_DOMAIN: "apps.example.com",
        AWS_DEPLOY_GATE_SECRET: "g".repeat(32),
        DEPLOY_APPS_SESSION_SECRET: explicit,
        PORTAL_SESSION_SECRET: "p".repeat(32),
      } as NodeJS.ProcessEnv),
      ["DEPLOY_APPS_SESSION_SECRET"],
    );
  }
});

test("a declared base model provider is enforced at boot, not just at deploy time", () => {
  for (const [provider, key] of [
    ["anthropic", "ANTHROPIC_API_KEY"],
    ["openai", "OPENAI_API_KEY"],
    ["openrouter", "OPENROUTER_API_KEY"],
  ] as const) {
    assert.deepEqual(validateCoreSecretEnv({ MODEL_PROVIDER: provider } as NodeJS.ProcessEnv), [key]);
    assert.deepEqual(validateCoreSecretEnv({ MODEL_PROVIDER: provider, [key]: "real-key" } as NodeJS.ProcessEnv), []);
    assert.deepEqual(validateCoreSecretEnv({ MODEL_PROVIDER: provider, [key]: "replace-me" } as NodeJS.ProcessEnv), [
      key,
    ]);
  }
  assert.deepEqual(validateCoreSecretEnv({} as NodeJS.ProcessEnv), [], "no provider declared, nothing required");
});

test("an OpenAI base model on the Codex harness reports its one missing key once", () => {
  assert.deepEqual(
    validateCoreSecretEnv({
      MODEL_PROVIDER: "openai",
      HARNESS: "codex",
      PUBLIC_API_URL: "https://core.example.test",
    } as NodeJS.ProcessEnv),
    ["OPENAI_API_KEY"],
    "two rules wanting the same key must not name it twice",
  );
});

test("Codex OpenAI auth waivers distinguish local files from deployment credentials", () => {
  assert.deepEqual(
    validateCoreSecretEnv({
      HARNESS: "codex",
      MODEL_PROVIDER: "openai",
      CODEX_AUTH_FILE: "/tmp/auth.json",
      PUBLIC_API_URL: "https://core.example.test",
    }),
    [],
  );
  const production = {
    NODE_ENV: "production",
    HARNESS: "codex",
    MODEL_PROVIDER: "openai",
    PUBLIC_API_URL: "https://core.example.test",
    CAPABILITY_SECRET: "c".repeat(32),
    CONNECTOR_SECRET_KEY: "k".repeat(32),
    CORE_SIGNING_SECRET: "s".repeat(32),
    PORTAL_IDENTITY_SECRET: "p".repeat(32),
    SKILL_SIGNING_SECRET: "i".repeat(32),
  } as NodeJS.ProcessEnv;
  assert.deepEqual(validateCoreSecretEnv({ ...production, CODEX_AUTH_FILE: "/tmp/auth.json" }), ["OPENAI_API_KEY"]);
  assert.deepEqual(validateCoreSecretEnv({ ...production, CODEX_AUTH_CREDENTIAL: "keychain-credential" }), []);
});

test("each core secret is named by exactly one spec, so boot failures never repeat a name", () => {
  const names = CORE_SECRET_SPECS.map((spec) => spec.name);
  assert.deepEqual(
    names.filter((name, i) => names.indexOf(name) !== i),
    [],
    "give a secret answering to several rules one spec with a requiredWhen list",
  );
});

test("the CLI's provider/harness table matches what the core model registry can actually serve", () => {
  for (const provider of MODEL_PROVIDERS) {
    assert.deepEqual(
      HARNESS_IDS.filter((harness) => defaultModelForProvider(harness, provider) !== undefined).sort(),
      [...MODEL_PROVIDER_HARNESSES[provider]].sort(),
      `MODEL_PROVIDER_HARNESSES.${provider} has drifted from the registry`,
    );
  }
});

test("production rejects weak encryption key material for managed credentials", () => {
  const strong = "x".repeat(32);
  const env = {
    NODE_ENV: "production",
    CAPABILITY_SECRET: "c".repeat(32),
    CONNECTOR_SECRET_KEY: strong,
    CORE_SIGNING_SECRET: strong,
    PORTAL_IDENTITY_SECRET: "p".repeat(32),
    SKILL_SIGNING_SECRET: strong,
  } as NodeJS.ProcessEnv;
  assert.deepEqual(validateCoreSecretEnv(env), []);
  assert.deepEqual(validateCoreSecretEnv({ ...env, CONNECTOR_SECRET_KEY: "short" }), ["CONNECTOR_SECRET_KEY"]);
});

test("core capability and portal identity strength is measured in UTF-8 bytes", () => {
  const env = {
    NODE_ENV: "production",
    CAPABILITY_SECRET: "c".repeat(32),
    CONNECTOR_SECRET_KEY: "k".repeat(32),
    CORE_SIGNING_SECRET: "s".repeat(32),
    PORTAL_IDENTITY_SECRET: "p".repeat(32),
    SKILL_SIGNING_SECRET: "i".repeat(32),
  } as NodeJS.ProcessEnv;
  for (const name of ["CAPABILITY_SECRET", "PORTAL_IDENTITY_SECRET"] as const) {
    assert.deepEqual(validateCoreSecretEnv({ ...env, [name]: "x".repeat(31) }), [name]);
    assert.deepEqual(validateCoreSecretEnv({ ...env, [name]: "x".repeat(32) }), []);
    assert.deepEqual(validateCoreSecretEnv({ ...env, [name]: `${"é".repeat(15)}x` }), [name]);
    assert.deepEqual(validateCoreSecretEnv({ ...env, [name]: "é".repeat(16) }), []);
  }
});

test("both porter roles share PORTER_DEPLOY_API_TOKEN", () => {
  assert.deepEqual(validateCoreSecretEnv({ SANDBOX_BACKEND: "porter" } as NodeJS.ProcessEnv), [
    "PORTER_DEPLOY_API_TOKEN",
  ]);
  assert.deepEqual(validateCoreSecretEnv({ DEPLOY_PROVIDER: "porter" } as NodeJS.ProcessEnv), [
    "PORTER_DEPLOY_API_TOKEN",
  ]);
  assert.deepEqual(
    validateCoreSecretEnv({
      SANDBOX_BACKEND: "porter",
      DEPLOY_PROVIDER: "porter",
      PORTER_DEPLOY_API_TOKEN: "t-1",
    } as NodeJS.ProcessEnv),
    [],
  );
});

test("sandbox secret gates normalize both primary and secondary selectors", () => {
  for (const selector of ["SANDBOX_BACKEND", "SANDBOX_SECONDARY_BACKEND"] as const) {
    for (const [backend, token] of [
      ["sprites", "SPRITES_TOKEN"],
      ["smolmachines", "SMOLMACHINES_TOKEN"],
      ["porter", "PORTER_DEPLOY_API_TOKEN"],
    ] as const) {
      const selected = { [selector]: ` ${backend} ` } as NodeJS.ProcessEnv;
      assert.deepEqual(validateCoreSecretEnv(selected), [token]);
      assert.deepEqual(validateCoreSecretEnv({ ...selected, [token]: " " }), [token]);
      assert.deepEqual(validateCoreSecretEnv({ ...selected, [token]: "token" }), []);
    }
  }
});

test("the retired Fly sandbox backend does not require a runtime token", () => {
  assert.deepEqual(validateCoreSecretEnv({ SANDBOX_BACKEND: "fly" } as NodeJS.ProcessEnv), []);
});
