import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";

const CORE_SIGNING_SECRET = "c".repeat(32);
const PORTAL_IDENTITY_SECRET = "i".repeat(32);
const PORTAL_SESSION_SECRET = "s".repeat(32);

test("`node src/index.ts` (relative entry, like Docker) binds the port and serves /healthz", async () => {
  const PORT = "18097";
  const child = spawn(process.execPath, ["src/index.ts"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT, PORTAL_PUBLIC_URL: `http://localhost:${PORT}`, NODE_ENV: "test" },
    stdio: "ignore",
  });
  try {
    const deadline = Date.now() + 8000;
    let ok = false;
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`http://localhost:${PORT}/healthz`);
        if (r.status === 200) {
          ok = true;
          break;
        }
      } catch {
        await new Promise((r) => setTimeout(r, 150));
      }
    }
    assert.ok(ok, "portal entry should bind the port and answer /healthz");
  } finally {
    child.kill("SIGKILL");
  }
});

test("boot refuses an own-origin OIDC endpoint when no broker upstream is wired", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    OIDC_AUTH_ENDPOINT: "https://agent.example.com/idp/authorize",
  };
  delete env.NODE_ENV;
  delete env.AUTH_BROKER_UPSTREAM;
  const looping = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env,
    encoding: "utf8",
  });
  assert.notEqual(looping.status, 0);
  assert.match(looping.stderr, /AUTH_BROKER_UPSTREAM is unset/);
  const wired = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env: { ...env, AUTH_BROKER_UPSTREAM: "http://127.0.0.1:9099" },
    encoding: "utf8",
  });
  assert.equal(wired.status, 0, wired.stderr);
});

test("production measures portal session and identity secrets in UTF-8 bytes", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
  };
  const boot = (env: NodeJS.ProcessEnv) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env,
      encoding: "utf8",
    });
  for (const name of ["PORTAL_SESSION_SECRET", "PORTAL_IDENTITY_SECRET"] as const) {
    for (const value of ["x".repeat(31), `${"é".repeat(15)}x`]) {
      const rejected = boot({ ...baseEnv, [name]: value });
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, new RegExp(`${name} must be at least 32 UTF-8 bytes`));
    }
    for (const value of ["x".repeat(32), "é".repeat(16)]) {
      const accepted = boot({ ...baseEnv, [name]: value });
      assert.equal(accepted.status, 0, accepted.stderr);
    }
  }
});

test("production boot requires an explicit OIDC tenant trust boundary", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    SKILL_SIGNING_SECRET: "skill-signing-secret",
    SANDBOX_BACKEND: "local",
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
  };
  delete baseEnv.PORTAL_EXPECTED_TEAM_ID;
  delete baseEnv.OIDC_ALLOWED_EMAIL_DOMAIN;
  delete baseEnv.OIDC_ALLOWED_EMAILS;
  for (const value of [undefined, "", " ", "replace-me"]) {
    const env = { ...baseEnv };
    if (value !== undefined) env.PORTAL_EXPECTED_TEAM_ID = value;
    const missing = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env,
      encoding: "utf8",
    });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_EMAIL_DOMAIN, or PORTAL_EXPECTED_TEAM_ID/);
  }
  for (const gate of [
    { OIDC_ALLOWED_EMAILS: "admin@example.com" },
    { OIDC_ALLOWED_EMAIL_DOMAIN: "example.com" },
    { PORTAL_EXPECTED_TEAM_ID: "T123" },
    { OIDC_ALLOWED_EMAIL_DOMAIN: "example.com", PORTAL_EXPECTED_TEAM_ID: "T123" },
  ]) {
    const accepted = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, ...gate },
      encoding: "utf8",
    });
    assert.equal(accepted.status, 0, accepted.stderr);
  }
});

test("production boot validates OIDC_ALLOWED_EMAILS as bounded ASCII dot-atoms with DNS domains", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
  };
  const boot = (value: string) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, OIDC_ALLOWED_EMAILS: value },
      encoding: "utf8",
    });
  const validDomain = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(61)}`;
  for (const value of [
    " Admin+alerts@Example.com , operator.name@sub.example.com ",
    `${"a".repeat(64)}@${validDomain}`,
  ]) {
    const accepted = boot(value);
    assert.equal(accepted.status, 0, `${value}: ${accepted.stderr}`);
  }
  for (const value of [
    ".admin@example.com",
    "admin.@example.com",
    "ad..min@example.com",
    "admin@example.com.",
    "admin@.example.com",
    "admin@bad..example.com",
    "admin@-bad.example.com",
    "admin@bad-.example.com",
    "admin@sub_domain.example.com",
    "admin@example.com:443",
    "admin@example.com/path",
    "admin@example.com?next=1",
    "admin@example.com#fragment",
    "admin@[127.0.0.1]",
    "admin@[::1]",
    "admin@127.0.0.1",
    "admín@example.com",
    "admin@exámple.com",
    `${"a".repeat(65)}@example.com`,
    `admin@${"a".repeat(64)}.example.com`,
    `${"a".repeat(64)}@${validDomain}x`,
  ]) {
    const rejected = boot(value);
    assert.notEqual(rejected.status, 0, value);
    assert.match(rejected.stderr, /OIDC_ALLOWED_EMAILS must be a comma-separated list of valid/);
  }
});

test("production boot accepts a 252-byte DNS allowlist domain and rejects invalid domain boundaries", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
  };
  const boot = (value: string) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, OIDC_ALLOWED_EMAIL_DOMAIN: value },
      encoding: "utf8",
    });
  const boundary = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(60)}`;
  const oversized = `${boundary}x`;
  assert.equal(boundary.length, 252);
  assert.equal(oversized.length, 253);
  const accepted = boot(boundary);
  assert.equal(accepted.status, 0, accepted.stderr);
  for (const value of [
    "example.com:443",
    "example.com/path",
    "example.com?next=1",
    "example.com#fragment",
    "[127.0.0.1]",
    "127.0.0.1",
    "exámple.com",
    "bad..example.com",
    "-bad.example.com",
    "bad-.example.com",
    oversized,
  ]) {
    const rejected = boot(value);
    assert.notEqual(rejected.status, 0, value);
    assert.match(rejected.stderr, /OIDC_ALLOWED_EMAIL_DOMAIN must be a valid/);
  }
});

test("production boot requires an explicit JWKS URI for custom issuers", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ISSUER: "https://auth.example.com",
    OIDC_AUTH_ENDPOINT: "https://auth.example.com/authorize",
    OIDC_TOKEN_ENDPOINT: "https://auth.example.com/token",
    OIDC_USERINFO_ENDPOINT: "https://auth.example.com/userinfo",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
  };
  delete baseEnv.OIDC_JWKS_URI;
  const missing = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env: baseEnv,
    encoding: "utf8",
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /OIDC_JWKS_URI is required/);

  const accepted = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env: { ...baseEnv, OIDC_JWKS_URI: "https://auth.example.com/jwks.json" },
    encoding: "utf8",
  });
  assert.equal(accepted.status, 0, accepted.stderr);
});

test("a session TTL above the default max ceiling still boots, but a contradictory pair does not", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    SKILL_SIGNING_SECRET: "skill-signing-secret",
    SANDBOX_BACKEND: "local",
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
    PORTAL_SESSION_TTL_S: "604800",
  };
  delete baseEnv.PORTAL_SESSION_MAX_TTL_S;

  const derived = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env: baseEnv,
    encoding: "utf8",
  });
  assert.equal(derived.status, 0, derived.stderr);

  const contradictory = spawnSync(process.execPath, ["--input-type=module", "-e", command], {
    cwd: process.cwd(),
    env: { ...baseEnv, PORTAL_SESSION_MAX_TTL_S: "86400" },
    encoding: "utf8",
  });
  assert.notEqual(contradictory.status, 0);
  assert.match(contradictory.stderr, /PORTAL_SESSION_MAX_TTL_S must be a finite number/);
});

test("production boot rejects invalid impersonation TTLs before serving", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
    PORTAL_SESSION_TTL_S: "3600",
    PORTAL_SESSION_MAX_TTL_S: "7200",
  };
  const boot = (env: NodeJS.ProcessEnv) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, ...env },
      encoding: "utf8",
    });

  for (const [value, env] of [
    ["", {}],
    ["not-a-number", {}],
    ["Infinity", {}],
    ["-1", {}],
    ["0", {}],
    ["1.5", {}],
    ["1e3", {}],
    ["0x10", {}],
    [" 1 ", {}],
    ["01", {}],
    ["7201", {}],
    ["86401", { PORTAL_SESSION_MAX_TTL_S: "172800" }],
  ] as const) {
    const rejected = boot({ ...env, PORTAL_IMPERSONATE_TTL_S: value });
    assert.notEqual(rejected.status, 0, value);
    assert.match(rejected.stderr, /PORTAL_IMPERSONATE_TTL_S must be a finite positive integer/);
  }

  const invalidDefault = boot({ PORTAL_SESSION_TTL_S: "0.5", PORTAL_SESSION_MAX_TTL_S: "0.5" });
  assert.notEqual(invalidDefault.status, 0);
  assert.match(invalidDefault.stderr, /PORTAL_IMPERSONATE_TTL_S must be a finite positive integer/);
});

test("production boot accepts bounded impersonation TTLs and clamps the default to the session maximum", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
    PORTAL_SESSION_TTL_S: "3600",
    PORTAL_SESSION_MAX_TTL_S: "7200",
  };
  const boot = (env: NodeJS.ProcessEnv) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, ...env },
      encoding: "utf8",
    });

  for (const env of [
    { PORTAL_IMPERSONATE_TTL_S: "1" },
    { PORTAL_IMPERSONATE_TTL_S: "7200" },
    {
      PORTAL_SESSION_MAX_TTL_S: "172800",
      PORTAL_IMPERSONATE_TTL_S: "86400",
    },
    {
      PORTAL_SESSION_TTL_S: "900",
      PORTAL_SESSION_MAX_TTL_S: "1800",
    },
  ]) {
    const accepted = boot(env);
    assert.equal(accepted.status, 0, accepted.stderr);
  }
});

test("production boot requires a canonical direct apps domain", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://portal.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
  };
  const boot = (value: string) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, PORTAL_DIRECT_APPS_DOMAIN: value },
      encoding: "utf8",
    });

  for (const value of [
    "",
    "Apps.example.com",
    "apps.example.com.",
    " apps.example.com",
    "*.apps.example.com",
    "https://apps.example.com",
    "apps.example.com:443",
    "apps_example.com",
    "127.0.0.1",
    "apps.123",
    `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(62)}`,
  ]) {
    const rejected = boot(value);
    assert.notEqual(rejected.status, 0, value);
    assert.match(rejected.stderr, /PORTAL_DIRECT_APPS_DOMAIN must be a canonical bare DNS name/);
  }

  const boundary = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(61)}`;
  assert.equal(boundary.length, 189);
  const accepted = boot(boundary);
  assert.equal(accepted.status, 0, accepted.stderr);
});

test("production boot keeps direct app hosts outside the effective portal session cookie domain", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const baseEnv: NodeJS.ProcessEnv = {
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://portal.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "client-id",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
  };
  const boot = (env: NodeJS.ProcessEnv) =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], {
      cwd: process.cwd(),
      env: { ...baseEnv, ...env },
      encoding: "utf8",
    });

  for (const env of [
    {
      DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "direct.portal.example.com",
    },
    {
      DEPLOY_APPS_DOMAIN: "apps.example.com",
      PORTAL_COOKIE_DOMAIN: "example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "direct.example.com",
    },
    {
      DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "portal.example.com",
    },
    {
      PORTAL_PUBLIC_URL: "https://auth.example.com",
      DEPLOY_APPS_DOMAIN: "apps.auth.example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "example.com",
    },
  ]) {
    const rejected = boot(env);
    assert.notEqual(rejected.status, 0, JSON.stringify(env));
    assert.match(rejected.stderr, /must be outside the portal session cookie domain/);
  }

  const hostCollision = boot({ PORTAL_DIRECT_APPS_DOMAIN: "example.com" });
  assert.notEqual(hostCollision.status, 0);
  assert.match(hostCollision.stderr, /must not be the parent of the portal host/);

  for (const env of [
    {
      DEPLOY_APPS_DOMAIN: "apps.portal.example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "apps.direct.example.net",
    },
    {
      PORTAL_DIRECT_APPS_DOMAIN: "direct.portal.example.com",
    },
    {
      PORTAL_PUBLIC_URL: "https://portal.team.example.com",
      PORTAL_DIRECT_APPS_DOMAIN: "example.com",
    },
  ]) {
    const accepted = boot(env);
    assert.equal(accepted.status, 0, accepted.stderr);
  }
});

test("production accepts cleartext OIDC only on private-network hosts, and only for the server-to-server endpoints", () => {
  const command = "import('./src/index.ts').then(m => m.bootChecks())";
  const brokerEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "production",
    PORTAL_PUBLIC_URL: "https://agent.example.com",
    PORTAL_SESSION_SECRET,
    PORTAL_IDENTITY_SECRET,
    CORE_SIGNING_SECRET,
    OIDC_CLIENT_ID: "qm-portal",
    OIDC_CLIENT_SECRET: "client-secret",
    OIDC_ISSUER: "https://agent.example.com/idp",
    OIDC_AUTH_ENDPOINT: "https://agent.example.com/idp/authorize",
    OIDC_TOKEN_ENDPOINT: "http://acme-auth.internal:8080/token",
    OIDC_USERINFO_ENDPOINT: "http://acme-auth.internal:8080/userinfo",
    OIDC_JWKS_URI: "http://acme-auth.internal:8080/.well-known/jwks.json",
    OIDC_ALLOWED_EMAILS: "admin@example.com",
    AUTH_BROKER_UPSTREAM: "http://acme-auth.internal:8080",
  };
  const boot = (env: NodeJS.ProcessEnv): { status: number | null; stderr: string } =>
    spawnSync(process.execPath, ["--input-type=module", "-e", command], { cwd: process.cwd(), env, encoding: "utf8" });

  const wired = boot(brokerEnv);
  assert.equal(wired.status, 0, wired.stderr);

  for (const [override, pattern] of [
    [
      { OIDC_TOKEN_ENDPOINT: "http://tokens.example.com/token" },
      /OIDC endpoint must be https unless it is the built-in broker/,
    ],
    [{ OIDC_JWKS_URI: "http://10.0.0.5/keys" }, /OIDC endpoint must be https unless it is the built-in broker/],
    [{ OIDC_AUTH_ENDPOINT: "http://agent.example.com/idp/authorize" }, /OIDC_AUTH_ENDPOINT must be https/],
    [{ AUTH_BROKER_UPSTREAM: "https://auth.example.com" }, /AUTH_BROKER_UPSTREAM must address a private-network host/],
    [
      { OIDC_AUTH_ENDPOINT: "https://elsewhere.example.com/idp/authorize" },
      /OIDC_AUTH_ENDPOINT must be https:\/\/agent\.example\.com\/idp\/authorize/,
    ],
    [{ OIDC_ISSUER: "https://elsewhere.example.com/idp" }, /OIDC_ISSUER must be https:\/\/agent\.example\.com\/idp/],
  ] as Array<[NodeJS.ProcessEnv, RegExp]>) {
    const refused = boot({ ...brokerEnv, ...override });
    assert.notEqual(refused.status, 0, JSON.stringify(override));
    assert.match(refused.stderr, pattern);
  }

  const externalEnv: NodeJS.ProcessEnv = { ...brokerEnv };
  delete externalEnv.AUTH_BROKER_UPSTREAM;
  externalEnv.OIDC_ISSUER = "https://auth.example.com";
  externalEnv.OIDC_AUTH_ENDPOINT = "https://auth.example.com/authorize";
  const externalCleartext = boot({ ...externalEnv, OIDC_JWKS_URI: "http://10.0.0.5/keys" });
  assert.notEqual(externalCleartext.status, 0, "the relaxation is for the built-in broker only");
  assert.match(externalCleartext.stderr, /OIDC endpoint must be https unless it is the built-in broker/);
});
